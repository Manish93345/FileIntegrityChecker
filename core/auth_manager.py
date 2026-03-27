#!/usr/bin/env python3
"""
auth_manager.py — FMSecure v2.0
Key fix: get_user_tier() now calls license_verifier WITHOUT email (device-based).
activate_license() also changed to not require email match.
"""
import os, hashlib, uuid
from core.utils import get_app_data_dir
from core.encryption_manager import crypto_manager

USERS_DB_FILE = os.path.join(get_app_data_dir(), "logs", "users.dat")

class AuthManager:
    def __init__(self):
        self.users = {}
        self._load_users()

    def _hash_password(self, password, salt=None):
        if not salt: salt = uuid.uuid4().hex
        return hashlib.sha256((password + salt).encode('utf-8')).hexdigest(), salt

    def _load_users(self):
        if not os.path.exists(USERS_DB_FILE):
            self._save_db()
            return
        data = crypto_manager.decrypt_json(USERS_DB_FILE)
        if data is None:
            # Decryption failed — key mismatch.
            # DO NOT silently start fresh here.
            # The startup patch above will handle this case properly
            # by showing a warning and clearing data only when a new
            # key was genuinely generated (not just temporarily missing).
            print("[AUTH] SECURITY: users.dat could not be decrypted.")
            print("[AUTH] If this is unexpected, check key recovery status.")
            self.users = {}
            # Do NOT call _save_db() here — that would overwrite with empty!
        else:
            self.users = data

    def _save_db(self):
        try:
            os.makedirs(os.path.dirname(USERS_DB_FILE), exist_ok=True)
            crypto_manager.encrypt_json(self.users, USERS_DB_FILE)
        except Exception as e:
            print(f"Error saving auth db: {e}")

    def has_users(self): return len(self.users) > 0

    def register_user(self, username, email, password, role="admin", auth_method="manual"):
        if username in self.users: return False, "Username already exists."
        h, s = self._hash_password(password)
        self.users[username] = {
            "hash": h, "salt": s, "role": role,
            "registered_email": email.strip().lower(),
            "license_key": "", "auth_method": auth_method,
            "sso_pin_hash": "", "sso_pin_salt": "",
        }
        self._save_db()
        return True, "Registration successful."

    def login(self, username, password):
        if username not in self.users: return False, None, "User not found"
        user = self.users[username]
        check, _ = self._hash_password(password, user.get("salt"))
        if check == user.get("hash"):
            return True, user.get("role", "user"), "Login Successful"
        return False, None, "Invalid Password"

    def get_auth_method(self, username):
        return self.users.get(username, {}).get("auth_method", "manual")

    def is_google_email_registered(self, email):
        el = email.strip().lower()
        for username, data in self.users.items():
            if data.get("registered_email", "").lower() == el:
                return True, username
        return False, None

    def has_sso_pin(self, username):
        return bool(self.users.get(username, {}).get("sso_pin_hash"))

    def set_sso_pin(self, username, pin):
        if username not in self.users: return False, "User not found."
        if not pin or len(pin) < 4: return False, "PIN must be at least 4 digits."
        if not pin.isdigit(): return False, "PIN must be digits only."
        h, s = self._hash_password(pin)
        self.users[username]["sso_pin_hash"] = h
        self.users[username]["sso_pin_salt"] = s
        self._save_db()
        return True, "PIN set successfully."

    def verify_sso_pin(self, username, pin):
        user = self.users.get(username, {})
        sh = user.get("sso_pin_hash", ""); ss = user.get("sso_pin_salt", "")
        if not sh or not ss: return False
        check, _ = self._hash_password(pin, ss)
        return check == sh

    def get_user_tier(self, username: str) -> str:
        """
        Returns the user's tier.
        Possible values: "free", "pro_monthly", "pro_annual"
        Legacy "PRO" is also handled for backward compatibility.
        """
        user = self.users.get(username, {})

        # Legacy override: old activations stored tier="PRO" directly
        if user.get("tier") in ("PRO", "pro_monthly", "pro_annual", "premium", "pro"):
            stored = user.get("tier", "free")
            # Map legacy "PRO" and "premium" to pro_monthly for consistency
            if stored in ("PRO", "premium", "pro"): return "pro_monthly"
            return stored

        key = user.get("license_key", "")
        if not key: return "free"

        # Call verifier — email is not needed anymore (device-based)
        try:
            from core.license_verifier import license_verifier
            is_valid, tier = license_verifier.verify_license(key)
            return tier if is_valid else "free"
        except Exception as e:
            print(f"[AUTH] License check error for {username}: {e}")
            return "free"

    def activate_license(self, username, key):
        """
        Activate a license key.
        No email check — device-based validation only.
        """
        if username not in self.users:
            return False, "User not found"

        clean_key = key.strip()
        if not clean_key:
            return False, "Please enter a license key."

        try:
            from core.license_verifier import license_verifier
            is_valid, tier = license_verifier.verify_license(clean_key)
        except Exception as e:
            return False, f"Could not reach license server: {e}"

        if is_valid:
            self.users[username]["license_key"] = clean_key
            self.users[username]["tier"] = tier
            self._save_db()
            # --- 🚨 STEP 4: THE INSTANT UPLOAD TRIGGER ---
            try:
                from core.integrity_core import CONFIG, save_config
                from core.encryption_manager import crypto_manager
                
                # 1. Permanently save PRO status to disk so it survives restarts
                CONFIG["is_pro_user"] = True
                save_config()
                
                # 2. Blast the key to the Master Keyring on Google Drive instantly!
                crypto_manager.force_key_backup()
            except Exception as e:
                print(f"[AUTH] Non-critical warning: Instant key backup failed: {e}")
            # -------------------------------------------------------------

            tier_label = "PRO Monthly" if "monthly" in tier else "PRO Annual" if "annual" in tier else tier.upper()
            return True, f"Success! Upgraded to {tier_label}."
        else:
            try:
                from core.license_verifier import license_verifier, REASON_MESSAGES
                resp_reason = license_verifier.get_activation_error(clean_key)
                return False, resp_reason
            except Exception:
                return False, "Invalid license key. Please check and try again."

    def update_password(self, username, new_password):
        if username not in self.users: return False, "User not found"
        h, s = self._hash_password(new_password)
        self.users[username]["hash"] = h; self.users[username]["salt"] = s
        try:
            self._save_db(); return True, "Password updated successfully"
        except Exception as e:
            return False, f"Failed to save: {e}"

auth = AuthManager()