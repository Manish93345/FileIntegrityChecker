#!/usr/bin/env python3
"""
auth_manager.py
Backend logic for Authentication System.
Handles user storage, password hashing (SHA-256 + Salt), role, and LICENSE VERIFICATION.
Now secured with AES-128 Encryption at rest.

Phase A Part 4 additions:
- auth_method field ("manual" | "google") stored per user
- SSO PIN: a 4-digit local device code set during first Google login
- verify_sso_pin() / set_sso_pin() for PIN management
- Google email allowlist: only registered emails can log in via Google
"""

import os
import hashlib
import uuid
from core.utils import get_app_data_dir
from core.license_verifier import license_verifier
from core.encryption_manager import crypto_manager

USERS_DB_FILE = os.path.join(get_app_data_dir(), "logs", "users.dat")


class AuthManager:
    def __init__(self):
        self.users = {}
        self._load_users()

    # ── Hashing ──────────────────────────────────────────────────────────

    def _hash_password(self, password, salt=None):
        """Hash password using SHA-256 and a salt."""
        if not salt:
            salt = uuid.uuid4().hex
        hashed = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
        return hashed, salt

    # ── Persistence ──────────────────────────────────────────────────────

    def _load_users(self):
        """Load users from the encrypted vault."""
        if not os.path.exists(USERS_DB_FILE):
            self._save_db()
            return

        decrypted_data = crypto_manager.decrypt_json(USERS_DB_FILE)

        if decrypted_data is None:
            print("SECURITY ALERT: users.dat is corrupted or tampered with. Starting fresh.")
            self.users = {}
            self._save_db()
        else:
            self.users = decrypted_data

    def _save_db(self):
        """Save users to the encrypted vault."""
        try:
            os.makedirs(os.path.dirname(USERS_DB_FILE), exist_ok=True)
            crypto_manager.encrypt_json(self.users, USERS_DB_FILE)
        except Exception as e:
            print(f"Error saving encrypted auth db: {e}")

    # ── User management ───────────────────────────────────────────────────

    def has_users(self):
        """Check if any users exist."""
        return len(self.users) > 0

    def register_user(self, username, email, password, role="admin", auth_method="manual"):
        """
        Register a new user.
        auth_method: "manual" for username/password, "google" for Google SSO.
        """
        if username in self.users:
            return False, "Username already exists."

        h, s = self._hash_password(password)
        self.users[username] = {
            "hash":             h,
            "salt":             s,
            "role":             role,
            "registered_email": email.strip().lower(),
            "license_key":      "",
            "auth_method":      auth_method,   # NEW
            "sso_pin_hash":     "",            # NEW — set during first Google login
            "sso_pin_salt":     "",            # NEW
        }
        self._save_db()
        return True, "Registration successful."

    def login(self, username, password):
        """
        Verify credentials.
        Returns: (success: bool, role: str, message: str)
        """
        if username not in self.users:
            return False, None, "User not found"

        user_data   = self.users[username]
        stored_hash = user_data.get("hash")
        salt        = user_data.get("salt")

        check_hash, _ = self._hash_password(password, salt)

        if check_hash == stored_hash:
            return True, user_data.get("role", "user"), "Login Successful"
        else:
            return False, None, "Invalid Password"

    # ── Google SSO helpers ────────────────────────────────────────────────

    def get_auth_method(self, username):
        """Return 'google' or 'manual' for the given user."""
        return self.users.get(username, {}).get("auth_method", "manual")

    def is_google_email_registered(self, email):
        """
        ALLOWLIST CHECK — Phase A Part 4, Gap 2 fix.
        Returns (True, username) if the email belongs to a registered user,
        (False, None) otherwise.
        Only registered emails may log in via Google.
        """
        email_lower = email.strip().lower()
        for username, data in self.users.items():
            if data.get("registered_email", "").lower() == email_lower:
                return True, username
        return False, None

    def has_sso_pin(self, username):
        """Return True if this user has set an SSO PIN."""
        user = self.users.get(username, {})
        return bool(user.get("sso_pin_hash"))

    def set_sso_pin(self, username, pin):
        """
        Store a hashed SSO PIN for the user.
        Called after Google verifies the user for the first time.
        Returns (True, msg) or (False, msg).
        """
        if username not in self.users:
            return False, "User not found."
        if not pin or len(pin) < 4:
            return False, "PIN must be at least 4 digits."
        if not pin.isdigit():
            return False, "PIN must contain digits only."

        h, s = self._hash_password(pin)
        self.users[username]["sso_pin_hash"] = h
        self.users[username]["sso_pin_salt"] = s
        self._save_db()
        return True, "PIN set successfully."

    def verify_sso_pin(self, username, pin):
        """
        Verify an SSO PIN for the given user.
        Returns True/False.
        """
        user = self.users.get(username, {})
        stored_hash = user.get("sso_pin_hash", "")
        salt        = user.get("sso_pin_salt", "")

        if not stored_hash or not salt:
            return False

        check_hash, _ = self._hash_password(pin, salt)
        return check_hash == stored_hash

    # ── Tier / License ────────────────────────────────────────────────────

    def get_user_tier(self, username: str) -> str:
        """
        Return the user's active tier by validating their license key
        against the subscription server (or local cache).
 
        Returns: "free" | "pro_monthly" | "pro_annual" | "PRO" (legacy)
        """
        user = self.users.get(username, {})
 
        # ── 1. Check for a hard-coded override (legacy activation path) ────────
        # Users who activated via the old static-key system have tier="PRO"
        # stored directly in users.dat. Honour this so existing customers
        # are not broken when you deploy the new system.
        if user.get("tier") == "PRO":
            return "PRO"
 
        # ── 2. No license key stored → definitely free ─────────────────────────
        key   = user.get("license_key", "")
        email = user.get("registered_email", "")
 
        if not key or not email:
            return "free"
 
        # ── 3. Validate against server (uses 24h encrypted local cache) ─────────
        try:
            from core.license_verifier import license_verifier
            is_valid, tier = license_verifier.verify_license(email, key)
            if is_valid:
                return tier
            else:
                return "free"
        except Exception as e:
            print(f"[AUTH] License check error for {username}: {e}")
            return "free"

    def activate_license(self, username, key):
        """Attempt to activate a license key using the already registered email."""
        if username not in self.users:
            return False, "User not found"

        email = self.users[username].get("registered_email", "")
        if not email:
            return False, "No email registered for this account."

        is_valid, tier = license_verifier.verify_license(email, key)

        if is_valid:
            self.users[username]["license_key"] = key
            self.users[username]["tier"]         = "PRO"
            self._save_db()
            return True, f"Success! Upgraded to {tier.upper()} Plan."
        else:
            return False, "Invalid License Key."

    def update_password(self, username, new_password):
        """Update the password for a specific user."""
        if username not in self.users:
            return False, "User not found"

        h, s = self._hash_password(new_password)
        self.users[username]["hash"] = h
        self.users[username]["salt"] = s

        try:
            self._save_db()
            return True, "Password updated successfully"
        except Exception as e:
            return False, f"Failed to save database: {e}"


# Singleton instance
auth = AuthManager()