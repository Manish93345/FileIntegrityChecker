#!/usr/bin/env python3
"""
auth_manager.py
Backend logic for Authentication System.
Handles user storage, password hashing (SHA-256 + Salt), role, and LICENSE VERIFICATION.
Now secured with AES-128 Encryption at rest.
"""

import os
import hashlib
import uuid
from core.utils import get_app_data_dir
from core.license_verifier import license_verifier
from core.encryption_manager import crypto_manager  # <-- NEW ENCRYPTION MANAGER

# Changed extension to .dat for binary encrypted storage
USERS_DB_FILE = os.path.join(get_app_data_dir(), "logs", "users.dat")

class AuthManager:
    def __init__(self):
        self.users = {}
        self._load_users()

    def _hash_password(self, password, salt=None):
        """Hash password using SHA-256 and a salt"""
        if not salt:
            salt = uuid.uuid4().hex
        hashed = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
        return hashed, salt

    def _load_users(self):
        """Load users from the encrypted vault."""
        if not os.path.exists(USERS_DB_FILE):
            self._save_db() # Create empty encrypted file
            return
            
        # Decrypt the binary file back into a dictionary
        decrypted_data = crypto_manager.decrypt_json(USERS_DB_FILE)
        
        if decrypted_data is None:
            # If decryption fails (tampering detected), wipe and start fresh
            print("SECURITY ALERT: users.dat is corrupted or tampered with. Starting fresh.")
            self.users = {}
            self._save_db()
        else:
            self.users = decrypted_data

    def _save_db(self):
        """Save users to the encrypted vault"""
        try:
            os.makedirs(os.path.dirname(USERS_DB_FILE), exist_ok=True)
            # Pass the dictionary directly to our encrypter
            crypto_manager.encrypt_json(self.users, USERS_DB_FILE)
        except Exception as e:
            print(f"Error saving encrypted auth db: {e}")

    def has_users(self):
        """Check if any users exist. Used by GUI to trigger First-Time Registration."""
        return len(self.users) > 0

    def register_user(self, username, email, password, role="admin"):
        """Register a new user (Usually the first admin)"""
        if username in self.users:
            return False, "Username already exists."
            
        h, s = self._hash_password(password)
        self.users[username] = {
            "hash": h,
            "salt": s,
            "role": role,
            "registered_email": email.strip().lower(),
            "license_key": ""
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
        
        user_data = self.users[username]
        stored_hash = user_data.get("hash")
        salt = user_data.get("salt")
        
        check_hash, _ = self._hash_password(password, salt)
        
        if check_hash == stored_hash:
            return True, user_data.get("role", "user"), "Login Successful"
        else:
            return False, None, "Invalid Password"

    def get_user_tier(self, username):
        """Calculate tier based on the stored license key and registered email."""
        user = self.users.get(username, {})
        key = user.get("license_key", "")
        email = user.get("registered_email", "")
        
        if not key or not email:
            return "free"
            
        is_valid, tier = license_verifier.verify_license(email, key)
        
        if is_valid:
            return tier
        else:
            return "free"

    def activate_license(self, username, key):
        """Attempt to activate a license key using the ALREADY registered email"""
        if username not in self.users:
            return False, "User not found"
            
        # Fetch the email they used on Day 1
        email = self.users[username].get("registered_email", "")
        if not email:
            return False, "No email registered for this account."

        # Verify using the saved email
        is_valid, tier = license_verifier.verify_license(email, key)
        
        if is_valid:
            self.users[username]["license_key"] = key
            self._save_db()
            return True, f"Success! Upgraded to {tier.upper()} Plan."
        else:
            return False, "Invalid License Key."

    def update_password(self, username, new_password):
        """Update the password for a specific user"""
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