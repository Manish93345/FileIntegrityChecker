# core/auth_manager.py

#!/usr/bin/env python3
"""
auth_manager.py
Backend logic for Authentication System.
Handles user storage, password hashing (SHA-256 + Salt), role, and SUBSCRIPTION TIER.
"""

import json
import os
import hashlib
import uuid
from core.utils import get_app_data_dir

# Use the safe path for storage
USERS_DB_FILE = os.path.join(get_app_data_dir(), "logs", "users.json")

# Default credentials (created on first run)
DEFAULT_USERS = {
    "admin": {
        "password": "admin123", 
        "role": "admin",
        "tier": "premium"  # Admin gets PRO features by default
    },
    "user": {
        "password": "user123",
        "role": "user",
        "tier": "free"     # Standard users start on Free
    }
}

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
        """Load users from JSON or create defaults"""
        if not os.path.exists(USERS_DB_FILE):
            self._create_default_db()
        
        try:
            with open(USERS_DB_FILE, 'r') as f:
                self.users = json.load(f)
        except Exception as e:
            print(f"Auth DB Error: {e}. Recreating defaults.")
            self._create_default_db()

    def _create_default_db(self):
        """Create the initial database with hashed passwords"""
        self.users = {}
        for username, data in DEFAULT_USERS.items():
            h, s = self._hash_password(data["password"])
            self.users[username] = {
                "hash": h,
                "salt": s,
                "role": data["role"],
                "tier": data["tier"]
            }
        self._save_db()

    def _save_db(self):
        try:
            os.makedirs(os.path.dirname(USERS_DB_FILE), exist_ok=True)
            with open(USERS_DB_FILE, 'w') as f:
                json.dump(self.users, f, indent=4)
        except Exception as e:
            print(f"Error saving auth db: {e}")

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
        """Get the subscription tier for a user (free/premium)"""
        user = self.users.get(username, {})
        return user.get("tier", "free")  # Default to free if missing

    def upgrade_user(self, username, new_tier="premium"):
        """Upgrade a user's subscription"""
        if username in self.users:
            self.users[username]["tier"] = new_tier
            self._save_db()
            return True
        return False

    def update_password(self, username, new_password):
        if username not in self.users:
            return False, "User not found"
        
        h, s = self._hash_password(new_password)
        self.users[username]["hash"] = h
        self.users[username]["salt"] = s
        
        self._save_db()
        return True, "Password updated successfully"

# Singleton instance
auth = AuthManager()