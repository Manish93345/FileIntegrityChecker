#!/usr/bin/env python3
"""
auth_manager.py
Backend logic for Authentication System.
Handles user storage, password hashing (SHA-256 + Salt), and role verification.
"""

import json
import os
import hashlib
import uuid

USERS_DB_FILE = os.path.join("logs", "users.json")

# Default credentials (created on first run)
DEFAULT_USERS = {
    "admin": {
        "password": "admin123", # Will be hashed on creation
        "role": "admin"
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
        # Combine password and salt
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
                "role": data["role"]
            }
        self._save_db()

    def _save_db(self):
        with open(USERS_DB_FILE, 'w') as f:
            json.dump(self.users, f, indent=4)

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
        
        # Hash the provided password with the stored salt
        check_hash, _ = self._hash_password(password, salt)
        
        if check_hash == stored_hash:
            return True, user_data["role"], "Login Successful"
        else:
            return False, None, "Invalid Password"

    def update_password(self, username, new_password):
        """Update the password for a specific user"""
        if username not in self.users:
            return False, "User not found"
        
        # Generate new hash and salt
        h, s = self._hash_password(new_password)
        
        # Update in memory
        self.users[username]["hash"] = h
        self.users[username]["salt"] = s
        
        # Save to file
        try:
            self._save_db()
            return True, "Password updated successfully"
        except Exception as e:
            return False, f"Failed to save database: {e}"

    def get_role(self, username):
        return self.users.get(username, {}).get("role", "user")

# Singleton instance
auth = AuthManager()