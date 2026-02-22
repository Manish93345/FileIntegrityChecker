import os
import json
from cryptography.fernet import Fernet
from core.utils import get_app_data_dir

class EncryptionManager:
    def __init__(self):
        self.app_data = get_app_data_dir()
        # Hide the key in a nested secure folder
        self.key_dir = os.path.join(self.app_data, "system32_config") 
        self.key_file = os.path.join(self.key_dir, "sys.key")
        self.fernet = None
        self._initialize_key()

    def _initialize_key(self):
        """Load existing key or generate a new one on first run"""
        if not os.path.exists(self.key_dir):
            os.makedirs(self.key_dir)

        if not os.path.exists(self.key_file):
            # Generate a new AES key
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as f:
                f.write(key)
            # Make the key file hidden on Windows
            try:
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(self.key_file, 2)
            except:
                pass

        # Load the key into memory
        with open(self.key_file, "rb") as f:
            key = f.read()
            self.fernet = Fernet(key)

    def encrypt_json(self, data_dict, filepath):
        """Convert a dictionary to JSON and encrypt it to a file"""
        json_string = json.dumps(data_dict).encode('utf-8')
        encrypted_data = self.fernet.encrypt(json_string)
        
        # Save as a binary file
        with open(filepath, "wb") as f:
            f.write(encrypted_data)

    def decrypt_json(self, filepath):
        """Decrypt a file and convert it back to a dictionary"""
        if not os.path.exists(filepath):
            return {}
            
        try:
            with open(filepath, "rb") as f:
                encrypted_data = f.read()
                
            decrypted_data = self.fernet.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode('utf-8'))
        except Exception as e:
            # If the file was tampered with, decryption will intentionally fail here!
            print(f"CRITICAL: Failed to decrypt {filepath} - Possible tampering! Error: {e}")
            return None

# Create a global instance to be used across the app
crypto_manager = EncryptionManager()