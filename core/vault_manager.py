import os
import shutil
from core.utils import get_app_data_dir
from core.encryption_manager import crypto_manager

class VaultManager:
    def __init__(self):
        self.vault_dir = os.path.join(get_app_data_dir(), "system32_vault")
        
        # Ensure the hidden vault directory exists
        if not os.path.exists(self.vault_dir):
            os.makedirs(self.vault_dir)
            # Make the vault folder hidden on Windows
            try:
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(self.vault_dir, 2)
            except:
                pass

    def _get_vault_path(self, original_filepath):
        """
        Creates a safe, unique filename for the vault based on the original path.
        We hash the path so hackers can't just search the vault for "index.html".
        """
        import hashlib
        path_hash = hashlib.sha256(original_filepath.encode('utf-8')).hexdigest()
        return os.path.join(self.vault_dir, f"{path_hash}.enc")

    def backup_file(self, filepath, max_size_mb=10, allowed_exts=None):
        """
        Safely copies and encrypts a file into the vault IF it passes the security rules.
        """
        if not os.path.exists(filepath):
            return False, "File does not exist."

        # RULE 1: Check File Size
        try:
            file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
            if file_size_mb > max_size_mb:
                return False, f"File too large ({file_size_mb:.1f}MB). Max is {max_size_mb}MB."
        except OSError:
            return False, "Could not read file size."

        # RULE 2: Check File Extension
        if allowed_exts:
            _, ext = os.path.splitext(filepath)
            if ext.lower() not in allowed_exts:
                return False, f"Extension {ext} not in allowed list for vaulting."

        # ACTION: Encrypt and Backup
        # ACTION: Encrypt and Backup
        try:
            vault_path = self._get_vault_path(filepath)
            
            # Read the raw bytes of the file
            with open(filepath, "rb") as f:
                raw_data = f.read()
                
            # Encrypt the raw bytes using our AES Fernet key
            encrypted_data = crypto_manager.fernet.encrypt(raw_data)
            
            # Save the encrypted blob to the hidden vault
            with open(vault_path, "wb") as f:
                f.write(encrypted_data)

            from core.cloud_sync import cloud_sync
                
            # --- NEW: FIRE OFF THE CLOUD SYNC ---
            # Now that the file is safely encrypted on the hard drive, beam it to Google Drive!
            cloud_sync.upload_encrypted_backup(vault_path)
                
            return True, "File securely vaulted."
        except Exception as e:
            return False, f"Vault backup failed: {e}"

    def restore_file(self, filepath):
        """
        TWO-TIER RESTORE:
        1. Try local vault.
        2. If local is missing (hacker deleted it), download from Cloud!
        """
        vault_path = self._get_vault_path(filepath)
        filename = os.path.basename(vault_path) # Gets just the 'hash.enc' part
        
        # --- TIER 2 DEFENSE: CLOUD RESCUE ---
        if not os.path.exists(vault_path):
            print(f"⚠️ Local vault missing {filename}! Attempting Cloud Rescue...")
            from core.cloud_sync import cloud_sync
            
            # Pause to download it from Google Drive
            success = cloud_sync.download_from_cloud(filename, vault_path)
            if not success:
                return False, "CRITICAL: No backup found in Local Vault OR Cloud Vault."
                
            print(f"☁️ Cloud Rescue successful! File downloaded to local vault.")

        # --- TIER 1: DECRYPT & RESTORE ---
        try:
            # Read the encrypted blob
            with open(vault_path, "rb") as f:
                encrypted_data = f.read()
                
            # Decrypt it back to raw bytes
            decrypted_data = crypto_manager.fernet.decrypt(encrypted_data)
            
            # Write it back to the original location (Overwriting the hacker's malware)
            with open(filepath, "wb") as f:
                f.write(decrypted_data)
                
            return True, "File successfully restored."
        except Exception as e:
            return False, f"Vault restoration failed: {e}"

# Global instance to be used by the security engine
vault = VaultManager()