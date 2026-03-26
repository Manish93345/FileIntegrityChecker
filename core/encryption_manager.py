"""
encryption_manager.py — FMSecure v2.0
AES-256 (Fernet) encryption with HARDWARE-BOUND KEK RESILIENCE:

  KEY PROTECTION LAYERS:
    0. Hardware KEK  → Invisible key derived from physical Motherboard/CPU (in RAM only).
    1. Primary key   → AppData/FMSecure/system32_config/sys.key (Encrypted by KEK)
    2. Local backup  → AppData/FMSecure/system32_shadow/.sys_backup.key (Encrypted by KEK)
    3. Cloud backup  → Google Drive (Encrypted by KEK)
"""

import os
import json
import shutil
import threading
import platform
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from core.utils import get_app_data_dir

class EncryptionManager:
    def __init__(self):
        self.app_data      = get_app_data_dir()
        
        # Primary Key Location
        self.key_dir       = os.path.join(self.app_data, "system32_config")
        self.key_file      = os.path.join(self.key_dir, "sys.key")          
        
        # Isolated Shadow Backup Location
        self.shadow_dir    = os.path.join(self.app_data, "system32_shadow")
        self.key_backup    = os.path.join(self.shadow_dir, ".sys_backup.key")  
        
        self.fernet        = None
        self._key_bytes    = None   
        
        # --- NEW: Generate the Hardware-Bound Key Encryption Key (KEK) ---
        self.hardware_kek  = self._generate_hardware_kek()

    # ──────────────────────────────────────────────────────────────────────────
    #  HARDWARE BINDING & INTERNAL HELPERS
    # ──────────────────────────────────────────────────────────────────────────

    def _generate_hardware_kek(self):
        """Derives a unique AES key based purely on the physical PC hardware."""
        hw_string = f"{platform.node()}-{platform.machine()}-{platform.processor()}"
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"fmsecure_enterprise_salt_v2", # Static salt for the KEK
            iterations=100000,
        )
        return Fernet(base64.urlsafe_b64encode(kdf.derive(hw_string.encode())))

    def _hide(self, path):
        """Mark a file as hidden on Windows."""
        try:
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(path, 2)
        except Exception:
            pass

    def _write_key(self, path, raw_key_bytes):
        """Encrypts the master key with the Hardware KEK, then writes to disk."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        # 🚨 KEK ENCRYPTION: Lock the master key before it touches the hard drive
        encrypted_master_key = self.hardware_kek.encrypt(raw_key_bytes)
        
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(encrypted_master_key)
            
        if os.path.exists(path):
            os.remove(path)
        os.rename(tmp, path)
        self._hide(path)

    def _read_key(self, path):
        """Reads and decrypts the master key using the Hardware KEK."""
        try:
            with open(path, "rb") as f:
                data = f.read()
                
            # --- THE LEGACY UPGRADE PATH ---
            # If the file is exactly 44 bytes, it is an old unencrypted key!
            if len(data) == 44:
                try:
                    Fernet(data) # Test if it's a valid raw key
                    print(f"[KEY] Legacy plaintext key detected at {os.path.basename(path)}. Upgrading to Hardware-Bound KEK...")
                    self._write_key(path, data) # Encrypt it instantly!
                    return data
                except Exception:
                    pass
                    
            # --- NORMAL OPERATION ---
            # Use the physical PC hardware to unlock the file
            try:
                raw_key = self.hardware_kek.decrypt(data)
                return raw_key
            except Exception:
                print(f"[KEY] CRITICAL: Hardware KEK decryption failed for {os.path.basename(path)}! Was this file copied from another PC?")
                return None
                
        except Exception:
            return None

    def _validate_fernet(self, key_bytes):
        """Return a Fernet instance if key is valid, else None."""
        try:
            return Fernet(key_bytes)
        except Exception:
            return None

    # ──────────────────────────────────────────────────────────────────────────
    #  KEY INITIALIZATION WITH RESILIENCE
    # ──────────────────────────────────────────────────────────────────────────

    def _initialize_key(self):
        os.makedirs(self.key_dir, exist_ok=True)

        # ── TIER 1: Primary key file 
        key = self._read_key(self.key_file)
        if key and self._validate_fernet(key):
            self._activate(key)
            self._ensure_local_backup(key)          
            self._schedule_cloud_backup(key)        
            return

        print("[KEY] Primary key missing, corrupt, or Hardware Mismatch — attempting recovery...")

        # ── TIER 2: Local shadow backup 
        key = self._read_key(self.key_backup)
        if key and self._validate_fernet(key):
            print("[KEY] Recovered from local shadow backup. Restoring primary...")
            self._write_key(self.key_file, key)
            self._activate(key)
            self._schedule_cloud_backup(key)
            return

        print("[KEY] Local backup also missing — attempting cloud recovery...")

        # ── TIER 3: Cloud Recovery
        key = self._attempt_cloud_key_recovery()
        if key and self._validate_fernet(key):
            print("[KEY] ✅ Cloud recovery successful.")
            self._write_key(self.key_file, key)
            self._activate(key)
            self._ensure_local_backup(key)
            return

        # ── TIER 4: Generate fresh key
        print("[KEY] WARNING: No backup found anywhere. Generating NEW encryption key.")
        key = Fernet.generate_key()
        self._write_key(self.key_file, key)
        self._write_key(self.key_backup, key)
        self._activate(key)
        self._schedule_cloud_backup(key)

    def _activate(self, key_bytes):
        self._key_bytes = key_bytes
        self.fernet = Fernet(key_bytes)

    def _ensure_local_backup(self, key_bytes):
        existing = self._read_key(self.key_backup)
        if existing != key_bytes:
            self._write_key(self.key_backup, key_bytes)

    # ──────────────────────────────────────────────────────────────────────────
    #  CLOUD KEY BACKUP / RECOVERY
    # ──────────────────────────────────────────────────────────────────────────

    def _schedule_cloud_backup(self, key_bytes):
        def _upload():
            try:
                import time; time.sleep(3)
                from core.integrity_core import CONFIG
                admin_email = CONFIG.get("admin_email")
                is_pro = CONFIG.get("is_pro_user", False)
                
                if not is_pro or not admin_email or admin_email == "UnknownUser":
                    print("[KEY] ☁️ Cloud key backup skipped (Awaiting PRO activation / valid email).")
                    return
                
                from core.cloud_sync import cloud_sync
                if cloud_sync.is_active:
                    cloud_sync.upload_encrypted_backup(self.key_file)
                    cloud_sync.upload_encrypted_backup(self.key_backup)
                    print("[KEY] ☁️ Key backup synced to cloud.")
            except Exception as e:
                print(f"[KEY] Cloud key backup failed (non-critical): {e}")

        t = threading.Thread(target=_upload, daemon=True)
        t.start()

    def _attempt_cloud_key_recovery(self):
        try:
            from core.cloud_sync import cloud_sync
            if not cloud_sync.is_active:
                return None

            for remote_name, local_dest in [
                (os.path.basename(self.key_file),   self.key_file),
                (os.path.basename(self.key_backup),  self.key_backup),
            ]:
                tmp_path = local_dest + ".cloud_tmp"
                ok = cloud_sync.download_from_cloud(remote_name, tmp_path)
                if ok:
                    key = self._read_key(tmp_path)
                    try:
                        os.remove(tmp_path)
                    except Exception:
                        pass
                    if key:
                        return key
        except Exception as e:
            print(f"[KEY] Cloud recovery attempt failed: {e}")
        return None

    # ──────────────────────────────────────────────────────────────────────────
    #  PUBLIC API (unchanged interface)
    # ──────────────────────────────────────────────────────────────────────────

    def encrypt_json(self, data_dict, filepath):
        json_string = json.dumps(data_dict).encode('utf-8')
        encrypted_data = self.fernet.encrypt(json_string)
        with open(filepath, "wb") as f:
            f.write(encrypted_data)

    def decrypt_json(self, filepath):
        if not os.path.exists(filepath):
            return {}
        try:
            with open(filepath, "rb") as f:
                encrypted_data = f.read()
            decrypted_data = self.fernet.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode('utf-8'))
        except Exception as e:
            print(f"CRITICAL: Failed to decrypt {filepath} — Possible tampering! Error: {e}")
            return None

    def encrypt_string(self, text):
        return self.fernet.encrypt(text.encode('utf-8')).decode('utf-8')

    def decrypt_string(self, encrypted_text):
        try:
            return self.fernet.decrypt(encrypted_text.encode('utf-8')).decode('utf-8')
        except Exception:
            return "[TAMPERED/UNREADABLE LOG ENTRY]"

    def force_key_backup(self):
        if not self._key_bytes:
            return False, "No active key in memory."
        try:
            self._ensure_local_backup(self._key_bytes)
            self._schedule_cloud_backup(self._key_bytes)
            return True, "Key backup initiated."
        except Exception as e:
            return False, str(e)

    def get_key_status(self):
        primary_ok = bool(self._read_key(self.key_file))
        backup_ok  = bool(self._read_key(self.key_backup))
        return {
            "primary":  primary_ok,
            "local_backup": backup_ok,
            "in_memory":    self.fernet is not None,
            "healthy":      primary_ok and backup_ok,
        }

# Global singleton — imported everywhere
crypto_manager = EncryptionManager()
crypto_manager._initialize_key()