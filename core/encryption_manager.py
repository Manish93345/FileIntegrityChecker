"""
encryption_manager.py — FMSecure v2.0
AES-256 (Fernet) encryption with KEY RESILIENCE:

  KEY PROTECTION LAYERS (in order of priority):
    1. Primary key   → AppData/FMSecure/system32_config/sys.key  (hidden)
    2. Local backup  → AppData/FMSecure/system32_config/.sys_backup.key (hidden, obfuscated name)
    3. Cloud backup  → Google Drive (uploaded automatically whenever the key changes)

  RECOVERY LOGIC on startup:
    - If primary key exists          → load it, silently verify backup exists
    - If primary missing, backup OK  → restore primary from backup, continue normally
    - If both local copies missing   → attempt cloud download, restore, continue
    - If all three missing           → generate NEW key, back it up everywhere,
                                       but warn the user that old data is unrecoverable

  This means deleting sys.key alone will NEVER cause a loss of access.
"""

import os
import json
import shutil
import threading
from cryptography.fernet import Fernet
from core.utils import get_app_data_dir


class EncryptionManager:
    def __init__(self):
        self.app_data      = get_app_data_dir()
        
        # Primary Key Location
        self.key_dir       = os.path.join(self.app_data, "system32_config")
        self.key_file      = os.path.join(self.key_dir, "sys.key")          
        
        # --- NEW: Isolated Shadow Backup Location ---
        self.shadow_dir    = os.path.join(self.app_data, "system32_shadow")
        self.key_backup    = os.path.join(self.shadow_dir, ".sys_backup.key")  
        
        self.fernet        = None
        self._key_bytes    = None   
        self._initialize_key()

    # ──────────────────────────────────────────────────────────────────────────
    #  INTERNAL HELPERS
    # ──────────────────────────────────────────────────────────────────────────

    def _hide(self, path):
        """Mark a file as hidden on Windows (no-op on other OS)."""
        try:
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(path, 2)
        except Exception:
            pass

    def _write_key(self, path, key_bytes):
        """Atomically write key bytes and mark hidden."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(key_bytes)
        if os.path.exists(path):
            os.remove(path)
        os.rename(tmp, path)
        self._hide(path)

    def _read_key(self, path):
        """Read raw key bytes, return None on any error."""
        try:
            with open(path, "rb") as f:
                data = f.read()
            if len(data) == 44:          # Fernet URL-safe base64 key is always 44 bytes
                return data
        except Exception:
            pass
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
        """
        Multi-tier key load with automatic healing.
        Never generates a new key if ANY valid backup exists.
        """
        os.makedirs(self.key_dir, exist_ok=True)

        # ── TIER 1: Primary key file ──────────────────────────────────────────
        key = self._read_key(self.key_file)
        if key and self._validate_fernet(key):
            self._activate(key)
            self._ensure_local_backup(key)          # heal backup if missing
            self._schedule_cloud_backup(key)        # background cloud sync
            return

        print("[KEY] Primary key missing or corrupt — attempting recovery...")

        # ── TIER 2: Local shadow backup ───────────────────────────────────────
        key = self._read_key(self.key_backup)
        if key and self._validate_fernet(key):
            print("[KEY] Recovered from local shadow backup. Restoring primary...")
            self._write_key(self.key_file, key)
            self._activate(key)
            self._schedule_cloud_backup(key)
            return

        print("[KEY] Local backup also missing — attempting cloud recovery...")

        # ── TIER 3: Cloud Recovery ──────────────────────────────────────────
        print("[KEY] Local backup also missing — attempting cloud recovery...")
        # ── TIER 3: Cloud Recovery (PRO Users Only) ─────────────────────────
        try:
            # Safely check config without triggering circular imports
            is_pro = False
            config_file = os.path.join(self.app_data, 'config.json')
            if os.path.exists(config_file):
                try:
                    with open(config_file, "r", encoding="utf-8") as f:
                        cfg = json.load(f)
                        is_pro = cfg.get("is_pro_user", False)
                except Exception:
                    pass

            if is_pro:
                print("[KEY] Local backup also missing — attempting cloud recovery...")
                key = self._attempt_cloud_key_recovery()
                if key and self._validate_fernet(key):
                    print("[KEY] ✅ Cloud recovery successful.")
                    self._write_key(self.key_file, key)
                    self._activate(key)
                    self._ensure_local_backup(key)
                    return
            else:
                print("[KEY] Skipping cloud recovery (Free Tier / First-time setup).")
                
        except Exception as e:
            print(f"[KEY] Cloud recovery check failed: {e}")

        # ── TIER 4: Generate fresh key (last resort — old data is gone) ───────
        print("[KEY] WARNING: No backup found anywhere. Generating NEW encryption key.")
        print("[KEY] All previously encrypted data (users, logs) is now unrecoverable.")
        key = Fernet.generate_key()
        self._write_key(self.key_file, key)
        self._write_key(self.key_backup, key)
        self._activate(key)
        self._schedule_cloud_backup(key)

    def _activate(self, key_bytes):
        """Set the active Fernet instance and cache key bytes."""
        self._key_bytes = key_bytes
        self.fernet = Fernet(key_bytes)

    def _ensure_local_backup(self, key_bytes):
        """Write shadow copy if it doesn't exist or is stale."""
        existing = self._read_key(self.key_backup)
        if existing != key_bytes:
            self._write_key(self.key_backup, key_bytes)

    # ──────────────────────────────────────────────────────────────────────────
    #  CLOUD KEY BACKUP / RECOVERY
    # ──────────────────────────────────────────────────────────────────────────

    def _schedule_cloud_backup(self, key_bytes):
        """Upload key to cloud in a daemon thread (non-blocking)."""
        def _upload():
            try:
                # Slight delay so the rest of the app finishes initialising first
                import time; time.sleep(3)
                
                # --- NEW FIX: Check for PRO Tier and Valid Email ---
                from core.integrity_core import CONFIG
                admin_email = CONFIG.get("admin_email")
                is_pro = CONFIG.get("is_pro_user", False)
                
                if not is_pro or not admin_email or admin_email == "UnknownUser":
                    print("[KEY] ☁️ Cloud key backup skipped (Awaiting PRO activation / valid email).")
                    return
                # ---------------------------------------------------
                
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
        """
        Try to download sys.key from Google Drive.
        Returns raw key bytes on success, None on failure.
        """
        try:
            from core.cloud_sync import cloud_sync
            if not cloud_sync.is_active:
                return None

            # Try primary filename first, then backup filename
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
        """Convert a dictionary to JSON and encrypt it to a file."""
        json_string = json.dumps(data_dict).encode('utf-8')
        encrypted_data = self.fernet.encrypt(json_string)
        with open(filepath, "wb") as f:
            f.write(encrypted_data)

    def decrypt_json(self, filepath):
        """Decrypt a file and convert it back to a dictionary."""
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
        """Encrypt a single string of text (used for log lines)."""
        return self.fernet.encrypt(text.encode('utf-8')).decode('utf-8')

    def decrypt_string(self, encrypted_text):
        """Decrypt a single string of text."""
        try:
            return self.fernet.decrypt(encrypted_text.encode('utf-8')).decode('utf-8')
        except Exception:
            return "[TAMPERED/UNREADABLE LOG ENTRY]"

    # ──────────────────────────────────────────────────────────────────────────
    #  KEY MANAGEMENT UTILITIES (called from GUI / admin actions)
    # ──────────────────────────────────────────────────────────────────────────

    def force_key_backup(self):
        """
        Manually trigger a full key backup (local + cloud).
        Call this from the GUI after settings are saved.
        """
        if not self._key_bytes:
            return False, "No active key in memory."
        try:
            self._ensure_local_backup(self._key_bytes)
            self._schedule_cloud_backup(self._key_bytes)
            return True, "Key backup initiated."
        except Exception as e:
            return False, str(e)

    def get_key_status(self):
        """
        Returns a dict describing the health of all key copies.
        Used by the GUI diagnostics panel.
        """
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