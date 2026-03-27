"""
encryption_manager.py — FMSecure v2.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

INDUSTRY-GRADE KEY MANAGEMENT — HOW THE CHICKEN-AND-EGG IS SOLVED
──────────────────────────────────────────────────────────────────
The problem: "sys.key is deleted → must recover from cloud → but cloud needs
  OAuth → OAuth token is in token.pickle → token.pickle is NOT encrypted →
  so cloud auth ALWAYS works → the only missing piece was correct design."

The real bug in the previous version was Python import order:
  1. encryption_manager is imported first (no cloud_sync module yet)
  2. _initialize_key() immediately calls _attempt_cloud_key_recovery()
  3. `from core.cloud_sync import cloud_sync` raises ImportError (circular)
  4. Cloud recovery silently falls through → new key generated → "Create Account"

THE FIX — Two-Phase Initialization:
  Phase 1 (sync, at import):   Local-only. Never touches the network.
  Phase 2 (sync, from startup): Cloud recovery. Called AFTER cloud_sync is ready.

MACHINE IDENTITY solves the chicken-and-egg at the cloud level:
  • machine_id.txt is a plaintext file (never encrypted, always readable)
  • Cloud folder is named after machine_id, not user email
  • No need to decrypt users.dat to find the email before fetching the key

KEY PROTECTION LAYERS:
  L1  Primary  → AppData/system32_config/sys.key           (KEK-encrypted)
  L2  Shadow   → AppData/system32_shadow/.sys_backup.key   (KEK-encrypted)
  L3  Cloud    → Google Drive/FMSecure_Keys_{MACHINE_ID}/   (KEK-encrypted)
                 PRO users only. Identified by machine_id, NOT email.
  L4  New key  → Last resort. Warns to console. Old data unrecoverable.

FREE vs PRO:
  Free: L1 + L2 (local resilience)
  PRO:  L1 + L2 + L3 (full cloud key escrow)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import os
import json
import hashlib
import platform
import base64
import threading
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from core.utils import get_app_data_dir


class EncryptionManager:

    def __init__(self):
        self.app_data    = get_app_data_dir()
        self.key_dir     = os.path.join(self.app_data, "system32_config")
        self.shadow_dir  = os.path.join(self.app_data, "system32_shadow")
        self.key_file    = os.path.join(self.key_dir,    "sys.key")
        self.key_backup  = os.path.join(self.shadow_dir, ".sys_backup.key")

        os.makedirs(self.key_dir,    exist_ok=True)
        os.makedirs(self.shadow_dir, exist_ok=True)

        # Machine identity — plaintext, hardware-derived, never encrypted
        self._machine_id = self._get_or_create_machine_id()

        # Hardware KEK — lives in RAM only, re-derived on every boot
        self.hardware_kek = self._derive_hardware_kek()

        # Runtime state
        self.fernet     = None
        self._key_bytes = None
        self._local_ok  = False
        self._cloud_recovery_attempted = False

        # Phase 1: local-only load (safe at import time — no network)
        self._phase1_local_init()

    # ══════════════════════════════════════════════════════════════════════════
    #  MACHINE IDENTITY
    # ══════════════════════════════════════════════════════════════════════════

    def _get_or_create_machine_id(self) -> str:
        """
        Stable hardware-derived ID stored as plaintext.
        Used as the cloud folder name so we can retrieve the key
        without needing to decrypt anything first.
        """
        mid_file = os.path.join(self.key_dir, "machine_id.txt")
        if os.path.exists(mid_file):
            try:
                mid = open(mid_file).read().strip()
                if mid:
                    return mid
            except Exception:
                pass

        hw  = f"{platform.node()}-{platform.machine()}-{platform.processor()}"
        mid = "FM-" + hashlib.sha256(hw.encode()).hexdigest()[:24].upper()

        try:
            with open(mid_file, "w") as f:
                f.write(mid)
        except Exception:
            pass

        return mid

    # ══════════════════════════════════════════════════════════════════════════
    #  HARDWARE KEK
    # ══════════════════════════════════════════════════════════════════════════

    def _derive_hardware_kek(self) -> Fernet:
        """
        Derives an AES-256 key from physical hardware.
        Never written to disk. Identical on every boot of the same machine.
        """
        hw  = f"{platform.node()}-{platform.machine()}-{platform.processor()}"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"fmsecure_kek_salt_v2_immutable",
            iterations=200_000,
        )
        return Fernet(base64.urlsafe_b64encode(kdf.derive(hw.encode())))

    # ══════════════════════════════════════════════════════════════════════════
    #  KEY FILE I/O
    # ══════════════════════════════════════════════════════════════════════════

    def _write_key(self, path: str, raw_key: bytes):
        """KEK-encrypt, then atomically write."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        blob = self.hardware_kek.encrypt(raw_key)
        tmp  = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(blob)
        if os.path.exists(path):
            os.remove(path)
        os.rename(tmp, path)
        self._hide(path)

    def _read_key(self, path: str):
        """
        Read and KEK-decrypt a key file.
        Handles legacy v1 plaintext keys (44-byte raw Fernet keys).
        Returns raw Fernet key bytes, or None on failure.
        """
        if not os.path.exists(path):
            return None
        try:
            data = open(path, "rb").read()
            if not data:
                return None

            # Legacy v1 upgrade path
            if len(data) == 44:
                try:
                    Fernet(data)
                    print(f"[KEY] Upgrading legacy key '{os.path.basename(path)}' to KEK format.")
                    self._write_key(path, data)
                    return data
                except Exception:
                    pass

            # Normal KEK-encrypted path
            try:
                return self.hardware_kek.decrypt(data)
            except Exception:
                print(f"[KEY] KEK mismatch for '{os.path.basename(path)}' "
                      f"(different machine or corrupted).")
                return None

        except Exception as e:
            print(f"[KEY] Read error '{path}': {e}")
            return None

    @staticmethod
    def _valid(key_bytes) -> bool:
        try:
            Fernet(key_bytes)
            return True
        except Exception:
            return False

    @staticmethod
    def _hide(path: str):
        try:
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(path, 2)
        except Exception:
            pass

    # ══════════════════════════════════════════════════════════════════════════
    #  PHASE 1 — LOCAL INIT  (runs at import, no network)
    # ══════════════════════════════════════════════════════════════════════════

    def _phase1_local_init(self):
        # L1 — Primary
        key = self._read_key(self.key_file)
        if key and self._valid(key):
            self._activate(key)
            self._ensure_shadow(key)
            self._local_ok = True
            print("[KEY] ✅ Primary key loaded.")
            return

        # L2 — Shadow backup
        print("[KEY] Primary missing — checking shadow backup...")
        key = self._read_key(self.key_backup)
        if key and self._valid(key):
            print("[KEY] ✅ Shadow backup restored primary key.")
            self._write_key(self.key_file, key)
            self._activate(key)
            self._local_ok = True
            return

        # Signal that Phase 2 (cloud) is needed
        print("[KEY] ⚠️  No valid local key. Phase 2 cloud recovery required.")
        self._local_ok = False

    # ══════════════════════════════════════════════════════════════════════════
    #  PHASE 2 — CLOUD RECOVERY  (called from app startup, after cloud_sync ready)
    # ══════════════════════════════════════════════════════════════════════════

    def attempt_cloud_recovery_if_needed(self) -> bool:
        """
        Called explicitly from the application startup sequence AFTER
        cloud_sync has been instantiated. This is the correct call site:

            # In your main startup / login_gui.py, after imports:
            from core.cloud_sync import cloud_sync   # ensures it's ready
            crypto_manager.attempt_cloud_recovery_if_needed()

        Returns:
            True  — key is available (was local, or cloud recovery succeeded)
            False — new key was generated (old data unrecoverable)
        """
        # Already healthy — just schedule a background cloud backup
        if self._local_ok and self.fernet is not None:
            self._schedule_cloud_backup_async()
            return True

        if self._cloud_recovery_attempted:
            return self.fernet is not None

        self._cloud_recovery_attempted = True
        print("[KEY] Phase 2: Attempting cloud key recovery via machine_id...")

        key = self._download_from_cloud()
        if key and self._valid(key):
            print("[KEY] ✅ Cloud recovery succeeded.")
            self._write_key(self.key_file,   key)
            self._write_key(self.key_backup, key)
            self._activate(key)
            self._local_ok = True
            return True

        # Last resort
        print("[KEY] ❌ All recovery tiers failed. Generating fresh key.")
        print("[KEY]    Data encrypted with the previous key is now unrecoverable.")
        key = Fernet.generate_key()
        self._write_key(self.key_file,   key)
        self._write_key(self.key_backup, key)
        self._activate(key)
        self._local_ok = True
        self._schedule_cloud_backup_async()
        return False

    # ══════════════════════════════════════════════════════════════════════════
    #  CLOUD DOWNLOAD
    # ══════════════════════════════════════════════════════════════════════════

    def _download_from_cloud(self):
        """
        Download a KEK-encrypted key from the machine-specific Drive folder.
        No email needed — machine_id is the lookup key.
        Google OAuth token.pickle is plaintext so this always works.
        """
        try:
            from core.cloud_sync import cloud_sync
            if not cloud_sync.is_active:
                print("[KEY] Cloud offline — cannot attempt download.")
                return None

            for fname in ["sys.key", ".sys_backup.key"]:
                tmp = os.path.join(self.key_dir, fname + ".cloud_tmp")
                try:
                    ok = cloud_sync.download_key_by_machine_id(
                        filename=fname,
                        machine_id=self._machine_id,
                        local_dest=tmp
                    )
                    if ok:
                        key = self._read_key(tmp)
                        try:
                            os.remove(tmp)
                        except Exception:
                            pass
                        if key:
                            print(f"[KEY] ☁️ Downloaded '{fname}' from cloud.")
                            return key
                except Exception as e:
                    print(f"[KEY] Download failed for '{fname}': {e}")

        except ImportError:
            print("[KEY] cloud_sync module not available yet.")
        except Exception as e:
            print(f"[KEY] Cloud download error: {e}")

        return None

    # ══════════════════════════════════════════════════════════════════════════
    #  CLOUD UPLOAD
    # ══════════════════════════════════════════════════════════════════════════

    def _schedule_cloud_backup_async(self):
        """Non-blocking — spawns daemon thread. PRO-only."""
        def _run():
            time.sleep(5)
            try:
                from core.integrity_core import CONFIG
                if not CONFIG.get("is_pro_user", False):
                    print("[KEY] Free plan — cloud key backup skipped.")
                    return
                self._upload_to_cloud()
            except Exception as e:
                print(f"[KEY] Background cloud backup error: {e}")

        threading.Thread(target=_run, daemon=True).start()

    def _upload_to_cloud(self) -> bool:
        """
        Upload both key files to the machine-specific Drive folder.
        Identified by machine_id — no email needed.
        """
        try:
            from core.cloud_sync import cloud_sync
            if not cloud_sync.is_active:
                return False

            count = 0
            for kpath in [self.key_file, self.key_backup]:
                if os.path.exists(kpath):
                    ok = cloud_sync.upload_key_by_machine_id(
                        local_path=kpath,
                        machine_id=self._machine_id
                    )
                    if ok:
                        count += 1
                        print(f"[KEY] ☁️ Uploaded '{os.path.basename(kpath)}'.")

            return count > 0

        except Exception as e:
            print(f"[KEY] Cloud upload error: {e}")
            return False

    # ══════════════════════════════════════════════════════════════════════════
    #  INTERNAL HELPERS
    # ══════════════════════════════════════════════════════════════════════════

    def _activate(self, key_bytes: bytes):
        self._key_bytes = key_bytes
        self.fernet = Fernet(key_bytes)

    def _ensure_shadow(self, key_bytes: bytes):
        if self._read_key(self.key_backup) != key_bytes:
            self._write_key(self.key_backup, key_bytes)

    # ══════════════════════════════════════════════════════════════════════════
    #  PUBLIC ENCRYPTION API
    # ══════════════════════════════════════════════════════════════════════════

    def encrypt_json(self, data_dict: dict, filepath: str):
        payload = json.dumps(data_dict).encode("utf-8")
        with open(filepath, "wb") as f:
            f.write(self.fernet.encrypt(payload))

    def decrypt_json(self, filepath: str):
        if not os.path.exists(filepath):
            return {}
        try:
            data = open(filepath, "rb").read()
            return json.loads(self.fernet.decrypt(data).decode("utf-8"))
        except Exception as e:
            print(f"[CRYPTO] decrypt_json failed for '{filepath}': {e}")
            return None

    def encrypt_string(self, text: str) -> str:
        return self.fernet.encrypt(text.encode("utf-8")).decode("utf-8")

    def decrypt_string(self, token: str) -> str:
        try:
            return self.fernet.decrypt(token.encode("utf-8")).decode("utf-8")
        except Exception:
            return "[TAMPERED/UNREADABLE LOG ENTRY]"

    # ══════════════════════════════════════════════════════════════════════════
    #  PUBLIC KEY MANAGEMENT API
    # ══════════════════════════════════════════════════════════════════════════

    def force_key_backup(self) -> tuple:
        """Force immediate cloud key backup. Call after PRO activation."""
        if not self._key_bytes:
            return False, "No active key in memory."
        self._ensure_shadow(self._key_bytes)
        ok = self._upload_to_cloud()
        return ok, "Cloud backup complete." if ok else "Cloud offline — shadow backup updated."

    def get_key_status(self) -> dict:
        return {
            "primary_exists": os.path.exists(self.key_file),
            "shadow_exists":  os.path.exists(self.key_backup),
            "in_memory":      self.fernet is not None,
            "machine_id":     self._machine_id,
            "local_healthy":  (os.path.exists(self.key_file) and
                               os.path.exists(self.key_backup)),
        }

    def get_machine_id(self) -> str:
        return self._machine_id


# ── Global singleton ──────────────────────────────────────────────────────────
# Phase 1 (local-only) runs here at import time.
# Call crypto_manager.attempt_cloud_recovery_if_needed() from your
# app startup code AFTER cloud_sync has been initialised.
crypto_manager = EncryptionManager()