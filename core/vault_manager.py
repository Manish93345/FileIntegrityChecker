"""
vault_manager.py — FMSecure v2.0
Auto-Heal Vault with THREE-TIER protection.

CHANGES vs. original:
  • All cloud operations now delegate to cloud_sync's machine-ID-based
    sub-folders. No email-derived folder names anywhere in this file.
  • Cloud upload is always fire-and-forget (never blocks local backup).
  • restore_file() falls back to cloud vault/ subfolder when local copy
    is missing.
"""

import os
import threading
import hashlib
import shutil
from core.utils import get_app_data_dir


class VaultManager:
    def __init__(self):
        self.vault_dir = os.path.join(get_app_data_dir(), "system32_vault")
        os.makedirs(self.vault_dir, exist_ok=True)
        self._hide_dir(self.vault_dir)

    # ─────────────────────────────────────────────────────────────────────────
    #  HELPERS
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _hide_dir(path):
        try:
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(path, 2)
        except Exception:
            pass

    def _get_vault_path(self, original_filepath):
        """Stable, opaque filename derived from the original path."""
        path_hash = hashlib.sha256(
            original_filepath.encode('utf-8')).hexdigest()
        return os.path.join(self.vault_dir, f"{path_hash}.enc")

    # ─────────────────────────────────────────────────────────────────────────
    #  CLOUD SYNC  (always non-blocking, PRO gate inside cloud_sync)
    # ─────────────────────────────────────────────────────────────────────────

    def _cloud_upload_async(self, local_path):
        """
        Fire-and-forget upload to the machine-id vault/ subfolder.
        cloud_sync enforces the PRO gate internally — no check needed here.
        Failures are logged but never propagate to the caller.
        """
        def _upload():
            try:
                from core.cloud_sync import cloud_sync
                if cloud_sync.is_active:
                    cloud_sync.upload_encrypted_backup(local_path)
            except Exception as e:
                print(f"[VAULT] Cloud upload skipped (non-critical): {e}")

        threading.Thread(target=_upload, daemon=True).start()

    def _backup_key_files_async(self):
        """
        Push encryption key files to cloud keys/ subfolder after every
        successful file backup so key escrow stays in sync.
        cloud_sync enforces the PRO gate internally.
        """
        def _upload_keys():
            try:
                from core.cloud_sync import cloud_sync
                from core.encryption_manager import crypto_manager

                if not cloud_sync.is_active:
                    return

                for kpath in [crypto_manager.key_file, crypto_manager.key_backup]:
                    if os.path.exists(kpath):
                        cloud_sync.upload_key_by_machine_id(
                            local_path=kpath)
                        print(f"[VAULT] ☁️  Key synced: "
                              f"{os.path.basename(kpath)}")
            except Exception as e:
                print(f"[VAULT] Key cloud backup skipped (non-critical): {e}")

        threading.Thread(target=_upload_keys, daemon=True).start()

    # ─────────────────────────────────────────────────────────────────────────
    #  PUBLIC API
    # ─────────────────────────────────────────────────────────────────────────

    def backup_file(self, filepath, max_size_mb=10, allowed_exts=None):
        """
        Encrypt and store a file in the local vault, then async-upload to
        cloud vault/ subfolder (PRO only, enforced by cloud_sync).

        Returns (True, message) or (False, reason).
        """
        # --- 🚨 FIX 1: LOCAL VAULT & ACTIVE DEFENSE GATEKEEPER ---
        try:
            from core.integrity_core import CONFIG
            
            # 1. Obey the Active Defense GUI toggle (FIXED KEY NAME)
            if not CONFIG.get("active_defense", False):
                return False, "Active Defense is disabled."
                
            # 2. Obey the PRO Tier requirement
            if not CONFIG.get("is_pro_user", False):
                return False, "Forensic Vault requires PRO Tier."
        except Exception:
            pass
        # ---------------------------------------------------------
            
        from core.encryption_manager import crypto_manager

        if not os.path.exists(filepath):
            return False, "File does not exist."

        # Size gate
        try:
            size_mb = os.path.getsize(filepath) / (1024 * 1024)
            if size_mb > max_size_mb:
                return False, (f"File too large ({size_mb:.1f} MB). "
                               f"Max {max_size_mb} MB.")
        except OSError:
            return False, "Could not read file size."

        # Extension gate
        if allowed_exts:
            _, ext = os.path.splitext(filepath)
            if ext.lower() not in allowed_exts:
                return False, f"Extension '{ext}' not in vault allowlist."

        # ── Local backup ──────────────────────────────────────────────────────
        try:
            vault_path = self._get_vault_path(filepath)
            with open(filepath, "rb") as f:
                raw_data = f.read()

            encrypted_data = crypto_manager.fernet.encrypt(raw_data)
            tmp_path       = vault_path + ".tmp"

            with open(tmp_path, "wb") as f:
                f.write(encrypted_data)
            if os.path.exists(vault_path):
                os.remove(vault_path)
            os.rename(tmp_path, vault_path)

        except Exception as e:
            return False, f"Local vault backup failed: {e}"

        # ── Cloud backup (background, non-blocking) ───────────────────────────
        # self._cloud_upload_async(vault_path)
        # self._backup_key_files_async()

        return True, "File securely vaulted."

    def restore_file(self, filepath):
        """
        Two-tier restore:
          Tier 1 — Local vault  (fast, always tried first)
          Tier 2 — Cloud vault/ subfolder (automatic fallback)

        Returns (True, message) or (False, reason).
        """
        from core.encryption_manager import crypto_manager
        vault_path = self._get_vault_path(filepath)
        filename   = os.path.basename(vault_path)

        # ── Tier 1: Local vault ───────────────────────────────────────────────
        if not os.path.exists(vault_path):
            print(f"[VAULT] ⚠️  Local vault missing for "
                  f"'{os.path.basename(filepath)}'. Attempting cloud rescue…")

            # ── Tier 2: Cloud vault/ subfolder ────────────────────────────────
            try:
                from core.cloud_sync import cloud_sync
                if cloud_sync.is_active:
                    ok = cloud_sync.download_from_cloud(filename, vault_path)
                    if ok:
                        print("[VAULT] ☁️  Cloud rescue successful.")
                    else:
                        return False, "No backup in local vault or cloud."
                else:
                    return False, "No local vault and cloud sync is offline."
            except Exception as e:
                return False, f"Cloud rescue failed: {e}"

        # ── Decrypt & write ───────────────────────────────────────────────────
        try:
            with open(vault_path, "rb") as f:
                encrypted_data = f.read()

            decrypted_data = crypto_manager.fernet.decrypt(encrypted_data)
            tmp_path       = filepath + ".restore_tmp"

            with open(tmp_path, "wb") as f:
                f.write(decrypted_data)
                
            # --- 🚨 THE FIX: Windows File Lock Bypass ---
            import time
            success = False
            for attempt in range(10):  # Try 10 times (up to 3 seconds)
                try:
                    if os.path.exists(filepath):
                        os.remove(filepath)
                    os.rename(tmp_path, filepath)
                    success = True
                    break
                except (PermissionError, OSError):
                    time.sleep(0.3)  # Wait 300ms for the other program to let go
                    
            if not success:
                return False, "File is permanently locked by another program."
            # --------------------------------------------

            return True, "File successfully restored."

        except Exception as e:
            return False, f"Vault restoration failed: {e}"

    def backup_key_files(self):
        """
        Force synchronous key backup to cloud keys/ subfolder.
        Called from GUI 'Sync to Cloud' button.
        """
        from core.encryption_manager import crypto_manager
        results = []
        try:
            from core.cloud_sync import cloud_sync
            if not cloud_sync.is_active:
                return False, "Cloud sync is offline."

            for kpath in [crypto_manager.key_file, crypto_manager.key_backup]:
                if os.path.exists(kpath):
                    ok = cloud_sync.upload_key_by_machine_id(
                        local_path=kpath)
                    if ok:
                        results.append(os.path.basename(kpath))

            if results:
                return True, f"Keys synced: {', '.join(results)}"
            return False, "No key files found to sync."
        except Exception as e:
            return False, f"Key sync failed: {e}"

    def list_vault_files(self):
        """Return all encrypted vault entries (for GUI viewer)."""
        try:
            return [f for f in os.listdir(self.vault_dir)
                    if f.endswith(".enc")]
        except Exception:
            return []


# Global singleton
vault = VaultManager()