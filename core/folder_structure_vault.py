"""
folder_structure_vault.py — FMSecure v2.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

FOLDER STRUCTURE VAULT — PRO FEATURE
─────────────────────────────────────
Backs up the complete folder structure (files + directory hierarchy) of all
monitored folders to Google Drive.  Respects vault allowed-extension + size
rules so only text/config/source files are backed up — not binary blobs.

Google Drive layout (inside the existing machine folder):
  FMSecure_{MACHINE_ID}/
    folder_backup/
      <watched_folder_name>_{hash}/
        manifest.json          ← maps Drive file-IDs → original relative paths
        <hash>.enc             ← AES-encrypted file content (Fernet)

RESTORE MODES:
  A) Original location  — recreates D:\Test exactly where it was
  B) New location       — user picks a destination; structure is recreated there

SKIPPED FILES REPORT:
  Any file that fails the size or extension gate is collected and returned so
  the GUI can show the user a clear "could not restore" warning list.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import os
import json
import hashlib
import tempfile
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.utils import get_app_data_dir
from core.encryption_manager import crypto_manager


# ── Constants ─────────────────────────────────────────────────────────────────

_SUBFOLDER_NAME = "folder_backup"          # subfolder inside FMSecure_{MID}/
_MANIFEST_NAME  = "folder_manifest.json"   # per-watched-folder manifest


# ── Helpers ───────────────────────────────────────────────────────────────────

def _folder_bucket_name(watch_root: str) -> str:
    """
    Stable, human-readable bucket name for a watched folder.
    e.g.  D:/TEST  →  TEST_3a7f1c
    Keeps the last component readable for the admin console while the hash
    suffix prevents collisions between identically named folders on different
    drives.
    """
    base   = os.path.basename(watch_root.rstrip("/\\")) or "root"
    suffix = hashlib.sha256(watch_root.encode()).hexdigest()[:6]
    return f"{base}_{suffix}"


def _file_enc_name(original_path: str) -> str:
    """Opaque, stable filename for the encrypted blob in Drive."""
    return hashlib.sha256(original_path.encode()).hexdigest() + ".enc"


def _is_allowed(filepath: str, allowed_exts: list, max_size_mb: float) -> tuple:
    """
    Returns (True, "") if the file passes both gates, or (False, reason).
    """
    _, ext = os.path.splitext(filepath)
    if ext.lower() not in allowed_exts:
        return False, f"extension '{ext}' not in allowlist"
    try:
        size_mb = os.path.getsize(filepath) / (1024 * 1024)
        if size_mb > max_size_mb:
            return False, f"too large ({size_mb:.1f} MB > {max_size_mb} MB limit)"
    except OSError as e:
        return False, f"could not read size: {e}"
    return True, ""


# ── Core class ────────────────────────────────────────────────────────────────

class FolderStructureVault:
    """
    Backs up and restores the full directory tree of monitored folders.
    PRO-only feature — all public methods silently return early for free users.
    """

    # ── Backup ────────────────────────────────────────────────────────────────

    def backup_folder_structure(
        self,
        watch_root: str,
        progress_cb=None,
    ) -> dict:
        """
        Walk *watch_root*, encrypt each allowed file, upload to Drive.

        progress_cb(uploaded, total, filename) — optional live UI callback.

        Returns:
        {
            "uploaded":  int,
            "skipped":   [ {"path": str, "reason": str}, ... ],
            "failed":    [ {"path": str, "error": str}, ... ],
            "errors":    [ str, ... ],
            "bucket":    str,   # Drive subfolder name
        }
        """
        result = {"uploaded": 0, "skipped": [], "failed": [], "errors": [], "bucket": ""}

        # ── PRO gate ──────────────────────────────────────────────────────────
        if not self._is_pro():
            result["errors"].append("PRO licence required for Folder Structure Backup.")
            return result

        # ── Cloud online? ─────────────────────────────────────────────────────
        from core.cloud_sync import cloud_sync
        if not cloud_sync.is_active:
            result["errors"].append("Google Drive is offline.")
            return result

        if not os.path.isdir(watch_root):
            result["errors"].append(f"Folder does not exist: {watch_root}")
            return result

        # ── Allowed-ext + size config ─────────────────────────────────────────
        allowed_exts, max_size_mb = self._get_vault_config()

        # ── Get/create Drive bucket folder ────────────────────────────────────
        machine_id  = self._get_machine_id()
        bucket_name = _folder_bucket_name(watch_root)
        result["bucket"] = bucket_name

        bucket_folder_id = self._get_or_create_bucket(
            cloud_sync, machine_id, bucket_name)
        if not bucket_folder_id:
            result["errors"].append("Could not create cloud bucket folder.")
            return result

        # ── Walk the tree ─────────────────────────────────────────────────────
        all_files = []
        for dirpath, _dirs, filenames in os.walk(watch_root):
            for fname in filenames:
                full_path = os.path.join(dirpath, fname)
                rel_path  = os.path.relpath(full_path, watch_root)
                all_files.append((full_path, rel_path))

        total    = len(all_files)
        uploaded = 0
        manifest = {
            "watch_root":    watch_root,
            "bucket":        bucket_name,
            "created_at":    datetime.utcnow().isoformat() + "Z",
            "files":         {},   # enc_name → rel_path
            "skipped":       [],
        }

        # ── Encrypt + upload each file ────────────────────────────────────────
        for full_path, rel_path in all_files:
            fname = os.path.basename(full_path)

            # Gate check
            ok, reason = _is_allowed(full_path, allowed_exts, max_size_mb)
            if not ok:
                manifest["skipped"].append({"path": rel_path, "reason": reason})
                result["skipped"].append({"path": rel_path, "reason": reason})
                if progress_cb:
                    try:
                        progress_cb(uploaded, total, f"[SKIP] {fname}")
                    except Exception:
                        pass
                continue

            # Encrypt to temp file
            try:
                with open(full_path, "rb") as fh:
                    raw = fh.read()
                encrypted = crypto_manager.fernet.encrypt(raw)

                enc_name  = _file_enc_name(full_path)
                tmp_path  = os.path.join(tempfile.gettempdir(), enc_name)
                with open(tmp_path, "wb") as fh:
                    fh.write(encrypted)

                # Upload
                ok_upload = cloud_sync._upload_one_file(
                    tmp_path, bucket_folder_id, remote_name=enc_name)

                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

                if ok_upload:
                    manifest["files"][enc_name] = rel_path
                    uploaded += 1
                else:
                    result["failed"].append(
                        {"path": rel_path, "error": "Drive upload returned False"})

            except Exception as exc:
                result["failed"].append({"path": rel_path, "error": str(exc)})

            if progress_cb:
                try:
                    progress_cb(uploaded, total, fname)
                except Exception:
                    pass

        # ── Upload manifest ───────────────────────────────────────────────────
        try:
            manifest_tmp = os.path.join(
                tempfile.gettempdir(), f"manifest_{bucket_name}.json")
            with open(manifest_tmp, "w", encoding="utf-8") as fh:
                json.dump(manifest, fh, indent=2)
            cloud_sync._upload_one_file(
                manifest_tmp, bucket_folder_id, remote_name=_MANIFEST_NAME)
            try:
                os.remove(manifest_tmp)
            except Exception:
                pass
        except Exception as exc:
            result["errors"].append(f"Manifest upload failed: {exc}")

        result["uploaded"] = uploaded
        print(f"[FSV] Backup done — {uploaded}/{total} files uploaded "
              f"({len(result['skipped'])} skipped, {len(result['failed'])} failed).")
        return result

    # ── Restore ───────────────────────────────────────────────────────────────

    def list_available_backups(self) -> list:
        """
        Return a list of dicts describing every backed-up folder found in Drive.
        Each dict:  { bucket_name, watch_root, created_at, file_count, skipped_count }
        """
        if not self._is_pro():
            return []

        from core.cloud_sync import cloud_sync
        if not cloud_sync.is_active:
            return []

        machine_id = self._get_machine_id()
        results    = []

        try:
            # Get machine root, then list folder_backup/ children
            root = cloud_sync._get_machine_root(machine_id)
            if not root:
                return []

            fb_folder = cloud_sync._get_or_create_folder(
                _SUBFOLDER_NAME, root)
            if not fb_folder:
                return []

            buckets = cloud_sync._list_folder(fb_folder)
            for bucket in buckets:
                manifest = self._download_manifest(
                    cloud_sync, bucket["id"])
                if manifest:
                    results.append({
                        "bucket_id":    bucket["id"],
                        "bucket_name":  bucket["name"],
                        "watch_root":   manifest.get("watch_root", "?"),
                        "created_at":   manifest.get("created_at", "?"),
                        "file_count":   len(manifest.get("files", {})),
                        "skipped_count":len(manifest.get("skipped", [])),
                        "manifest":     manifest,
                    })
        except Exception as exc:
            print(f"[FSV] list_available_backups error: {exc}")

        return results

    def restore_folder_structure(
        self,
        bucket_id:   str,
        manifest:    dict,
        destination: str,        # "" means original location
        progress_cb=None,
    ) -> dict:
        """
        Restore all files from a Drive bucket to *destination*.

        If destination == "" the original paths from the manifest are used.

        Returns:
        {
            "restored":  int,
            "skipped":   [ {"path": str, "reason": str} ],
            "failed":    [ {"path": str, "error": str}  ],
            "errors":    [ str ],
        }
        """
        result = {"restored": 0, "skipped": [], "failed": [], "errors": []}

        if not self._is_pro():
            result["errors"].append("PRO licence required.")
            return result

        from core.cloud_sync import cloud_sync
        if not cloud_sync.is_active:
            result["errors"].append("Google Drive is offline.")
            return result

        files_map  = manifest.get("files", {})   # enc_name → rel_path
        watch_root = manifest.get("watch_root", "")
        total      = len(files_map)
        restored   = 0

        # Include skipped files in report immediately so user sees full picture
        for entry in manifest.get("skipped", []):
            result["skipped"].append(entry)

        # List files inside the bucket folder on Drive
        try:
            drive_files = cloud_sync._list_folder(bucket_id)
            drive_map   = {f["name"]: f["id"] for f in drive_files}
        except Exception as exc:
            result["errors"].append(f"Could not list Drive bucket: {exc}")
            return result

        for enc_name, rel_path in files_map.items():
            # Determine output path
            if destination:
                out_path = os.path.join(destination, rel_path)
            else:
                if watch_root:
                    out_path = os.path.join(watch_root, rel_path)
                else:
                    result["failed"].append(
                        {"path": rel_path,
                         "error": "No original path and no destination given."})
                    continue

            fname = os.path.basename(rel_path)

            if enc_name not in drive_map:
                result["failed"].append(
                    {"path": rel_path, "error": "File not found in Drive bucket."})
                if progress_cb:
                    try:
                        progress_cb(restored, total, f"[MISSING] {fname}")
                    except Exception:
                        pass
                continue

            # Download to temp
            try:
                tmp_enc = os.path.join(
                    tempfile.gettempdir(), f"fmr_{enc_name}")
                ok = cloud_sync._download_one_file(drive_map[enc_name], tmp_enc)
                if not ok:
                    result["failed"].append(
                        {"path": rel_path, "error": "Drive download failed."})
                    continue

                # Decrypt
                with open(tmp_enc, "rb") as fh:
                    encrypted = fh.read()
                try:
                    os.remove(tmp_enc)
                except Exception:
                    pass

                raw = crypto_manager.fernet.decrypt(encrypted)

                # Write to destination (create parent dirs)
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, "wb") as fh:
                    fh.write(raw)

                restored += 1

            except Exception as exc:
                result["failed"].append({"path": rel_path, "error": str(exc)})

            if progress_cb:
                try:
                    progress_cb(restored, total, fname)
                except Exception:
                    pass

        result["restored"] = restored
        print(f"[FSV] Restore done — {restored}/{total} files restored, "
              f"{len(result['skipped'])} skipped, {len(result['failed'])} failed.")
        return result

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _is_pro(self) -> bool:
        try:
            from core.integrity_core import CONFIG
            return bool(CONFIG.get("is_pro_user", False))
        except Exception:
            return False

    def _get_machine_id(self) -> str:
        try:
            from core.encryption_manager import crypto_manager as cm
            return cm.get_machine_id()
        except Exception:
            import platform
            hw = f"{platform.node()}-{platform.machine()}"
            return "FM-" + hashlib.sha256(hw.encode()).hexdigest()[:24].upper()

    def _get_vault_config(self) -> tuple:
        """Return (allowed_exts list, max_size_mb float)."""
        try:
            from core.integrity_core import CONFIG
            exts     = CONFIG.get("vault_allowed_exts",
                                  [".txt", ".json", ".py", ".html",
                                   ".js", ".css", ".php", ".ini",
                                   ".conf", ".jsx"])
            max_mb   = float(CONFIG.get("vault_max_size_mb", 10))
            return exts, max_mb
        except Exception:
            return [".txt", ".json", ".py", ".html",
                    ".js", ".css", ".php", ".ini", ".conf", ".jsx"], 10.0

    def _get_or_create_bucket(
        self, cloud_sync, machine_id: str, bucket_name: str
    ) -> str | None:
        """
        Return the Drive folder-ID for
          FMSecure_{MID}/folder_backup/{bucket_name}/
        creating folders along the way if needed.
        """
        root = cloud_sync._get_machine_root(machine_id)
        if not root:
            return None
        fb = cloud_sync._get_or_create_folder(_SUBFOLDER_NAME, root)
        if not fb:
            return None
        return cloud_sync._get_or_create_folder(bucket_name, fb)

    def _download_manifest(self, cloud_sync, bucket_folder_id: str) -> dict | None:
        """Download and parse the manifest JSON from a bucket folder."""
        try:
            items = cloud_sync._list_folder(bucket_folder_id)
            for item in items:
                if item["name"] == _MANIFEST_NAME:
                    tmp = os.path.join(
                        tempfile.gettempdir(), f"fmm_{bucket_folder_id}.json")
                    ok = cloud_sync._download_one_file(item["id"], tmp)
                    if ok:
                        with open(tmp, "r", encoding="utf-8") as fh:
                            data = json.load(fh)
                        try:
                            os.remove(tmp)
                        except Exception:
                            pass
                        return data
        except Exception as exc:
            print(f"[FSV] manifest download error: {exc}")
        return None


# ── Global singleton ───────────────────────────────────────────────────────────
folder_vault = FolderStructureVault()