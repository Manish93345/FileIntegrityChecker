"""
cloud_backup_scheduler.py — FMSecure v2.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Automatic background cloud backup for PRO users.

Industry pattern: periodic incremental backup with a dirty-flag so we
don't hammer the Drive API on every heartbeat.

Schedule:
  • Logs + forensics → every 15 minutes if any new events occurred
  • Full AppData     → every 6 hours
  • Keys             → immediately after PRO activation, then every 24h

Usage (call from integrity_gui.py after the GUI is built):
    from core.cloud_backup_scheduler import start_auto_backup
    start_auto_backup(username=self.username)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import threading
import time
import os

_scheduler_started = False
_scheduler_lock    = threading.Lock()

# Intervals in seconds
_LOG_BACKUP_INTERVAL     = 15 * 60   # 15 minutes
_APPDATA_BACKUP_INTERVAL = 6 * 3600  # 6 hours
_KEY_BACKUP_INTERVAL     = 24 * 3600 # 24 hours


def start_auto_backup(username: str = ""):
    """
    Start the background auto-backup thread.
    Safe to call multiple times — only one thread is ever running.
    """
    global _scheduler_started
    with _scheduler_lock:
        if _scheduler_started:
            return
        _scheduler_started = True

    t = threading.Thread(
        target=_scheduler_loop,
        args=(username,),
        daemon=True,
        name="FMSecure-CloudBackup"
    )
    t.start()
    print("[BACKUP] Auto-backup scheduler started.")


def _is_pro(username: str) -> bool:
    try:
        from core.auth_manager import auth
        from core.subscription_manager import subscription_manager
        tier = auth.get_user_tier(username)
        return subscription_manager.is_pro(tier)
    except Exception:
        return False


def _get_machine_id() -> str:
    try:
        from core.encryption_manager import crypto_manager
        return crypto_manager.get_machine_id()
    except Exception:
        return "UNKNOWN"


def _get_log_mtime() -> float:
    """Return the modification time of the integrity log — used as dirty flag."""
    try:
        from core.utils import get_app_data_dir
        log_path = os.path.join(get_app_data_dir(), "logs", "integrity_log.dat")
        return os.path.getmtime(log_path) if os.path.exists(log_path) else 0.0
    except Exception:
        return 0.0


def _scheduler_loop(username: str):
    last_log_backup     = 0.0
    last_appdata_backup = 0.0
    last_key_backup     = 0.0
    last_log_mtime      = 0.0

    # Wait for the app to finish starting up
    time.sleep(30)

    while True:
        try:
            now = time.time()

            if not _is_pro(username):
                time.sleep(60)
                continue

            from core.cloud_sync import cloud_sync
            if not cloud_sync.is_active:
                time.sleep(60)
                continue

            # --- ADD THIS BLOCK ---
            from core.integrity_core import CONFIG
            admin_email = CONFIG.get("admin_email", "")
            if not admin_email or admin_email == "UnknownUser":
                # Don't backup if the config is corrupt or user isn't logged in
                time.sleep(60)
                continue
                # ----------------------

            machine_id = _get_machine_id()

            # ── Logs + forensics (only if log file changed) ───────────────
            current_mtime = _get_log_mtime()
            if (now - last_log_backup > _LOG_BACKUP_INTERVAL
                    and current_mtime != last_log_mtime):
                print("[BACKUP] Auto-backup: logs + forensics…")
                result = cloud_sync.backup_logs_and_forensics(machine_id)
                print(f"[BACKUP] Logs: {result['uploaded']} uploaded, "
                      f"{result['failed']} failed.")
                last_log_backup = now
                last_log_mtime  = current_mtime

            # ── Full AppData ───────────────────────────────────────────────
            if now - last_appdata_backup > _APPDATA_BACKUP_INTERVAL:
                print("[BACKUP] Auto-backup: full AppData…")
                result = cloud_sync.backup_full_appdata(machine_id)
                print(f"[BACKUP] AppData: {result['uploaded']} uploaded.")
                last_appdata_backup = now

            # ── Encryption keys ────────────────────────────────────────────
            if now - last_key_backup > _KEY_BACKUP_INTERVAL:
                print("[BACKUP] Auto-backup: encryption keys…")
                from core.encryption_manager import crypto_manager
                ok, msg = crypto_manager.force_key_backup()
                print(f"[BACKUP] Keys: {msg}")
                last_key_backup = now

        except Exception as e:
            print(f"[BACKUP] Scheduler error (non-critical): {e}")

        time.sleep(60)   # check every minute, but actions are rate-limited above