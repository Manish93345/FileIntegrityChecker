"""
retention_manager.py — FMSecure v2.6
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

DATA RETENTION & GDPR COMPLIANCE ENGINE

Implements:
  • Configurable log retention (default 90 days)
  • Automatic nightly cleanup of telemetry.jsonl, rotated logs, forensics
  • GDPR Article 17 (right to erasure) — wipe all personal data on request
  • Retention report for compliance audits

Industry reference:
  CrowdStrike default: 90-day retention for endpoint telemetry
  SentinelOne default: 14 days (free), 365 days (enterprise)
  GDPR minimum: no hard limit but "no longer than necessary"
  PCI-DSS Req 10.7: at least 12 months, 3 months immediately available
"""

import os
import json
import time
import shutil
import threading
import glob
from datetime import datetime, timedelta
from typing import Dict, List, Optional


# ── Default retention periods (days) ─────────────────────────────────────────
DEFAULT_RETENTION = {
    "telemetry_days":   90,    # telemetry.jsonl and rotated copies
    "forensics_days":   180,   # encrypted forensic snapshots (longer — legal value)
    "log_history_days": 365,   # archived session logs in config/history/
    "quarantine_days":  30,    # quarantined malware files
}


class RetentionManager:
    """
    Runs as a background daemon thread.
    Wakes once per day and deletes files older than the configured retention period.
    Never touches: integrity_log.dat (active log), hash_records.dat (active baseline),
    users.dat (account data — separate GDPR flow).
    """

    def __init__(self):
        self._running  = False
        self._thread:  Optional[threading.Thread] = None
        self._config   = dict(DEFAULT_RETENTION)

    def configure(self, config: dict):
        """
        Load retention settings from CONFIG.
        Called after load_config() so customer settings are respected.
        """
        self._config["telemetry_days"]   = int(config.get("retention_telemetry_days",  90))
        self._config["forensics_days"]   = int(config.get("retention_forensics_days",  180))
        self._config["log_history_days"] = int(config.get("retention_log_history_days", 365))
        self._config["quarantine_days"]  = int(config.get("retention_quarantine_days",  30))

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread  = threading.Thread(
            target=self._daily_loop,
            daemon=True,
            name="FMSecure-RetentionManager"
        )
        self._thread.start()
        print("[RETENTION] Manager started.")

    def stop(self):
        self._running = False

    # ── Main cleanup loop ─────────────────────────────────────────────────────

    def _daily_loop(self):
        """Run cleanup once at startup, then every 24 hours."""
        while self._running:
            try:
                self._run_cleanup()
            except Exception as e:
                print(f"[RETENTION] Cleanup error (non-critical): {e}")
            # Sleep 24 hours, checking every minute if stop() was called
            for _ in range(24 * 60):
                if not self._running:
                    return
                time.sleep(60)

    def _run_cleanup(self):
        """Execute all cleanup passes."""
        report = self.cleanup_now()
        total  = sum(report.values())
        if total > 0:
            print(f"[RETENTION] Cleanup complete: {report}")
            try:
                from core.integrity_core import append_log_line
                append_log_line(
                    f"Data retention cleanup: deleted {total} files "
                    f"(telemetry={report['telemetry']}, "
                    f"forensics={report['forensics']}, "
                    f"history={report['history']})",
                    event_type="RETENTION_CLEANUP",
                    severity="INFO"
                )
            except Exception:
                pass

    # ── Public API ────────────────────────────────────────────────────────────

    def cleanup_now(self) -> Dict[str, int]:
        """
        Run all retention passes immediately.
        Returns count of files deleted per category.
        Safe to call manually from GUI or tests.
        """
        from core.utils import get_app_data_dir
        app_data = get_app_data_dir()

        deleted = {
            "telemetry": 0,
            "forensics": 0,
            "history":   0,
            "quarantine":0,
        }

        # 1. Rotated telemetry logs (telemetry_YYYYMMDDHHMMSS.jsonl)
        logs_dir = os.path.join(app_data, "logs")
        deleted["telemetry"] += self._delete_old_files(
            folder=logs_dir,
            pattern="telemetry_*.jsonl",
            max_age_days=self._config["telemetry_days"]
        )

        # 2. Trim active telemetry.jsonl to remove lines older than retention period
        telemetry_path = os.path.join(logs_dir, "telemetry.jsonl")
        deleted["telemetry"] += self._trim_jsonl(
            path=telemetry_path,
            max_age_days=self._config["telemetry_days"]
        )

        # 3. Forensic snapshots
        forensics_dir = os.path.join(app_data, "forensics")
        deleted["forensics"] += self._delete_old_files(
            folder=forensics_dir,
            pattern="forensic_*.dat",
            max_age_days=self._config["forensics_days"]
        )
        # Also trim forensics index to remove deleted entries
        self._trim_forensics_index(forensics_dir)

        # 4. Session history archives
        history_dir = os.path.join(app_data, "config", "history")
        deleted["history"] += self._delete_old_folders(
            folder=history_dir,
            max_age_days=self._config["log_history_days"]
        )

        # 5. Quarantine folder
        quarantine_dir = os.path.join(app_data, "quarantine")
        deleted["quarantine"] += self._delete_old_files(
            folder=quarantine_dir,
            pattern="*.quarantine",
            max_age_days=self._config["quarantine_days"]
        )

        return deleted

    def get_retention_report(self) -> Dict:
        """
        Return a report of current data sizes and retention settings.
        Used by GUI and C2 dashboard for compliance display.
        """
        from core.utils import get_app_data_dir
        app_data = get_app_data_dir()

        def _dir_size_mb(path):
            total = 0
            if not os.path.isdir(path):
                return 0.0
            for f in os.listdir(path):
                try:
                    total += os.path.getsize(os.path.join(path, f))
                except OSError:
                    pass
            return round(total / (1024 * 1024), 2)

        def _file_count(path, pattern="*"):
            if not os.path.isdir(path):
                return 0
            return len(glob.glob(os.path.join(path, pattern)))

        logs_dir      = os.path.join(app_data, "logs")
        forensics_dir = os.path.join(app_data, "forensics")
        history_dir   = os.path.join(app_data, "config", "history")

        return {
            "settings": dict(self._config),
            "telemetry_size_mb":   _dir_size_mb(logs_dir),
            "forensics_count":     _file_count(forensics_dir, "forensic_*.dat"),
            "forensics_size_mb":   _dir_size_mb(forensics_dir),
            "history_sessions":    _file_count(history_dir),
            "history_size_mb":     _dir_size_mb(history_dir),
            "generated_at":        datetime.now().isoformat(),
        }

    def gdpr_erase_all(self) -> Dict[str, int]:
        """
        GDPR Article 17 — Right to Erasure.
        Deletes ALL log data, telemetry, and forensics for this installation.
        Does NOT delete: users.dat (account data — handled separately),
                         hash_records.dat (not personal data),
                         config.json (settings, not personal data).

        Returns count of files deleted.
        Call this when a tenant requests full data deletion.
        """
        from core.utils import get_app_data_dir
        app_data = get_app_data_dir()
        deleted  = 0

        targets = [
            (os.path.join(app_data, "logs"),      "integrity_log*.dat"),
            (os.path.join(app_data, "logs"),      "integrity_log*.sig"),
            (os.path.join(app_data, "logs"),      "telemetry*.jsonl"),
            (os.path.join(app_data, "logs"),      "severity_counters.json"),
            (os.path.join(app_data, "forensics"), "forensic_*.dat"),
            (os.path.join(app_data, "forensics"), "forensics_index.json"),
        ]

        for folder, pattern in targets:
            deleted += self._delete_old_files(
                folder=folder,
                pattern=pattern,
                max_age_days=0   # 0 = delete everything
            )

        # Wipe session history
        history_dir = os.path.join(app_data, "config", "history")
        if os.path.isdir(history_dir):
            try:
                shutil.rmtree(history_dir)
                deleted += 1
            except Exception:
                pass

        try:
            from core.integrity_core import append_log_line
            append_log_line(
                "GDPR Article 17: All personal data erased on request.",
                event_type="GDPR_ERASURE",
                severity="INFO"
            )
        except Exception:
            pass

        return {"deleted_files": deleted, "timestamp": datetime.now().isoformat()}

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _delete_old_files(self, folder: str, pattern: str,
                          max_age_days: int) -> int:
        """Delete files matching pattern that are older than max_age_days."""
        if not os.path.isdir(folder):
            return 0
        cutoff = time.time() - (max_age_days * 86400)
        deleted = 0
        for path in glob.glob(os.path.join(folder, pattern)):
            try:
                if os.path.getmtime(path) < cutoff:
                    os.remove(path)
                    deleted += 1
            except Exception:
                pass
        return deleted

    def _delete_old_folders(self, folder: str, max_age_days: int) -> int:
        """Delete subdirectories older than max_age_days."""
        if not os.path.isdir(folder):
            return 0
        cutoff  = time.time() - (max_age_days * 86400)
        deleted = 0
        for entry in os.scandir(folder):
            if entry.is_dir():
                try:
                    if entry.stat().st_mtime < cutoff:
                        shutil.rmtree(entry.path)
                        deleted += 1
                except Exception:
                    pass
        return deleted

    def _trim_jsonl(self, path: str, max_age_days: int) -> int:
        """
        Remove lines from a JSONL file that are older than max_age_days.
        Reads the @timestamp field from each JSON line.
        Rewrites the file atomically.
        Returns number of lines removed.
        """
        if not os.path.exists(path):
            return 0
        cutoff_dt = datetime.utcnow() - timedelta(days=max_age_days)
        kept      = []
        removed   = 0
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        ts  = obj.get("@timestamp", "")
                        # Parse ISO timestamp — drop anything older than cutoff
                        dt  = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                        if dt.replace(tzinfo=None) >= cutoff_dt:
                            kept.append(line)
                        else:
                            removed += 1
                    except Exception:
                        kept.append(line)   # keep unparseable lines

            if removed > 0:
                tmp = path + ".retention_tmp"
                with open(tmp, "w", encoding="utf-8") as fh:
                    fh.write("\n".join(kept))
                    if kept:
                        fh.write("\n")
                os.replace(tmp, path)

        except Exception as e:
            print(f"[RETENTION] JSONL trim error for {path}: {e}")

        return removed

    def _trim_forensics_index(self, forensics_dir: str):
        """Remove entries from forensics_index.json for files that no longer exist."""
        index_path = os.path.join(forensics_dir, "forensics_index.json")
        if not os.path.exists(index_path):
            return
        try:
            with open(index_path, "r", encoding="utf-8") as fh:
                entries = json.load(fh)
            kept = [
                e for e in entries
                if os.path.exists(os.path.join(forensics_dir, e.get("filename", "")))
            ]
            if len(kept) < len(entries):
                with open(index_path, "w", encoding="utf-8") as fh:
                    json.dump(kept, fh, indent=2)
        except Exception:
            pass


# ── Module-level singleton ────────────────────────────────────────────────────

_manager: Optional[RetentionManager] = None


def get_retention_manager() -> RetentionManager:
    global _manager
    if _manager is None:
        _manager = RetentionManager()
    return _manager


def start_retention_management(config: dict) -> None:
    """Called from FileIntegrityMonitor.start_monitoring()."""
    mgr = get_retention_manager()
    mgr.configure(config)
    mgr.start()


def stop_retention_management() -> None:
    """Called from FileIntegrityMonitor.stop_monitoring()."""
    get_retention_manager().stop()


def run_cleanup_now() -> Dict:
    """Manual trigger — wire to a GUI button later."""
    return get_retention_manager().cleanup_now()


def gdpr_erase() -> Dict:
    """GDPR Article 17 full erasure — wire to server API endpoint."""
    return get_retention_manager().gdpr_erase_all()


def get_retention_report() -> Dict:
    """For GUI / dashboard display."""
    return get_retention_manager().get_retention_report()