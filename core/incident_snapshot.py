#!/usr/bin/env python3
"""
incident_snapshot.py
Forensic Incident Capture Engine — FMSecure EDR

Industry-standard design:
  - Every snapshot is AES-encrypted using the installation key (crypto_manager)
  - Readable ONLY through FMSecure — not by file explorer or text editor
  - Stored in AppData/FMSecure/forensics/ (script) or AppData/Local/SecureFIM/forensics/ (EXE)
  - A plaintext index file (forensics_index.json) tracks metadata for the GUI viewer
  - The snapshot ID is included in the alert email so the admin knows which local file to open
  - No binary attachment in email (avoids AV scanners and size limits)
"""

import os
import json
import time
import hashlib
import traceback
from datetime import datetime

from core.utils import get_app_data_dir
from core.encryption_manager import crypto_manager

# ── Paths ─────────────────────────────────────────────────────────────────────
APP_DATA      = get_app_data_dir()
FORENSICS_DIR = os.path.join(APP_DATA, "forensics")
INDEX_FILE    = os.path.join(FORENSICS_DIR, "forensics_index.json")
LOG_DIR       = os.path.join(APP_DATA, "logs")
LOG_FILE      = os.path.join(LOG_DIR, "integrity_log.dat")


def _ensure_dirs():
    """Create forensics directory silently if it does not exist."""
    os.makedirs(FORENSICS_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)


def _hide_dir_windows(path):
    """Mark a directory as hidden on Windows (silently ignored on other OS)."""
    try:
        import ctypes
        ctypes.windll.kernel32.SetFileAttributesW(path, 2)
    except Exception:
        pass


# ── Index management ──────────────────────────────────────────────────────────

def _load_index():
    """Load the plaintext index of all snapshots."""
    if not os.path.exists(INDEX_FILE):
        return []
    try:
        with open(INDEX_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _save_index(entries):
    """Persist the index. Kept as plaintext JSON — it only contains metadata, not evidence."""
    try:
        with open(INDEX_FILE, "w", encoding="utf-8") as f:
            json.dump(entries, f, indent=2)
    except Exception as e:
        print(f"[FORENSICS] Could not update index: {e}")


def _register_snapshot(snapshot_id, filename, event_type, severity, affected_count):
    """Add a new entry to the forensics index."""
    entries = _load_index()
    entries.insert(0, {
        "id":             snapshot_id,
        "filename":       filename,
        "event_type":     event_type,
        "severity":       severity,
        "affected_files": affected_count,
        "timestamp":      datetime.now().isoformat(),
        "timestamp_pretty": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })
    # Keep only the last 100 entries so the index stays small
    _save_index(entries[:100])


# ── Data collectors ───────────────────────────────────────────────────────────

def _collect_system_state():
    """Lightweight system snapshot — disk, process, config summary."""
    state = {}

    # Disk usage
    try:
        import shutil
        usage = shutil.disk_usage(APP_DATA)
        state["disk"] = {
            "total_gb": round(usage.total / 1024**3, 2),
            "used_gb":  round(usage.used  / 1024**3, 2),
            "free_gb":  round(usage.free  / 1024**3, 2),
        }
    except Exception:
        state["disk"] = {}

    # Process info
    try:
        import psutil, os as _os
        p = psutil.Process(_os.getpid())
        state["process"] = {
            "pid":       p.pid,
            "name":      p.name(),
            "memory_mb": round(p.memory_info().rss / 1024**2, 1),
            "cpu_pct":   p.cpu_percent(interval=0.1),
            "status":    p.status(),
            "started":   datetime.fromtimestamp(p.create_time()).isoformat(),
        }
    except ImportError:
        state["process"] = {"note": "psutil not installed"}
    except Exception as e:
        state["process"] = {"error": str(e)}

    # Config summary (no secrets)
    try:
        from core.integrity_core import CONFIG
        state["config"] = {
            "watch_folders":        CONFIG.get("watch_folders", []),
            "killswitch_enabled":   CONFIG.get("ransomware_killswitch", False),
            "active_defense":       CONFIG.get("active_defense", False),
            "verify_interval":      CONFIG.get("verify_interval", "N/A"),
        }
    except Exception:
        state["config"] = {}

    # Safe mode status
    try:
        from core import safe_mode
        state["safe_mode_active"] = safe_mode.is_safe_mode_enabled()
    except Exception:
        state["safe_mode_active"] = False

    return state


def _collect_critical_hashes():
    """SHA-256 (first 16 chars) of critical internal files."""
    targets = {
        "integrity_log":    LOG_FILE,
        "hash_records":     os.path.join(LOG_DIR, "hash_records.dat"),
        "severity_counters":os.path.join(LOG_DIR, "severity_counters.json"),
    }
    result = {}
    for label, path in targets.items():
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    result[label] = hashlib.sha256(f.read()).hexdigest()[:16]
            except Exception as e:
                result[label] = f"error: {e}"
        else:
            result[label] = "not found"
    return result


def _collect_recent_log_lines(count=15):
    """
    Return the last `count` log lines.
    Decrypts each line using crypto_manager — same as the GUI audit viewer.
    Falls back to raw lines if decryption fails.
    """
    lines = []
    if not os.path.exists(LOG_FILE):
        return ["Log file not found."]
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            raw_lines = f.readlines()
        recent = raw_lines[-count:] if len(raw_lines) > count else raw_lines
        for raw in recent:
            raw = raw.strip()
            if not raw:
                continue
            try:
                lines.append(crypto_manager.decrypt_string(raw))
            except Exception:
                lines.append(raw)
    except Exception as e:
        lines.append(f"Error reading log: {e}")
    return lines


# ── Main public API ───────────────────────────────────────────────────────────

def generate_incident_snapshot(event_type, severity, message,
                                affected_files=None, additional_data=None):
    """
    Generate, encrypt, and store a forensic incident snapshot.

    Parameters
    ----------
    event_type      : str   e.g. "RANSOMWARE_BURST", "HONEYPOT_BREACH"
    severity        : str   "CRITICAL" | "HIGH" | "MEDIUM" | "INFO"
    message         : str   Human-readable description of the event
    affected_files  : list  Paths of files involved in the incident
    additional_data : dict  Any extra key-value pairs to include

    Returns
    -------
    dict with keys:
        "snapshot_id"   — short hex ID (for email reference)
        "filepath"      — full path to the encrypted .dat file
        "email_summary" — pre-formatted plain-text block for the alert email
    Returns None on failure.
    """
    _ensure_dirs()
    _hide_dir_windows(FORENSICS_DIR)

    try:
        # ── Generate identifiers ───────────────────────────────────────────
        now          = datetime.now()
        snapshot_id  = hashlib.sha256(
            f"{event_type}{now.isoformat()}".encode()
        ).hexdigest()[:12].upper()

        ts_file      = now.strftime("%Y-%m-%d_%H-%M-%S")
        safe_event   = event_type.replace(":", "_").replace("/", "_").replace("\\", "_")
        filename     = f"forensic_{ts_file}_{safe_event}.dat"
        filepath     = os.path.join(FORENSICS_DIR, filename)

        affected_files  = affected_files or []
        additional_data = additional_data or {}

        # ── Collect evidence ───────────────────────────────────────────────
        payload = {
            "meta": {
                "snapshot_id":     snapshot_id,
                "fmsecure_version":"2.0",
                "generated_at":    now.isoformat(),
                "generated_at_pretty": now.strftime("%Y-%m-%d %H:%M:%S"),
            },
            "incident": {
                "event_type":    event_type,
                "severity":      severity,
                "message":       message,
                "affected_files":affected_files,
            },
            "system_state":    _collect_system_state(),
            "critical_hashes": _collect_critical_hashes(),
            "recent_log":      _collect_recent_log_lines(15),
            "extra":           additional_data,
        }

        # ── Encrypt and write ──────────────────────────────────────────────
        # crypto_manager.encrypt_json() writes the file and returns None.
        # We check for the file's existence afterward to confirm success.
        crypto_manager.encrypt_json(payload, filepath)

        if not os.path.exists(filepath):
            raise RuntimeError("encrypt_json ran but output file not found.")

        # ── Register in index ──────────────────────────────────────────────
        _register_snapshot(
            snapshot_id  = snapshot_id,
            filename     = filename,
            event_type   = event_type,
            severity     = severity,
            affected_count = len(affected_files),
        )

        # ── Build the email summary block ──────────────────────────────────
        file_lines = "\n".join(
            f"  • {os.path.basename(p)}" for p in affected_files[:20]
        )
        if len(affected_files) > 20:
            file_lines += f"\n  ... and {len(affected_files) - 20} more."

        email_summary = (
            f"FORENSIC SNAPSHOT ID: {snapshot_id}\n"
            f"{'='*48}\n"
            f"Severity  : {severity}\n"
            f"Event     : {event_type}\n"
            f"Time      : {now.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Files hit : {len(affected_files)}\n"
            f"\nCAUSALTY LIST\n{file_lines}\n"
            f"\nFORENSIC FILE\n"
            f"  Stored at : AppData\\FMSecure\\forensics\\{filename}\n"
            f"  Encrypted : AES-256 (viewable only inside FMSecure)\n"
            f"  Open via  : FMSecure → Vault / Cloud tab → Open Audit Log Vault\n"
            f"{'='*48}\n"
        )

        print(f"[FORENSICS] Snapshot {snapshot_id} saved → {filename}")

        return {
            "snapshot_id":   snapshot_id,
            "filepath":      filepath,
            "email_summary": email_summary,
        }

    except Exception as e:
        print(f"[FORENSICS] CAPTURE FAILED: {e}")
        traceback.print_exc()
        return None


def list_snapshots():
    """
    Return the forensics index (list of dicts, newest first).
    Used by the GUI viewer to populate the list.
    """
    return _load_index()


def read_snapshot(filename):
    """
    Decrypt and return the content of a single snapshot as a dict.
    Used by the GUI viewer to display details.
    Returns None if the file cannot be decrypted.
    """
    filepath = os.path.join(FORENSICS_DIR, filename)
    if not os.path.exists(filepath):
        return None
    try:
        return crypto_manager.decrypt_json(filepath)
    except Exception as e:
        print(f"[FORENSICS] Could not read snapshot {filename}: {e}")
        return None


def format_snapshot_for_display(data):
    """
    Convert a decrypted snapshot dict into a human-readable string
    for display inside the GUI viewer text box.
    """
    if not data:
        return "Could not decrypt or parse this snapshot."

    meta     = data.get("meta", {})
    incident = data.get("incident", {})
    state    = data.get("system_state", {})
    hashes   = data.get("critical_hashes", {})
    log      = data.get("recent_log", [])
    affected = incident.get("affected_files", [])

    lines = [
        "=" * 60,
        "  FMSECURE FORENSIC INCIDENT SNAPSHOT",
        "=" * 60,
        f"  Snapshot ID   : {meta.get('snapshot_id', 'N/A')}",
        f"  Generated at  : {meta.get('generated_at_pretty', 'N/A')}",
        f"  FMSecure ver  : {meta.get('fmsecure_version', 'N/A')}",
        "",
        "[ INCIDENT ]",
        f"  Severity      : {incident.get('severity', 'N/A')}",
        f"  Event type    : {incident.get('event_type', 'N/A')}",
        f"  Message       : {incident.get('message', 'N/A')}",
        "",
        f"[ AFFECTED FILES ({len(affected)}) ]",
    ]

    for p in affected:
        lines.append(f"  • {p}")
    if not affected:
        lines.append("  (none recorded)")

    # Config
    cfg = state.get("config", {})
    if cfg:
        lines += [
            "",
            "[ SYSTEM CONFIG AT TIME OF INCIDENT ]",
            f"  Watch folders      : {', '.join(cfg.get('watch_folders', []))}",
            f"  Killswitch enabled : {cfg.get('killswitch_enabled', 'N/A')}",
            f"  Active defense     : {cfg.get('active_defense', 'N/A')}",
            f"  Safe mode active   : {state.get('safe_mode_active', 'N/A')}",
        ]

    # Disk
    disk = state.get("disk", {})
    if disk:
        lines += [
            "",
            "[ DISK STATE ]",
            f"  Total : {disk.get('total_gb', '?')} GB",
            f"  Used  : {disk.get('used_gb', '?')} GB",
            f"  Free  : {disk.get('free_gb', '?')} GB",
        ]

    # Process
    proc = state.get("process", {})
    if proc and "pid" in proc:
        lines += [
            "",
            "[ PROCESS STATE ]",
            f"  PID        : {proc.get('pid')}",
            f"  Memory     : {proc.get('memory_mb')} MB",
            f"  CPU        : {proc.get('cpu_pct')}%",
            f"  Status     : {proc.get('status')}",
            f"  Started at : {proc.get('started')}",
        ]

    # Hashes
    lines += [
        "",
        "[ CRITICAL FILE HASHES (SHA-256, first 16 chars) ]",
    ]
    for label, val in hashes.items():
        lines.append(f"  {label:<22} : {val}")

    # Recent log
    lines += [
        "",
        f"[ LAST {len(log)} LOG ENTRIES ]",
    ]
    for entry in log:
        lines.append(f"  {entry}")

    lines += [
        "",
        "=" * 60,
        "  END OF FORENSIC REPORT",
        "  Decrypted by FMSecure — do not share this output.",
        "=" * 60,
    ]

    return "\n".join(lines)