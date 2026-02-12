#!/usr/bin/env python3
"""
integrity_core.py
Core backend logic for Secure File Integrity Monitor
- All hashing, HMAC, monitoring, and verification logic
- No CLI-specific code
"""

import os
import json
import time
import hashlib
import hmac
import threading
import traceback
import shutil
from datetime import datetime

SEVERITY_COUNTER_FILE = os.path.join("logs", "severity_counters.json")

# Import security features (silent imports)
try:
    from security_imports import (
        AUTO_RESPONSE_AVAILABLE,
        trigger_auto_response,
        handle_tamper_event,
        SAFE_MODE_AVAILABLE,
        enable_safe_mode,
        is_safe_mode_enabled
    )
except ImportError:
    # If security_imports doesn't exist, use dummy functions
    AUTO_RESPONSE_AVAILABLE = False
    SAFE_MODE_AVAILABLE = False
    
    def trigger_auto_response(*args, **kwargs):
        return False
    
    def handle_tamper_event(*args, **kwargs):
        return False
    
    def enable_safe_mode(*args, **kwargs):
        return False
    
    def is_safe_mode_enabled():
        return False

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except Exception:
    print("Missing dependency: watchdog. Install with `pip install watchdog`.")
    raise

try:
    import requests
except Exception:
    requests = None  # webhook optional; code will continue without requests


# --- GLOBAL MEMORY COUNTERS (Prevents Race Conditions) ---
_COUNTER_LOCK = threading.Lock()
_SEVERITY_CACHE = {
    "CRITICAL": 0, 
    "HIGH": 0, 
    "MEDIUM": 0, 
    "INFO": 0
}

# Attempt to load existing counts from disk on startup
if os.path.exists(SEVERITY_COUNTER_FILE):
    try:
        with open(SEVERITY_COUNTER_FILE, "r", encoding="utf-8") as f:
            loaded = json.load(f)
            # Merge loaded data into cache safely
            for k, v in loaded.items():
                if k in _SEVERITY_CACHE:
                    _SEVERITY_CACHE[k] = int(v)
    except Exception:
        print("Warning: Could not load existing severity counters.")


# [In integrity_core.py - Add this Class after imports]

class SimpleLock:
    """A simple file-based lock to prevent race conditions"""
    def __init__(self, lock_file, timeout=2.0):
        self.lock_file = lock_file
        self.timeout = timeout

    def __enter__(self):
        start_time = time.time()
        # Wait while lock exists
        while os.path.exists(self.lock_file):
            if time.time() - start_time > self.timeout:
                # Lock is stale (crashed process?), break it
                print("⚠️ Breaking stale lock file")
                try:
                    os.remove(self.lock_file)
                except OSError:
                    pass
                break
            time.sleep(0.05)
        
        # Create lock
        try:
            with open(self.lock_file, 'w') as f:
                f.write(str(os.getpid()))
        except Exception:
            pass # Should not happen often if wait worked
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            if os.path.exists(self.lock_file):
                os.remove(self.lock_file)
        except OSError:
            pass


# ------------------ Severity Levels ------------------
SEVERITY_LEVELS = {
    "INFO": {"color": "🟢", "priority": 0, "gui_color": "#0dcaf0"},  # Blue/Cyan
    "MEDIUM": {"color": "🟡", "priority": 1, "gui_color": "#ffc107"},  # Yellow
    "HIGH": {"color": "🟠", "priority": 2, "gui_color": "#fd7e14"},  # Orange
    "CRITICAL": {"color": "🔴", "priority": 3, "gui_color": "#dc3545"},  # Red
}


# Event to severity mapping
EVENT_SEVERITY = {
    # File operations
    "CREATED": "INFO",
    "CREATED_ON_MODIFY": "INFO",
    "MODIFIED": "MEDIUM",
    "DELETED": "MEDIUM",
    "DELETED_UNTRACKED": "MEDIUM",
    
    # Security events
    "TAMPERED_RECORDS": "CRITICAL",
    "TAMPERED_LOGS": "CRITICAL",
    "LOG_INTEGRITY_FAIL": "CRITICAL",
    "INTEGRITY_FAIL": "CRITICAL",
    "SIGNATURE_MISMATCH": "CRITICAL",
    
    # Configuration changes
    "CONFIG_CHANGED": "HIGH",
    "SETTINGS_UPDATED": "HIGH",
    
    # Multiple/burst operations
    "MULTIPLE_DELETES": "HIGH",
    "BURST_OPERATION": "HIGH",
    
    # System events
    "MONITOR_STARTED": "INFO",
    "MONITOR_STOPPED": "INFO",
    "VERIFICATION_STARTED": "INFO",
    "VERIFICATION_COMPLETED": "INFO",
    "LOG_ROTATED": "INFO",
    "WEBHOOK_SENT": "INFO",
    "WEBHOOK_FAIL": "MEDIUM",
}


# --- IMPORT THE UTILITY ---
try:
    from core.utils import get_app_data_dir, get_base_path
except ImportError:
    # Fallback if running directly
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from core.utils import get_app_data_dir, get_base_path

# --- SETUP PATHS CORRECTLY ---
DATA_ROOT = get_app_data_dir()
log_dir = os.path.join(DATA_ROOT, "logs")

# 1. FORCE CREATE THE LOGS DIRECTORY
if not os.path.exists(log_dir):
    try:
        os.makedirs(log_dir)
        print(f"✅ Created log directory at: {log_dir}")
    except Exception as e:
        print(f"❌ Error creating log dir: {e}")

# ------------------ Defaults & Config ------------------
# Default configuration will be loaded from config.json
DEFAULT_CONFIG = {}

# 2. UPDATE ALL FILE PATHS TO USE 'log_dir'
HASH_RECORD_FILE = os.path.join(log_dir, "hash_records.json")
HASH_SIGNATURE_FILE = os.path.join(log_dir, "hash_records.sig")
LOG_FILE = os.path.join(log_dir, "integrity_log.txt")
LOG_SIG_FILE = os.path.join(log_dir, "integrity_log.sig")
REPORT_SUMMARY_FILE = os.path.join(log_dir, "report_summary.txt")
SEVERITY_COUNTER_FILE = os.path.join(log_dir, "severity_counters.json")

# in-memory config will be loaded on startup
CONFIG = dict(DEFAULT_CONFIG)

# Additional temp patterns to ignore (lowercase)
TEMP_PATTERNS = [".tmp", ".part", ".crdownload", ".ds_store", ".swp", ".bak", "~", ".~"]


def get_severity(event_type):
    """Get severity level for event type"""
    return EVENT_SEVERITY.get(event_type, "INFO")



# ------------------ Utilities ------------------
def now_iso():
    return datetime.now().isoformat(timespec='seconds')

def now_pretty():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def atomic_write_text(path, text):
    """Safely write text to a file"""
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
        if os.path.exists(path):
            os.remove(path)
        os.rename(tmp, path)
    except Exception as e:
        print(f"Error in atomic_write_text: {e}")
        # Fallback: direct write
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
        except Exception as e2:
            print(f"Fallback write also failed: {e2}")

def atomic_write_json(path, obj):
    """Safely write JSON to a file"""
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=4, sort_keys=True)
        if os.path.exists(path):
            os.remove(path)
        os.rename(tmp, path)
    except Exception as e:
        print(f"Error in atomic_write_json: {e}")

def load_config(path=None):
    global CONFIG
    
    # 1. Initialize with ROBUST DEFAULTS immediately
    # This ensures "hash_chunk_size" always exists, preventing crashes
    defaults = {
        "watch_folder": os.path.join(os.path.expanduser("~"), "Documents"),
        "verify_interval": 60,
        "webhook_url": None,
        "secret_key": "Lisacutie",
        "max_log_size_mb": 10,
        "max_log_backups": 5,
        "hash_algo": "sha256",
        "hash_chunk_size": 65536,
        "hash_retries": 3,
        "hash_retry_delay": 0.5,
        "ignore_filenames": ["hash_records.json", "integrity_log.txt", "integrity_log.sig", "hash_records.sig", "report_summary.txt"]
    }
    CONFIG.update(defaults)


    # 2. Determine Paths
    # External: Next to the EXE (Users can edit this)
    external_config = os.path.join(get_app_data_dir(), "config", "config.json")
    # Internal: Bundled inside EXE (Fallback)
    internal_config = os.path.join(get_base_path(), "config", "config.json")
    
    target_path = path or external_config
    
    # 3. Try to load External Config
    if os.path.exists(target_path):
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                user_config = json.load(f)
                CONFIG.update(user_config) # Merge user settings over defaults
                print(f"[CONFIG] Loaded from {target_path}")
                return True
        except Exception as e:
            print(f"[CONFIG] Error loading external {target_path}: {e}")

    # 4. Try to load Internal Config (if external missing)
    elif os.path.exists(internal_config):
        try:
            with open(internal_config, "r", encoding="utf-8") as f:
                user_config = json.load(f)
                CONFIG.update(user_config)
                print(f"[CONFIG] Loaded from bundled defaults")
                return True
        except Exception as e:
            print(f"[CONFIG] Error loading internal: {e}")
            
    # 5. Fallback
    print("[CONFIG] Using hardcoded defaults")
    return True

# ------------------ Logging & Log HMAC (per-line) ------------------
def append_log_line(message, event_type=None, severity=None):
    """Append log line and sign it"""
    try:
        os.makedirs(os.path.dirname(os.path.abspath(LOG_FILE)) or ".", exist_ok=True)
        
        if severity is None:
            if event_type:
                severity = get_severity(event_type)
            else:
                severity = "INFO"
        
        emoji = SEVERITY_LEVELS.get(severity, {}).get("color", "⚪")
        line = f"{now_pretty()} - [{emoji} {severity}] {message}"
        
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())
        
        # Consistent signing format
        sig_line = f"{line}|UNKNOWN|{severity}"
        append_log_signature(sig_line)
        
        update_severity_counter(severity)
        print(f"DEBUG: Logging - Severity: {severity}, Event: {event_type}")
        
    except Exception as e:
        print(f"Log Error: {e}")


def update_severity_counter(severity):
    """
    Update severity counters reliably using Memory Cache + Disk Persistence.
    This fixes the issue where counters reset to 0 during burst operations.
    """
    global _SEVERITY_CACHE
    
    # 1. Update Memory (Instant & Reliable)
    # We use a thread lock to ensure safe updates in memory
    with _COUNTER_LOCK:
        if severity in _SEVERITY_CACHE:
            _SEVERITY_CACHE[severity] += 1
        else:
            _SEVERITY_CACHE[severity] = 1
        
        # Create a copy to save to disk
        data_to_save = _SEVERITY_CACHE.copy()

    # 2. Persist to Disk (Best Effort)
    # Even if this fails or collides with GUI reading, memory remains correct
    try:
        counter_file = SEVERITY_COUNTER_FILE
        temp_file = counter_file + ".tmp"
        
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(data_to_save, f, indent=2)
        
        if os.path.exists(counter_file):
            try:
                os.remove(counter_file)
            except OSError:
                pass # If locked by GUI, we skip this write cycle; memory is still truth
        
        try:
            os.rename(temp_file, counter_file)
        except OSError:
            pass
            
    except Exception as e:
        print(f"Background save error (harmless): {e}")


def append_log_signature(line):
    """Compute HMAC of full line and append to signature file"""
    try:
        # ENSURE CONFIG IS LOADED
        if "secret_key" not in CONFIG: load_config()
            
        key = CONFIG.get("secret_key", "Lisacutie").encode("utf-8")
        h = getattr(hashlib, CONFIG.get("hash_algo", "sha256"))
        
        # Consistent UTF-8 encoding
        sig = hmac.new(key, line.encode("utf-8"), h).hexdigest()
        
        with open(LOG_SIG_FILE, "a", encoding="utf-8") as f:
            f.write(sig + "\n")
            f.flush()
            os.fsync(f.fileno())
    except Exception as e:
        print(f"Sig Write Error: {e}")

def rotate_logs_if_needed():
    """
    Rotate integrity_log.txt when it exceeds configured max size (MB).
    Also rotate the sig file accordingly and cleanup old backups.
    """
    max_mb = CONFIG["max_log_size_mb"]
    max_bytes = max_mb * 1024 * 1024
    if not os.path.exists(LOG_FILE):
        return
    try:
        size = os.path.getsize(LOG_FILE)
    except Exception:
        return
    if size <= max_bytes:
        return
    ts = datetime.now().strftime("%Y%m%d%H%M%S")
    base = os.path.splitext(LOG_FILE)[0]
    new_log = f"{base}_{ts}.log"
    os.replace(LOG_FILE, new_log)
    if os.path.exists(LOG_SIG_FILE):
        sig_new = f"{os.path.splitext(LOG_SIG_FILE)[0]}_{ts}.sig"
        os.replace(LOG_SIG_FILE, sig_new)
    # write rotation event
    append_log_line(f"LOG_ROTATED: {new_log}")
    cleanup_backups(base, CONFIG["max_log_backups"])

def cleanup_backups(base, keep):
    files = sorted([f for f in os.listdir(".") if f.startswith(base + "_")], reverse=True)
    for old in files[keep:]:
        try:
            os.remove(old)
        except Exception:
            pass

# ------------------ Hash records + HMAC ------------------
def generate_records_hmac(records_dict):
    raw = json.dumps(records_dict, sort_keys=True).encode("utf-8")
    key = CONFIG["secret_key"].encode("utf-8")
    h = getattr(hashlib, CONFIG["hash_algo"])
    return hmac.new(key, raw, h).hexdigest()

def save_hash_records(records):
    atomic_write_json(HASH_RECORD_FILE, records)
    sig = generate_records_hmac(records)
    atomic_write_text(HASH_SIGNATURE_FILE, sig)

def load_hash_records():
    if not os.path.exists(HASH_RECORD_FILE):
        atomic_write_json(HASH_RECORD_FILE, {})
        atomic_write_text(HASH_SIGNATURE_FILE, "")
        return {}
    try:
        with open(HASH_RECORD_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else dict(data)
    except json.JSONDecodeError:
        append_log_line("WARNING: hash_records.json corrupted or invalid JSON — resetting to {}")
        return {}

def load_hash_signature():
    if not os.path.exists(HASH_SIGNATURE_FILE):
        return ""
    try:
        with open(HASH_SIGNATURE_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return ""

def verify_records_signature_on_disk():
    records = load_hash_records()
    sig = load_hash_signature()
    if not sig:
        save_hash_records(records)
        append_log_line("INFO: No hash signature found; created new signature.", 
                       event_type="SIGNATURE_CREATED", severity="INFO")
        return True
    expected = generate_records_hmac(records)
    ok = hmac.compare_digest(expected, sig)
    if not ok:
        append_log_line("ALERT: hash_records.json signature mismatch (possible tampering)", 
                       event_type="TAMPERED_RECORDS", severity="CRITICAL")
        send_webhook_safe("INTEGRITY_FAIL", "hash_records.json HMAC mismatch", HASH_RECORD_FILE)
        if handle_tamper_event:
            handle_tamper_event("records", HASH_RECORD_FILE)
    return ok

# ------------------ Log signature verification ------------------
# [In integrity_core.py] Replace the verify_log_signatures function

def verify_log_signatures():
    """Verify logs - Strict & Robust"""
    if not os.path.exists(LOG_FILE): return True, "No log file"
    
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            log_lines = [l.rstrip("\n") for l in f.readlines() if l.strip()]
    except: return False, "Read fail"

    if not log_lines: return True, "Empty"

    sig_lines = []
    if os.path.exists(LOG_SIG_FILE):
        try:
            with open(LOG_SIG_FILE, "r", encoding="utf-8") as f:
                sig_lines = [s.rstrip("\n") for s in f.readlines() if s.strip()]
        except: return False, "Sig read fail"

    # AUTO HEAL (Crash/Sync)
    if len(log_lines) > len(sig_lines):
        missing = len(log_lines) - len(sig_lines)
        try:
            for line in log_lines[-missing:]:
                append_log_signature(f"{line}|UNKNOWN|INFO")
            print(f"DEBUG: Auto-healed {missing} signatures")
            return True, f"Auto-healed {missing}"
        except Exception as e: 
            print(f"❌ Auto-Heal Failed: {e}") # Print the error!
            return False, f"Heal failed: {e}"

    # TAMPER (Deletion)
    if len(log_lines) < len(sig_lines):
        if handle_tamper_event: handle_tamper_event("logs", LOG_FILE)
        return False, "Deletion Detected"

    # CONTENT VERIFICATION
    # Ensure config is loaded
    if "secret_key" not in CONFIG: load_config()
    
    key = CONFIG.get("secret_key", "Lisacutie").encode("utf-8")
    h_factory = getattr(hashlib, CONFIG.get("hash_algo", "sha256"))
    
    for i, (line, stored_sig) in enumerate(zip(log_lines, sig_lines)):
        # Strategy 1: Check Standard/Healed format (INFO)
        check1 = f"{line}|UNKNOWN|INFO"
        sig1 = hmac.new(key, check1.encode("utf-8"), h_factory).hexdigest()
        
        if stored_sig == sig1: continue

        # Strategy 2: Parse Severity from Text
        parsed_sev = "INFO"
        if "[🔴 CRITICAL]" in line: parsed_sev = "CRITICAL"
        elif "[🟠 HIGH]" in line: parsed_sev = "HIGH"
        elif "[🟡 MEDIUM]" in line: parsed_sev = "MEDIUM"
        
        check2 = f"{line}|UNKNOWN|{parsed_sev}"
        sig2 = hmac.new(key, check2.encode("utf-8"), h_factory).hexdigest()

        if stored_sig == sig2: continue

        # Strategy 3: The "None" Fallback
        check3 = f"{line}|UNKNOWN|None"
        sig3 = hmac.new(key, check3.encode("utf-8"), h_factory).hexdigest()
        if stored_sig == sig3: continue

        # FAIL
        print(f"\n[DEBUG] SIGNATURE MISMATCH AT LINE {i+1}")
        print(f"Content: {line}")
        print(f"Expected 1 (INFO): {sig1}")
        print(f"Found on Disk:   {stored_sig}")
        
        if handle_tamper_event: handle_tamper_event("signature", LOG_FILE)
        return False, f"Signature Mismatch at line {i+1}"

    return True, "Signatures OK"

# ------------------ Hashing (chunked + retry) ------------------
def is_ignored_filename(name):
    ln = name.lower()
    # first config-based ignore substrings
    for ig in CONFIG.get("ignore_filenames", []):
        if ig.lower() in ln:
            return True
    # then temp patterns
    for p in TEMP_PATTERNS:
        if p in ln:
            return True
    return False

def generate_file_hash(path):
    """
    Chunked hashing with retries for transient lock conditions.
    """
    # skip if filename matches ignore/temp patterns
    fn = os.path.basename(path)
    if is_ignored_filename(fn):
        return None
    chunk_size = CONFIG["hash_chunk_size"]
    retries = CONFIG["hash_retries"]
    delay = CONFIG["hash_retry_delay"]
    algo = getattr(hashlib, CONFIG["hash_algo"])
    for attempt in range(1, retries + 1):
        try:
            h = algo()
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.hexdigest()
        except (PermissionError, FileNotFoundError) as e:
            # transient lock or file disappeared — retry a few times
            if attempt < retries:
                time.sleep(delay)
                continue
            append_log_line(f"SKIP_HASH: {path} ({e})")
            return None
        except Exception as e:
            append_log_line(f"ERROR_HASH: {path} ({e})")
            return None

# ------------------ Webhook safe sender ------------------
def send_webhook_safe(event_type, message, file_path=None):
    url = CONFIG.get("webhook_url") or None
    if url is None:
        return
    if requests is None:
        append_log_line(f"ALERT_WEBHOOK_NOT_POSSIBLE: requests not installed for {event_type}", 
                       event_type="WEBHOOK_FAIL", severity="MEDIUM")
        return
    
    severity = get_severity(event_type)
    
    payload = {
        "timestamp": now_iso(),
        "event": event_type,
        "severity": severity,
        "message": message,
        "file": file_path,
        "priority": SEVERITY_LEVELS.get(severity, {}).get("priority", 0)
    }
    try:
        response = requests.post(url, json=payload, timeout=5)
        append_log_line(f"Webhook sent: {event_type} ({severity})", 
                       event_type="WEBHOOK_SENT", severity="INFO")
        return response
    except Exception as e:
        append_log_line(f"WEBHOOK_FAIL: {e}", 
                       event_type="WEBHOOK_FAIL", severity="MEDIUM")

# ------------------ Verification & Summary ------------------
def verify_all_files_and_update(records=None, watch_folder=None):
    """
    Full scan: verify all files in watch_folder against records.
    Update records for new/modified files and remove deleted ones.
    Returns a summary dict including tamper flags.
    """
    print("DEBUG: Starting verify_all_files_and_update")
    
    if watch_folder is None:
        watch_folder = CONFIG["watch_folder"]
    if records is None:
        records = load_hash_records()
    
    print(f"DEBUG: Watch folder: {watch_folder}")
    print(f"DEBUG: Initial records count: {len(records)}")
    
    seen = set()
    created = []
    modified = []
    skipped = []
    
    # Scan all files
    for root, _, files in os.walk(watch_folder):
        for fn in files:
            if is_ignored_filename(fn):
                continue
            path = os.path.abspath(os.path.join(root, fn))
            seen.add(path)
            h = generate_file_hash(path)
            if h is None:
                skipped.append(path)
                continue
            old_hash = records.get(path, {}).get("hash")
            if not old_hash:
                records[path] = {"hash": h, "last_checked": now_pretty()}
                created.append(path)
                print(f"DEBUG: Created: {path}")
            elif old_hash != h:
                records[path] = {"hash": h, "last_checked": now_pretty()}
                modified.append(path)
                print(f"DEBUG: Modified: {path}")
            else:
                records[path]["last_checked"] = now_pretty()
    
    # detect deleted
    deleted = [p for p in list(records.keys()) if p not in seen and not is_ignored_filename(os.path.basename(p))]
    for p in deleted:
        records.pop(p, None)
        print(f"DEBUG: Deleted: {p}")
    
    print(f"DEBUG: Created: {len(created)}, Modified: {len(modified)}, Deleted: {len(deleted)}, Skipped: {len(skipped)}")
    
    # save updated records & signature
    save_hash_records(records)
    
    # verify signatures now
    records_ok = verify_records_signature_on_disk()
    logs_ok, logs_detail = verify_log_signatures()
    
    summary = {
        "timestamp": now_iso(),
        "total_monitored": len(records),
        "created": created,
        "modified": modified,
        "deleted": deleted,
        "skipped": skipped,
        "tampered_records": not records_ok,
        "tampered_logs": not logs_ok,
        "logs_detail": logs_detail
    }
    
    print(f"DEBUG: Summary prepared, calling write_report_summary")
    write_report_summary(summary)
    return summary

# [In integrity_core.py] Replace write_report_summary

def write_report_summary(summary):
    """Write human-readable summary AND detailed report"""
    try:
        # 1. Write Summary (Existing logic)
        header = f"=== Summary @ {summary['timestamp']} ==="
        lines = [
            header,
            f"Total files monitored: {summary['total_monitored']}",
            f"New files: {len(summary['created'])}",
            f"Modified files: {len(summary['modified'])}",
            f"Deleted files: {len(summary['deleted'])}",
            f"Skipped: {len(summary['skipped'])}",
            f"TAMPER - records: {'YES' if summary.get('tampered_records') else 'NO'}",
            f"TAMPER - logs: {'YES' if summary.get('tampered_logs') else 'NO'}",
            "=" * 50,
            ""
        ]
        text = "\n".join(lines)
        
        with open(REPORT_SUMMARY_FILE, "a", encoding="utf-8") as f:
            f.write(text + "\n")

        # 2. Write Detailed Report (NEW LOGIC)
        detailed_file = os.path.join("logs", "detailed_reports.txt")
        with open(detailed_file, "w", encoding="utf-8") as df:
            df.write(f"DETAILED INTEGRITY REPORT\n")
            df.write(f"Generated: {now_pretty()}\n")
            df.write("=" * 60 + "\n\n")

            if summary['created']:
                df.write(f"--- [ {len(summary['created'])} NEW FILES ] ---\n")
                for item in summary['created']:
                    df.write(f"+ {item}\n")
                df.write("\n")

            if summary['modified']:
                df.write(f"--- [ {len(summary['modified'])} MODIFIED FILES ] ---\n")
                for item in summary['modified']:
                    df.write(f"~ {item}\n")
                df.write("\n")

            if summary['deleted']:
                df.write(f"--- [ {len(summary['deleted'])} DELETED FILES ] ---\n")
                for item in summary['deleted']:
                    df.write(f"- {item}\n")
                df.write("\n")
                
            if not (summary['created'] or summary['modified'] or summary['deleted']):
                df.write("No changes detected in this scan.\n")
                
        # Append detailed generation event to internal log (silent severity)
        append_log_line(f"Reports generated: {REPORT_SUMMARY_FILE}, {detailed_file}", severity="INFO")

    except Exception as e:
        print(f"Error writing reports: {e}")
        traceback.print_exc()

# ------------------ Watchdog event handler ------------------
class IntegrityHandler(FileSystemEventHandler):
    def __init__(self, watch_folder=None, callback=None):  # <--- FIXED: Added callback support
        super().__init__()
        self.watch_folder = watch_folder or CONFIG["watch_folder"]
        self.callback = callback  # <--- Store the GUI callback
        self.records = load_hash_records()
        
        # Verify signatures on startup
        ok_records = verify_records_signature_on_disk()
        append_log_line("Startup: records signature OK" if ok_records else "Startup: records signature FAILED")
        ok_logs, detail = verify_log_signatures()
        append_log_line("Startup: log signature OK" if ok_logs else f"Startup: log signature FAILED ({detail})")
        
        # Ensure log files exist
        if not os.path.exists(LOG_FILE):
            atomic_write_text(LOG_FILE, f"{now_pretty()} - Log started\n")
        if not os.path.exists(LOG_SIG_FILE):
            atomic_write_text(LOG_SIG_FILE, "")

        # Initial scan to populate missing files
        initial_added = False
        for root, _, files in os.walk(self.watch_folder):
            for fn in files:
                if is_ignored_filename(fn): continue
                path = os.path.abspath(os.path.join(root, fn))
                if path not in self.records:
                    h = generate_file_hash(path)
                    if h:
                        self.records[path] = {"hash": h, "last_checked": now_pretty()}
                        initial_added = True
        if initial_added:
            save_hash_records(self.records)

        # Burst detection variables
        self.recent_deletes = []
        self.recent_events = []
        self.burst_threshold = 5
        self.burst_time_window = 10

    def _notify_gui(self, event_type, path, severity):
        """
        Notify GUI only if stealth mode is disabled.
        """
        if CONFIG.get("stealth_mode", False):
            return  # 🔒 Silent background mode

        if self.callback:
            try:
                self.callback(event_type, path, severity)
            except Exception as e:
                print(f"Callback error: {e}")



    def _check_burst_operations(self, event_type):
        """Check for burst operations"""
        current_time = time.time()
        # Clean old events
        self.recent_events = [t for t in self.recent_events if current_time - t < self.burst_time_window]
        self.recent_events.append(current_time)
        
        # Check for burst
        if len(self.recent_events) >= self.burst_threshold:
            severity = "HIGH"
            message = f"Burst operation detected: {len(self.recent_events)} events in {self.burst_time_window} seconds"
            append_log_line(message, event_type="BURST_OPERATION", severity=severity)
            send_webhook_safe("BURST_OPERATION", message, None)
            
            self._notify_gui("BURST_OPERATION", "Multiple Files", severity) # <--- NOTIFY GUI
            
            self.recent_events = []
            return True
        return False

    def save_records(self):
        save_hash_records(self.records)

    def on_created(self, event):
        if event.is_directory: return
        path = os.path.abspath(event.src_path)
        if is_ignored_filename(os.path.basename(path)): return
        
        h = generate_file_hash(path)
        if h:
            self.records[path] = {"hash": h, "last_checked": now_pretty()}
            self.save_records()
            append_log_line(f"CREATED: {path}", event_type="CREATED", severity="INFO")
            send_webhook_safe("CREATED", "New file created", path)
            self._notify_gui("CREATED", path, "INFO") # <--- NOTIFY GUI

    def on_modified(self, event):
        if event.is_directory: return
        path = os.path.abspath(event.src_path)
        if is_ignored_filename(os.path.basename(path)): return
        
        h = generate_file_hash(path)
        if not h: return
        
        old_hash = self.records.get(path, {}).get("hash")
        if not old_hash:
            self.records[path] = {"hash": h, "last_checked": now_pretty()}
            self.save_records()
            append_log_line(f"CREATED_ON_MODIFY: {path}", event_type="CREATED_ON_MODIFY", severity="INFO")
            self._notify_gui("CREATED", path, "INFO") # <--- NOTIFY GUI
        elif old_hash != h:
            self.records[path] = {"hash": h, "last_checked": now_pretty()}
            self.save_records()
            append_log_line(f"MODIFIED: {path}", event_type="MODIFIED", severity="MEDIUM")
            send_webhook_safe("MODIFIED", "File content changed", path)
            self._notify_gui("MODIFIED", path, "MEDIUM") # <--- NOTIFY GUI

    def on_deleted(self, event):
        if event.is_directory: return
        path = os.path.abspath(event.src_path)
        if is_ignored_filename(os.path.basename(path)): return
        
        # Burst Logic
        current_time = time.time()
        self.recent_deletes.append(current_time)
        self.recent_deletes = [t for t in self.recent_deletes if current_time - t < self.burst_time_window]
        
        if len(self.recent_deletes) >= 3:
            severity = "HIGH"
            message = f"Multiple deletes detected: {len(self.recent_deletes)} files"
            append_log_line(message, event_type="MULTIPLE_DELETES", severity=severity)
            send_webhook_safe("MULTIPLE_DELETES", message, None)
            self._notify_gui("MULTIPLE_DELETES", "Multiple Files", severity) # <--- NOTIFY GUI
        
        # Individual Logic
        if path in self.records:
            self.records.pop(path, None)
            self.save_records()
            append_log_line(f"DELETED: {path}", event_type="DELETED", severity="MEDIUM")
            send_webhook_safe("DELETED", "File deleted", path)
            self._notify_gui("DELETED", path, "MEDIUM") # <--- NOTIFY GUI
        else:
            append_log_line(f"DELETED_UNTRACKED: {path}", event_type="DELETED_UNTRACKED", severity="MEDIUM")
            self._notify_gui("DELETED", path, "MEDIUM") # <--- NOTIFY GUI
        
        self._check_burst_operations("DELETE")

# ------------------ Monitor Controller ------------------
class FileIntegrityMonitor:
    def __init__(self):
        self.observer = None
        self.handler = None
        self.verifier_thread = None
        self.running = False
        self.current_watch_folder = None

    def start_monitoring(self, watch_folder=None, event_callback=None):
        """Start the file integrity monitoring"""
        if not load_config():
            return False

        # Use provided watch_folder or from config
        self.current_watch_folder = watch_folder or CONFIG["watch_folder"]
        wf = self.current_watch_folder
        
        if not os.path.exists(wf):
            print(f"[ERROR] Watch folder does not exist: {wf}")
            return False

        # ensure log files exist
        if not os.path.exists(LOG_FILE):
            atomic_write_text(LOG_FILE, f"{now_pretty()} - Log started\n")
        if not os.path.exists(LOG_SIG_FILE):
            atomic_write_text(LOG_SIG_FILE, "")

        # --- FIX IS HERE: Pass 'event_callback' to the Handler ---
        self.handler = IntegrityHandler(watch_folder=wf, callback=event_callback)
        
        self.observer = Observer()
        self.observer.schedule(self.handler, wf, recursive=True)
        self.observer.start()

        # Start periodic verification thread
        self.running = True
        self.verifier_thread = threading.Thread(target=self._periodic_verifier_loop, daemon=True)
        self.verifier_thread.start()

        append_log_line(f"MONITOR_STARTED: {wf}")
        return True

    def stop_monitoring(self):
        """Stop the file integrity monitoring"""
        self.running = False
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
        self.handler = None
        append_log_line("MONITOR_STOPPED")

    def _periodic_verifier_loop(self):
        """Periodic verification loop"""
        while self.running:
            time.sleep(CONFIG["verify_interval"])
            try:
                rotate_logs_if_needed()
                append_log_line("PERIODIC_VERIFICATION_START")
                
                # Run the actual verification
                if self.handler:
                    summary = verify_all_files_and_update(self.handler.records, self.current_watch_folder)
                else:
                    summary = verify_all_files_and_update(None, self.current_watch_folder)
                
                # Optional webhook with numeric summary
                send_webhook_safe("PERIODIC_SUMMARY", "Periodic verification completed", None)
                
            except Exception as e:
                append_log_line(f"ERROR in periodic verification: {e}")

    def run_verification(self, watch_folder=None):
        """Run one-time verification and return summary"""
        print("DEBUG: run_verification called")
        # Use provided watch_folder, current folder, or from config
        target_folder = watch_folder or self.current_watch_folder or CONFIG["watch_folder"]
        
        append_log_line("MANUAL_VERIFICATION_STARTED")
        
        if self.handler:
            result = verify_all_files_and_update(self.handler.records, target_folder)
        else:
            result = verify_all_files_and_update(None, target_folder)
        
        print(f"DEBUG: run_verification returning: {result}")
        return result

    def get_summary(self):
        """Get the last summary from report file"""
        try:
            if os.path.exists(REPORT_SUMMARY_FILE):
                with open(REPORT_SUMMARY_FILE, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    if content:
                        return content
                    else:
                        return "Report summary file exists but is empty."
            else:
                return "No report summary file found. Run a verification first."
        except Exception as e:
            return f"Error reading summary file: {e}"


# Add 'import shutil' at the top of the file if not present

def archive_session():
    """
    Archive logs and reset safely with SIGNATURES.
    """
    try:
        # 1. Setup paths
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        history_base = os.path.join(DATA_ROOT, "config", "history") # Use DATA_ROOT
        if not os.path.exists(history_base):
            os.makedirs(history_base)
            
        session_folder = os.path.join(history_base, f"Session_{timestamp}")
        if not os.path.exists(session_folder):
            os.makedirs(session_folder)

        # Files to move
        files_to_archive = [
            "integrity_log.txt",
            "integrity_log.sig",
            "hash_records.json",
            "hash_records.sig",
            "detailed_reports.txt",
            "report_data.json",
            "severity_counters.json"
        ]

        # 2. Move files
        for filename in files_to_archive:
            src = os.path.join(log_dir, filename) # Use log_dir variable
            if os.path.exists(src):
                dst = os.path.join(session_folder, filename)
                shutil.move(src, dst)
                print(f"Archived: {filename}")

        # 3. RE-INITIALIZE SAFELY (The Fix)
        
        # Clear files first
        open(LOG_FILE, "w").close() 
        open(LOG_SIG_FILE, "w").close()
        open(HASH_RECORD_FILE, "w").close()
        open(HASH_SIGNATURE_FILE, "w").close()

        # Reset JSONs
        with open(HASH_RECORD_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f)
        
        empty_counters = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0}
        with open(SEVERITY_COUNTER_FILE, "w", encoding="utf-8") as f:
            json.dump(empty_counters, f)
        
        # Reset Memory Counters
        global _SEVERITY_CACHE
        _SEVERITY_CACHE = empty_counters.copy()

        # CRITICAL: Use append_log_line to write the first line. 
        # This automatically generates the signature!
        append_log_line("Log reset. New session started.", severity="INFO")
        
        return True, f"Session archived to {session_folder}"

    except Exception as e:
        traceback.print_exc()
        return False, str(e)