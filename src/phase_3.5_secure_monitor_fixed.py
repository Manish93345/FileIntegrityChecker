#!/usr/bin/env python3
"""
phase_3_5_secure_monitor_fixed.py
Phase 3.5 (fixed): Secure File Integrity Monitor
- fixes:
  * verify integrity_log.sig vs integrity_log.txt (detect log tampering)
  * include tampering info in report summary
  * better ignore rules for temp/partial files to avoid SKIP_HASH spam
  * verify log signatures at startup and periodically
- other features from previous version retained
"""

import os
import sys
import json
import time
import hashlib
import hmac
import threading
import argparse
from datetime import datetime

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

# ------------------ Defaults & Config ------------------
DEFAULT_CONFIG = {
    "watch_folder": r"D:\Study\LISA_PROJECT\FileIntegrityChecker\tests",
    "verify_interval": 60,             # 30 minutes
    "webhook_url": None,
    "secret_key": "Lisamerijaanu_change_me",
    "max_log_size_mb": 10,
    "max_log_backups": 5,
    "hash_algo": "sha256",
    "hash_chunk_size": 65536,
    "hash_retries": 3,
    "hash_retry_delay": 0.5,
    # default filenames to ignore (substring match)
    "ignore_filenames": ["hash_records.json", "integrity_log.txt", "integrity_log.sig", "hash_records.sig", "report_summary.txt"]
}

# Filenames (can be overridden if you extend config to change names)
HASH_RECORD_FILE = "hash_records.json"
HASH_SIGNATURE_FILE = "hash_records.sig"
LOG_FILE = "integrity_log.txt"
LOG_SIG_FILE = "integrity_log.sig"
REPORT_SUMMARY_FILE = "report_summary.txt"

# in-memory config will be loaded on startup
CONFIG = dict(DEFAULT_CONFIG)

# Additional temp patterns to ignore (lowercase)
TEMP_PATTERNS = [".tmp", ".part", ".crdownload", ".ds_store", ".swp", ".bak", "~", ".~"]

# ------------------ Utilities ------------------
def now_iso():
    return datetime.now().isoformat(timespec='seconds')

def now_pretty():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def atomic_write_text(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)

def atomic_write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=4, sort_keys=True)
    os.replace(tmp, path)

def load_config(path=None):
    global CONFIG
    if path and os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                CONFIG.update(cfg)
                print(f"[CONFIG] Loaded config from {path}")
        except Exception as e:
            print(f"[CONFIG] Failed to load config {path}: {e} — using defaults")
    else:
        default_path = os.path.join(os.getcwd(), "config.json")
        if os.path.exists(default_path):
            try:
                with open(default_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                    CONFIG.update(cfg)
                    print(f"[CONFIG] Loaded config from {default_path}")
            except Exception as e:
                print(f"[CONFIG] Failed to load default config.json: {e} — using defaults")
        else:
            print("[CONFIG] No config.json found — using defaults")

    # normalize types
    CONFIG["verify_interval"] = int(CONFIG.get("verify_interval", DEFAULT_CONFIG["verify_interval"]))
    CONFIG["max_log_size_mb"] = int(CONFIG.get("max_log_size_mb", DEFAULT_CONFIG["max_log_size_mb"]))
    CONFIG["max_log_backups"] = int(CONFIG.get("max_log_backups", DEFAULT_CONFIG["max_log_backups"]))
    CONFIG["hash_chunk_size"] = int(CONFIG.get("hash_chunk_size", DEFAULT_CONFIG["hash_chunk_size"]))
    CONFIG["hash_retries"] = int(CONFIG.get("hash_retries", DEFAULT_CONFIG["hash_retries"]))
    CONFIG["hash_retry_delay"] = float(CONFIG.get("hash_retry_delay", DEFAULT_CONFIG["hash_retry_delay"]))
    # ensure secrets are present
    if not CONFIG.get("secret_key"):
        CONFIG["secret_key"] = DEFAULT_CONFIG["secret_key"]
    return CONFIG

# ------------------ Logging & Log HMAC (per-line) ------------------
def append_log_line(message):
    """
    Append a human-readable line to integrity_log.txt and append per-line HMAC to integrity_log.sig
    """
    os.makedirs(os.path.dirname(os.path.abspath(LOG_FILE)) or ".", exist_ok=True)
    line = f"{now_pretty()} - {message}"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    append_log_signature(line)

def append_log_signature(line):
    """
    Compute HMAC of the full line string and append hex to LOG_SIG_FILE (one per line).
    """
    key = CONFIG["secret_key"].encode("utf-8")
    h = getattr(hashlib, CONFIG["hash_algo"])
    sig = hmac.new(key, line.encode("utf-8"), h).hexdigest()
    with open(LOG_SIG_FILE, "a", encoding="utf-8") as f:
        f.write(sig + "\n")

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
        append_log_line("INFO: No hash signature found; created new signature.")
        return True
    expected = generate_records_hmac(records)
    ok = hmac.compare_digest(expected, sig)
    if not ok:
        append_log_line("ALERT: hash_records.json signature mismatch (possible tampering)")
        send_webhook_safe("INTEGRITY_FAIL", "hash_records.json HMAC mismatch", HASH_RECORD_FILE)
    return ok

# ------------------ Log signature verification ------------------
def verify_log_signatures():
    """
    Verify integrity_log.txt lines vs integrity_log.sig lines.
    Returns (ok:bool, details:str)
    """
    if not os.path.exists(LOG_FILE) and not os.path.exists(LOG_SIG_FILE):
        # nothing yet
        return True, "No log files present"
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as lf:
            log_lines = [l.rstrip("\n") for l in lf.readlines()]
    except Exception as e:
        return False, f"Failed to read log file: {e}"
    try:
        with open(LOG_SIG_FILE, "r", encoding="utf-8") as sf:
            sig_lines = [s.rstrip("\n") for s in sf.readlines()]
    except Exception as e:
        return False, f"Failed to read sig file: {e}"
    # if lengths differ -> possible tamper (or rotation race). Report it.
    if len(log_lines) != len(sig_lines):
        msg = f"Log/Sig length mismatch: {len(log_lines)} lines vs {len(sig_lines)} sigs"
        append_log_line("ALERT: integrity_log signature length mismatch")
        send_webhook_safe("LOG_INTEGRITY_FAIL", msg, LOG_FILE)
        return False, msg
    # verify each line
    key = CONFIG["secret_key"].encode("utf-8")
    h = getattr(hashlib, CONFIG["hash_algo"])
    for i, (line, sig) in enumerate(zip(log_lines, sig_lines)):
        # verify using exact line text
        calc = hmac.new(key, line.encode("utf-8"), h).hexdigest()
        if not hmac.compare_digest(calc, sig):
            detail = f"Line {i+1} signature mismatch"
            append_log_line("ALERT: integrity_log content mismatch detected")
            send_webhook_safe("LOG_INTEGRITY_FAIL", detail, LOG_FILE)
            return False, detail
    return True, "Log signatures OK"

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
        append_log_line(f"ALERT_WEBHOOK_NOT_POSSIBLE: requests not installed for {event_type}")
        return
    payload = {
        "timestamp": now_iso(),
        "event": event_type,
        "message": message,
        "file": file_path
    }
    try:
        requests.post(url, json=payload, timeout=5)
    except Exception as e:
        append_log_line(f"WEBHOOK_FAIL: {e}")

# ------------------ Verification & Summary ------------------
def verify_all_files_and_update(records=None, watch_folder=None):
    """
    Full scan: verify all files in watch_folder against records.
    Update records for new/modified files and remove deleted ones.
    Returns a summary dict including tamper flags.
    """
    if watch_folder is None:
        watch_folder = CONFIG["watch_folder"]
    if records is None:
        records = load_hash_records()
    seen = set()
    created = []
    modified = []
    skipped = []
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
            elif old_hash != h:
                records[path] = {"hash": h, "last_checked": now_pretty()}
                modified.append(path)
            else:
                records[path]["last_checked"] = now_pretty()
    # detect deleted
    deleted = [p for p in list(records.keys()) if p not in seen and not is_ignored_filename(os.path.basename(p))]
    for p in deleted:
        records.pop(p, None)
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
    write_report_summary(summary)
    return summary

def write_report_summary(summary):
    # human readable summary (append)
    header = f"=== Summary @ {summary['timestamp']} ==="
    lines = [
        header,
        f"Total files monitored: {summary['total_monitored']}",
        f"New files: {len(summary['created'])}",
        f"Modified files: {len(summary['modified'])}",
        f"Deleted files: {len(summary['deleted'])}",
        f"Skipped (couldn't hash): {len(summary['skipped'])}",
        f"TAMPER - records: {'YES' if summary.get('tampered_records') else 'NO'}",
        f"TAMPER - logs: {'YES' if summary.get('tampered_logs') else 'NO'}",
        f"Log check detail: {summary.get('logs_detail')}",
        ""
    ]
    text = "\n".join(lines)
    with open(REPORT_SUMMARY_FILE, "a", encoding="utf-8") as f:
        f.write(text + "\n")
    append_log_line("VERIFICATION_SUMMARY: " + header)
    append_log_line(f"Total={summary['total_monitored']} New={len(summary['created'])} Mod={len(summary['modified'])} Del={len(summary['deleted'])} Skip={len(summary['skipped'])} TamperedRecords={summary.get('tampered_records')} TamperedLogs={summary.get('tampered_logs')}")
    # also print concise to console
    print("\n" + header)
    for l in lines[1:]:
        print(l)
    print()

# ------------------ Watchdog event handler ------------------
class IntegrityHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.records = load_hash_records()
        ok_records = verify_records_signature_on_disk()
        append_log_line("Startup: records signature OK" if ok_records else "Startup: records signature FAILED")
        ok_logs, detail = verify_log_signatures()
        append_log_line("Startup: log signature OK" if ok_logs else f"Startup: log signature FAILED ({detail})")
        # ensure log files exist
        if not os.path.exists(LOG_FILE):
            atomic_write_text(LOG_FILE, f"{now_pretty()} - Log started\n")
        if not os.path.exists(LOG_SIG_FILE):
            atomic_write_text(LOG_SIG_FILE, "")
        # initial scan to populate missing files if any
        initial_added = False
        for root, _, files in os.walk(CONFIG["watch_folder"]):
            for fn in files:
                if is_ignored_filename(fn):
                    continue
                path = os.path.abspath(os.path.join(root, fn))
                if path not in self.records:
                    h = generate_file_hash(path)
                    if h:
                        self.records[path] = {"hash": h, "last_checked": now_pretty()}
                        append_log_line(f"INITIALIZED: {path}")
                        initial_added = True
        if initial_added:
            save_hash_records(self.records)
            append_log_line("Initial scan added missing records and saved signature.")

    def save_records(self):
        save_hash_records(self.records)

    def on_created(self, event):
        if event.is_directory:
            return
        path = os.path.abspath(event.src_path)
        if is_ignored_filename(os.path.basename(path)):
            return
        h = generate_file_hash(path)
        if h:
            self.records[path] = {"hash": h, "last_checked": now_pretty()}
            self.save_records()
            append_log_line(f"CREATED: {path}")
            send_webhook_safe("CREATED", "New file created", path)

    def on_modified(self, event):
        if event.is_directory:
            return
        path = os.path.abspath(event.src_path)
        if is_ignored_filename(os.path.basename(path)):
            return
        h = generate_file_hash(path)
        if not h:
            return
        old_hash = self.records.get(path, {}).get("hash")
        if not old_hash:
            self.records[path] = {"hash": h, "last_checked": now_pretty()}
            self.save_records()
            append_log_line(f"CREATED_ON_MODIFY: {path}")
            send_webhook_safe("CREATED_ON_MODIFY", "Untracked file observed on modify", path)
        elif old_hash != h:
            self.records[path] = {"hash": h, "last_checked": now_pretty()}
            self.save_records()
            append_log_line(f"MODIFIED: {path}")
            send_webhook_safe("MODIFIED", "File content changed", path)

    def on_deleted(self, event):
        if event.is_directory:
            return
        path = os.path.abspath(event.src_path)
        if is_ignored_filename(os.path.basename(path)):
            return
        if path in self.records:
            self.records.pop(path, None)
            self.save_records()
            append_log_line(f"DELETED: {path}")
            send_webhook_safe("DELETED", "File deleted", path)
        else:
            append_log_line(f"DELETED_UNTRACKED: {path}")
            send_webhook_safe("DELETED_UNTRACKED", "Untracked file deleted", path)

# ------------------ Periodic verifier thread ------------------
def periodic_verifier_loop(handler):
    while True:
        time.sleep(CONFIG["verify_interval"])
        rotate_logs_if_needed()
        append_log_line("PERIODIC_VERIFICATION_START")
        # 1) check records signature on disk (detect external tampering)
        records_ok = verify_records_signature_on_disk()
        if not records_ok:
            # already alerted by verify_records_signature_on_disk()
            # still continue to check logs so we know both statuses
            pass
        # 2) check log signatures
        logs_ok, detail = verify_log_signatures()
        if not logs_ok:
            # verify_log_signatures already logged & webhooked
            pass
        # 3) perform full verify & update summary (this will call verify functions again)
        summary = verify_all_files_and_update(handler.records, CONFIG["watch_folder"])
        # 4) optional webhook with numeric summary
        send_webhook_safe("PERIODIC_SUMMARY", "Periodic verification completed", None)

# ------------------ CLI / Main ------------------
def main():
    parser = argparse.ArgumentParser(description="Phase 3.5 Secure File Integrity Monitor (fixed)")
    parser.add_argument("--config", type=str, help="Path to config.json (optional)")
    parser.add_argument("--watch", type=str, help="Folder to watch (overrides config)")
    parser.add_argument("--verify", action="store_true", help="Run full verification once and exit")
    parser.add_argument("--summary-only", action="store_true", help="Print last summary and exit")
    parser.add_argument("--webhook", type=str, help="Enable webhook URL for this run")
    parser.add_argument("--interval", type=int, help="Periodic verify interval seconds")
    args = parser.parse_args()

    load_config(args.config)
    # overrides
    if args.watch:
        CONFIG["watch_folder"] = os.path.abspath(args.watch)
    if args.webhook:
        CONFIG["webhook_url"] = args.webhook
    if args.interval:
        CONFIG["verify_interval"] = int(args.interval)

    wf = CONFIG["watch_folder"]
    if not os.path.exists(wf):
        print(f"[ERROR] Watch folder does not exist: {wf}")
        sys.exit(1)

    # startup info
    print("========================================")
    print("Phase 3.5 — Secure File Integrity Monitor (fixed)")
    print(f"Watch folder: {wf}")
    print(f"Verify interval: {CONFIG['verify_interval']}s")
    print(f"Webhook: {'enabled' if CONFIG.get('webhook_url') else 'disabled'}")
    print("Starting up...")
    print("========================================")

    # ensure log files exist
    if not os.path.exists(LOG_FILE):
        atomic_write_text(LOG_FILE, f"{now_pretty()} - Log started\n")
    if not os.path.exists(LOG_SIG_FILE):
        atomic_write_text(LOG_SIG_FILE, "")

    if args.summary_only:
        if os.path.exists(REPORT_SUMMARY_FILE):
            with open(REPORT_SUMMARY_FILE, "r", encoding="utf-8") as f:
                print(f.read())
        else:
            print("No report summary file found.")
        return

    handler = IntegrityHandler()

    if args.verify:
        print("Running one-shot full verification...")
        s = verify_all_files_and_update(handler.records, CONFIG["watch_folder"])
        print("One-shot verification completed.")
        return

    observer = Observer()
    observer.schedule(handler, CONFIG["watch_folder"], recursive=True)
    observer.start()
    t = threading.Thread(target=periodic_verifier_loop, args=(handler,), daemon=True)
    t.start()

    print("Monitor running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping monitor...")
        append_log_line("MONITOR_STOPPED_BY_USER")
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()
