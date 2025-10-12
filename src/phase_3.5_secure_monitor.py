#!/usr/bin/env python3
"""
phase_3_5_secure_monitor.py
Phase 3.5 — Secure File Integrity Monitor with:
 - config.json support
 - real-time monitoring (watchdog)
 - HMAC-signed hash_records.json (hash_records.sig)
 - per-line HMAC signatures for integrity_log.txt (integrity_log.sig)
 - atomic writes
 - periodic verification and summary report (report_summary.txt)
 - CLI flags and optional webhook alerts
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
    # "watch_folder": os.path.abspath(os.path.join(os.getcwd(), "tests")),
    "watch_folder": r"D:\Study\LISA_PROJECT\FileIntegrityChecker\tests",
    "verify_interval": 60,             # time for periodic verification
    "webhook_url": None,
    "secret_key": "Lisamerijaanu",
    "max_log_size_mb": 10,
    "max_log_backups": 5,
    "hash_algo": "sha256",
    "hash_chunk_size": 65536,
    "hash_retries": 3,
    "hash_retry_delay": 0.5,
    "ignore_filenames": ["hash_records.json", "integrity_log.txt", "integrity_log.sig", "hash_records.sig", "report_summary.txt"]
}

# Filenames (can be overridden via config file path keys if you want)
HASH_RECORD_FILE = "hash_records.json"
HASH_SIGNATURE_FILE = "hash_records.sig"
LOG_FILE = "integrity_log.txt"
LOG_SIG_FILE = "integrity_log.sig"
REPORT_SUMMARY_FILE = "report_summary.txt"

# in-memory config will be loaded on startup
CONFIG = dict(DEFAULT_CONFIG)

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
        # try default file in cwd
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
    return CONFIG

# ------------------ Logging & Log HMAC (per-line) ------------------
def append_log_line(message):
    """
    Append a human-readable line to integrity_log.txt and append per-line HMAC to integrity_log.sig
    """
    # ensure directory exists
    os.makedirs(os.path.dirname(os.path.abspath(LOG_FILE)) or ".", exist_ok=True)

    line = f"{now_pretty()} - {message}"
    # append line
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    # append per-line signature
    append_log_signature(line)

def append_log_signature(line):
    """
    For each log line, compute HMAC of the full line string and append hex to LOG_SIG_FILE (one per line).
    """
    key = CONFIG["secret_key"].encode("utf-8")
    sig = hmac.new(key, line.encode("utf-8"), getattr(hashlib, CONFIG["hash_algo"])).hexdigest()
    with open(LOG_SIG_FILE, "a", encoding="utf-8") as f:
        f.write(sig + "\n")

def rotate_logs_if_needed():
    """
    Rotate integrity_log.txt when it exceeds configured max size (MB). Keep configured number of backups.
    Also rotate/sign the sig file accordingly.
    """
    max_mb = CONFIG["max_log_size_mb"]
    max_bytes = max_mb * 1024 * 1024
    if not os.path.exists(LOG_FILE):
        return
    size = os.path.getsize(LOG_FILE)
    if size <= max_bytes:
        return
    # rotate: rename with timestamp
    ts = datetime.now().strftime("%Y%m%d%H%M%S")
    base = os.path.splitext(LOG_FILE)[0]
    new_name = f"{base}_{ts}.log"
    os.replace(LOG_FILE, new_name)
    # also move corresponding sig file if exists
    if os.path.exists(LOG_SIG_FILE):
        sig_new = f"{os.path.splitext(LOG_SIG_FILE)[0]}_{ts}.sig"
        os.replace(LOG_SIG_FILE, sig_new)
    append_log_line(f"LOG_ROTATED: {new_name}")
    # cleanup old backups
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
    # use sorted JSON bytes so signature consistent
    raw = json.dumps(records_dict, sort_keys=True).encode("utf-8")
    key = CONFIG["secret_key"].encode("utf-8")
    return hmac.new(key, raw, getattr(hashlib, CONFIG["hash_algo"])).hexdigest()

def save_hash_records(records):
    # atomic write records and signature
    atomic_write_json(HASH_RECORD_FILE, records)
    sig = generate_records_hmac(records)
    atomic_write_text(HASH_SIGNATURE_FILE, sig)

def load_hash_records():
    if not os.path.exists(HASH_RECORD_FILE):
        # create empty
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
        # if no signature, create one
        save_hash_records(records)
        append_log_line("INFO: No hash signature found; created new signature.")
        return True
    expected = generate_records_hmac(records)
    ok = hmac.compare_digest(expected, sig)
    if not ok:
        append_log_line("ALERT: hash_records.json signature mismatch (possible tampering)")
        send_webhook_safe("INTEGRITY_FAIL", "hash_records.json HMAC mismatch", HASH_RECORD_FILE)
    return ok

# ------------------ Hashing (chunked + retry) ------------------
def generate_file_hash(path):
    """
    Chunked hashing with retries for transient lock conditions.
    """
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
    Returns a summary dict.
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
            if any(ig in fn for ig in CONFIG["ignore_filenames"]):
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
    deleted = [p for p in list(records.keys()) if p not in seen and not any(ig in p for ig in CONFIG["ignore_filenames"])]
    for p in deleted:
        # remove from records
        records.pop(p, None)
    # save updated records & signature
    save_hash_records(records)
    summary = {
        "timestamp": now_iso(),
        "total_monitored": len(records),
        "created": created,
        "modified": modified,
        "deleted": deleted,
        "skipped": skipped
    }
    # write report summary file (append)
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
        ""
    ]
    text = "\n".join(lines)
    with open(REPORT_SUMMARY_FILE, "a", encoding="utf-8") as f:
        f.write(text + "\n")
    # also print concise to console & log
    append_log_line("VERIFICATION_SUMMARY: " + header)
    append_log_line(f"Total={summary['total_monitored']} New={len(summary['created'])} Mod={len(summary['modified'])} Del={len(summary['deleted'])} Skip={len(summary['skipped'])}")
    print("\n" + header)
    for l in lines[1:]:
        print(l)
    print()

# ------------------ Watchdog event handler ------------------
class IntegrityHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.records = load_hash_records()
        # verify on-disk signature at startup
        ok = verify_records_signature_on_disk()
        if ok:
            append_log_line("Startup: records signature OK")
        else:
            append_log_line("Startup: records signature FAILED (see earlier alert)")
        # make sure log signature file exists (create headers if not)
        if not os.path.exists(LOG_FILE):
            atomic_write_text(LOG_FILE, f"{now_pretty()} - Log started\n")
        if not os.path.exists(LOG_SIG_FILE):
            atomic_write_text(LOG_SIG_FILE, "")
        # initial scan to populate any missing files (do not overwrite if signature failed)
        # If signature failed, still attempt to populate but keep alert sent
        initial_added = False
        for root, _, files in os.walk(CONFIG["watch_folder"]):
            for fn in files:
                if any(ig in fn for ig in CONFIG["ignore_filenames"]):
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
        if any(ig in os.path.basename(path) for ig in CONFIG["ignore_filenames"]):
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
        if any(ig in os.path.basename(path) for ig in CONFIG["ignore_filenames"]):
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
        # rotate logs if needed
        rotate_logs_if_needed()
        append_log_line("PERIODIC_VERIFICATION_START")
        # verify on-disk signature first
        ok = verify_records_signature_on_disk()
        if not ok:
            # signature mismatch already alerted in verify_records_signature_on_disk()
            continue
        # perform full verify & update summary
        summary = verify_all_files_and_update(handler.records, CONFIG["watch_folder"])
        # send webhook with summary counts (optional)
        send_webhook_safe("PERIODIC_SUMMARY", "Periodic verification completed", None)

# ------------------ CLI / Main ------------------
def main():
    parser = argparse.ArgumentParser(description="Phase 3.5 Secure File Integrity Monitor")
    parser.add_argument("--config", type=str, help="Path to config.json (optional)")
    parser.add_argument("--watch", type=str, help="Folder to watch (overrides config)")
    parser.add_argument("--verify", action="store_true", help="Run full verification once and exit")
    parser.add_argument("--summary-only", action="store_true", help="Print last summary and exit")
    parser.add_argument("--webhook", type=str, help="Enable webhook URL for this run")
    parser.add_argument("--interval", type=int, help="Periodic verify interval seconds")
    args = parser.parse_args()

    # load config
    load_config(args.config)
    # overrides
    if args.watch:
        CONFIG["watch_folder"] = os.path.abspath(args.watch)
    if args.webhook:
        CONFIG["webhook_url"] = args.webhook
    if args.interval:
        CONFIG["verify_interval"] = int(args.interval)

    # basic checks
    wf = CONFIG["watch_folder"]
    if not os.path.exists(wf):
        print(f"[ERROR] Watch folder does not exist: {wf}")
        sys.exit(1)

    # show startup info
    print("========================================")
    print("Phase 3.5 — Secure File Integrity Monitor")
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

    # if summary-only, print last report_summary if exists
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

    # start watchdog & periodic thread
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
