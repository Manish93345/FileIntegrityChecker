# realtime_monitor_enhanced.py
"""
File Integrity Checker — Enhanced (Phase 1)
Features:
- Startup checks: auto-create log & records, validate watch folder
- Initial scan to register existing files
- generate_hash: chunked hashing + retry for PermissionError / transient locks
- verify_all_files(): manual full re-check and summary report
- Real-time monitoring with watchdog (CREATE / MODIFY / DELETE)
- Optional webhook alert call if WEBHOOK_URL set in config
- CLI: run monitor (default) or --verify then exit
"""

import os
import json
import time
import hashlib
import argparse
import requests  # optional, include in requirements.txt; code tolerates if import fails at runtime
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ---------------------------
# CONFIG — edit as needed
# ---------------------------
WATCH_FOLDER = r"D:\Study\LISA_PROJECT\FileIntegrityChecker\tests"  # change to your folder
HASH_RECORD_FILE = "hash_records.json"
LOG_FILE = "integrity_log.txt"

# Hashing params
HASH_ALGO = "sha256"
HASH_CHUNK_SIZE = 65536  # 64KB per chunk
HASH_RETRIES = 4
HASH_RETRY_DELAY = 0.5  # seconds between retries

# Optional webhook (set to your webhook URL to enable alert POSTs)
WEBHOOK_URL = None  # e.g. "https://webhook.site/xxxx" or None to disable
# WEBHOOK_URL = "https://webhook.site/eeaa3926-d2da-4bd8-bd36-bf9994a4a5f2" 

# Ignore patterns (simple substring match)
IGNORE_FILENAMES = ["hash_records.json", "integrity_log.txt"]

# ---------------------------
# Helpers
# ---------------------------
def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def append_log(message):
    os.makedirs(os.path.dirname(os.path.abspath(LOG_FILE)), exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{now()} - {message}\n")

def send_webhook(event_type, path, extra=None):
    if not WEBHOOK_URL:
        return
    payload = {"event": event_type, "path": path, "timestamp": datetime.now().isoformat(), "extra": extra or {}}
    try:
        requests.post(WEBHOOK_URL, json=payload, timeout=3)
    except Exception as e:
        append_log(f"ALERT_FAILED: {e}")

# ---------------------------
# Robust chunked hash function
# ---------------------------
def generate_hash(file_path, retries=HASH_RETRIES, delay=HASH_RETRY_DELAY, chunk_size=HASH_CHUNK_SIZE):
    """Generate file hash using streaming (chunked) read + retry logic for transient PermissionError."""
    for attempt in range(1, retries + 1):
        try:
            h = hashlib.new(HASH_ALGO)
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.hexdigest()
        except (PermissionError, FileNotFoundError) as e:
            # transient lock/permission: wait and retry a few times
            if attempt < retries:
                time.sleep(delay)
                continue
            append_log(f"⚠️ Skipped (hash failed) {file_path} ({e})")
            return None
        except Exception as e:
            append_log(f"ERROR hashing {file_path}: {e}")
            return None

# ---------------------------
# Load / Save records (safe)
# ---------------------------
def load_hash_records():
    if not os.path.exists(HASH_RECORD_FILE):
        # create empty file
        with open(HASH_RECORD_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f)
        return {}
    try:
        with open(HASH_RECORD_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
            # if file has different shape, coerce
            return dict(data)
    except json.JSONDecodeError:
        append_log("WARNING: hash_records.json corrupted / empty — resetting to {}")
        return {}

def save_hash_records(records):
    with open(HASH_RECORD_FILE, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=4)

# ---------------------------
# Startup / initialization
# ---------------------------
def initialize_system(watch_folder=WATCH_FOLDER):
    # ensure watch folder exists and is accessible
    if not os.path.exists(watch_folder):
        raise FileNotFoundError(f"Watch folder does not exist: {watch_folder}")

    # ensure log file exists (append mode will create, but create explicit header)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            f.write(f"{now()} - Log started\n")

    # ensure records file exists / is valid
    records = load_hash_records()
    append_log("✅ Startup checks complete")
    return records

# ---------------------------
# Full verification function
# ---------------------------
def verify_all_files(watch_folder=WATCH_FOLDER):
    """Scans the whole watch folder and returns a summary dict. Also updates hash_records.json."""
    append_log("🔁 Starting full verification (verify_all_files)")
    records = load_hash_records()
    seen = set()
    modified = []
    created = []
    skipped = []

    for root, _, files in os.walk(watch_folder):
        for name in files:
            if any(ig in name for ig in IGNORE_FILENAMES):
                continue
            path = os.path.abspath(os.path.join(root, name))
            seen.add(path)
            new_hash = generate_hash(path)
            if new_hash is None:
                skipped.append(path)
                continue
            old_hash = records.get(path, {}).get("hash")
            if not old_hash:
                records[path] = {"hash": new_hash, "last_checked": now()}
                created.append(path)
            elif old_hash != new_hash:
                records[path] = {"hash": new_hash, "last_checked": now()}
                modified.append(path)
            else:
                # unchanged -> update last_checked
                records[path]["last_checked"] = now()

    # detect deleted (present in records but not on disk)
    deleted = [p for p in list(records.keys()) if p not in seen and not any(ig in p for ig in IGNORE_FILENAMES)]
    for p in deleted:
        append_log(f"DELETED (from verify): {p}")
        del records[p]

    save_hash_records(records)
    append_log("✅ Full verification complete")
    summary = {"created": created, "modified": modified, "deleted": deleted, "skipped": skipped, "total_monitored": len(records)}
    return summary

# ---------------------------
# Watchdog Event Handler
# ---------------------------
class IntegrityHandler(FileSystemEventHandler):
    def __init__(self):
        self.records = load_hash_records()

    def update_record(self, path, new_hash):
        self.records[path] = {"hash": new_hash, "last_checked": now()}
        save_hash_records(self.records)

    def on_created(self, event):
        if event.is_directory:
            return
        path = os.path.abspath(event.src_path)
        if any(ig in os.path.basename(path) for ig in IGNORE_FILENAMES):
            return
        h = generate_hash(path)
        if h:
            self.update_record(path, h)
            append_log(f"CREATED: {path}")
            send_webhook("CREATED", path)

    def on_modified(self, event):
        if event.is_directory:
            return
        path = os.path.abspath(event.src_path)
        if any(ig in os.path.basename(path) for ig in IGNORE_FILENAMES):
            return
        h = generate_hash(path)
        if not h:
            return
        old_hash = self.records.get(path, {}).get("hash")
        if not old_hash:
            # untracked file modified -> treat as created
            self.update_record(path, h)
            append_log(f"CREATED_ON_MODIFY (previously untracked): {path}")
            send_webhook("CREATED_ON_MODIFY", path)
        elif old_hash != h:
            self.update_record(path, h)
            append_log(f"MODIFIED: {path}")
            send_webhook("MODIFIED", path)

    def on_deleted(self, event):
        if event.is_directory:
            return
        path = os.path.abspath(event.src_path)
        if path in self.records:
            append_log(f"DELETED: {path}")
            del self.records[path]
            save_hash_records(self.records)
            send_webhook("DELETED", path)
        else:
            append_log(f"DELETED (untracked): {path}")
            send_webhook("DELETED_UNTRACKED", path)

# ---------------------------
# Main CLI & loop
# ---------------------------
def main():
    global WATCH_FOLDER
    parser = argparse.ArgumentParser(description="File Integrity Checker — Real-time monitor + verify_all_files")
    parser.add_argument("--verify", action="store_true", help="Run full verify_all_files once and exit")
    parser.add_argument("--watch", type=str, default=WATCH_FOLDER, help="Folder to watch (overrides default)")
    args = parser.parse_args()

    watch_path = os.path.abspath(args.watch)
    
    WATCH_FOLDER = watch_path

    # Startup checks
    try:
        records = initialize_system(WATCH_FOLDER)
    except Exception as e:
        print(f"[ERROR] Startup failed: {e}")
        return

    if args.verify:
        summary = verify_all_files(WATCH_FOLDER)
        print("Verification summary:")
        print(json.dumps({k: len(v) if isinstance(v, list) else v for k, v in summary.items()}, indent=2))
        return

    # Initial scan (register existing files if not present)
    handler = IntegrityHandler()
    # If no records exist, or some missing, do an initial scan to populate baseline
    if not handler.records:
        append_log("Initial records empty — performing initial_scan via verify_all_files()")
        verify_all_files(WATCH_FOLDER)
        handler.records = load_hash_records()

    observer = Observer()
    observer.schedule(handler, WATCH_FOLDER, recursive=True)
    observer.start()
    append_log("🚀 Real-time integrity monitor started")
    print("Monitoring:", WATCH_FOLDER)
    print("Press Ctrl+C to stop. Use --verify to run full check only.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        append_log("🛑 Monitor stopped by user.")
    observer.join()

if __name__ == "__main__":
    main()
