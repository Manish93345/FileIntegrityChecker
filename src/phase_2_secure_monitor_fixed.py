# phase_2_secure_monitor_fixed.py
"""
Secure File Integrity Monitor — Phase 2 (fixed)
Features:
- Real-time monitoring (watchdog) with clear console logs
- Optional webhook (disabled by default)
- HMAC-signed hash_records.json (hash_records.sig)
- Atomic save of records + signature
- Periodic verification: (a) check on-disk HMAC vs sig, (b) scan files for hash mismatches
- CLI: --verify for one-shot verify + exit
"""

import os
import json
import time
import hashlib
import threading
import argparse
import hmac
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

try:
    import requests
except Exception:
    requests = None  # webhook optional

# ---------------- CONFIG ----------------
WATCH_FOLDER = r"D:\Study\LISA_PROJECT\FileIntegrityChecker\tests"
HASH_RECORD_FILE = "hash_records.json"
HASH_SIGNATURE_FILE = "hash_records.sig"
LOG_FILE = "integrity_log.txt"
WEBHOOK_URL = None  # set your webhook URL string to enable
SECRET_KEY = b"Lisa_cutie_baby"  # set via env in prod
VERIFY_INTERVAL = 60  # seconds for testing; set 1800 (30m) in real run
IGNORE_FILENAMES = ["hash_records.json", "integrity_log.txt"]
HASH_ALGO = "sha256"
# ----------------------------------------

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def append_log(msg):
    os.makedirs(os.path.dirname(os.path.abspath(LOG_FILE)), exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{now()} - {msg}\n")

def print_and_log(msg):
    print(msg)
    append_log(msg)

def send_webhook(event_type, message, file_path=None):
    if not WEBHOOK_URL:
        return
    if requests is None:
        append_log(f"ALERT (webhook requested but requests not installed): {event_type} {file_path}")
        return
    payload = {"timestamp": now(), "event": event_type, "message": message, "file": file_path}
    try:
        requests.post(WEBHOOK_URL, json=payload, timeout=5)
    except Exception as e:
        append_log(f"⚠️ Webhook failed: {e}")

# ---------- HMAC helpers ----------
def generate_hmac(data_dict):
    raw = json.dumps(data_dict, sort_keys=True).encode("utf-8")
    return hmac.new(SECRET_KEY, raw, hashlib.sha256).hexdigest()

def verify_hmac(data_dict, sig):
    return hmac.compare_digest(generate_hmac(data_dict), sig)

# ---------- atomic file write ----------
def atomic_write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=4)
    os.replace(tmp, path)

def atomic_write_text(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)

# ---------- hash functions ----------
def generate_hash(path, chunk_size=65536):
    try:
        h = hashlib.new(HASH_ALGO)
        with open(path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError) as e:
        append_log(f"⚠️ Skipped hashing {path} ({e})")
        return None
    except Exception as e:
        append_log(f"ERROR hashing {path}: {e}")
        return None

# ---------- load/save records ----------
def load_hash_records_from_disk():
    if not os.path.exists(HASH_RECORD_FILE):
        # create empty file
        atomic_write_json(HASH_RECORD_FILE, {})
        atomic_write_text(HASH_SIGNATURE_FILE, "")
        return {}
    try:
        with open(HASH_RECORD_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else dict(data)
    except json.JSONDecodeError:
        append_log("WARNING: hash_records.json corrupted — returning empty dict")
        return {}

def save_hash_records_to_disk(records):
    # atomic write records then signature
    atomic_write_json(HASH_RECORD_FILE, records)
    sig = generate_hmac(records)
    atomic_write_text(HASH_SIGNATURE_FILE, sig)

def load_signature():
    if not os.path.exists(HASH_SIGNATURE_FILE):
        return ""
    try:
        with open(HASH_SIGNATURE_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return ""

# ---------- integrity check of on-disk records ----------
def check_on_disk_signature():
    records_on_disk = load_hash_records_from_disk()
    sig = load_signature()
    if not sig:
        # no signature exists yet
        append_log("No signature file found on disk; creating one now.")
        save_hash_records_to_disk(records_on_disk)
        return True
    if not verify_hmac(records_on_disk, sig):
        # mismatch detected
        msg = "🚨 ALERT: hash_records.json HMAC mismatch — possible tampering!"
        print_and_log(msg)
        send_webhook("INTEGRITY_FAIL", msg, HASH_RECORD_FILE)
        return False
    return True

# ---------- Event Handler ----------
class IntegrityHandler(FileSystemEventHandler):
    def __init__(self):
        # load in-memory records from disk
        self.records = load_hash_records_from_disk()
        print_and_log("Loaded records (in-memory): {}".format(len(self.records)))
        # immediately check signature on disk
        ok = check_on_disk_signature()
        if ok:
            print_and_log("HMAC signature OK on startup.")
        else:
            print_and_log("HMAC signature FAILED on startup.")
        # run initial scan to populate missing entries (but do NOT overwrite if on-disk signature failed)
        self.initial_scan()

    def save_records(self):
        save_hash_records_to_disk(self.records)

    def initial_scan(self):
        print_and_log("🔍 Performing initial folder scan...")
        changed = False
        for root, _, files in os.walk(WATCH_FOLDER):
            for name in files:
                if any(ig in name for ig in IGNORE_FILENAMES):
                    continue
                path = os.path.abspath(os.path.join(root, name))
                if path not in self.records:
                    h = generate_hash(path)
                    if h:
                        self.records[path] = {"hash": h, "last_checked": now()}
                        append_log(f"INITIALIZED: {path}")
                        changed = True
        if changed:
            self.save_records()
            print_and_log("Initial scan added missing files and saved records.")
        else:
            print_and_log("Initial scan complete — no new files added.")

    def update_record(self, path, new_hash):
        self.records[path] = {"hash": new_hash, "last_checked": now()}
        self.save_records()

    # explicit event handlers for clarity & console output
    def on_created(self, event):
        if event.is_directory:
            return
        path = os.path.abspath(event.src_path)
        if any(ig in os.path.basename(path) for ig in IGNORE_FILENAMES):
            return
        h = generate_hash(path)
        if h:
            self.update_record(path, h)
            print_and_log(f"CREATED: {path}")
            send_webhook("CREATED", "New file created", path)

    def on_modified(self, event):
        if event.is_directory:
            return
        path = os.path.abspath(event.src_path)
        if any(ig in os.path.basename(path) for ig in IGNORE_FILENAMES):
            return
        h = generate_hash(path)
        if not h:
            return
        old = self.records.get(path, {}).get("hash")
        if not old:
            # previously untracked (treat as created)
            self.update_record(path, h)
            print_and_log(f"CREATED_ON_MODIFY: {path}")
            send_webhook("CREATED_ON_MODIFY", "Untracked file observed on modify", path)
        elif old != h:
            self.update_record(path, h)
            print_and_log(f"MODIFIED: {path}")
            send_webhook("MODIFIED", "File content changed", path)

    def on_deleted(self, event):
        if event.is_directory:
            return
        path = os.path.abspath(event.src_path)
        if path in self.records:
            print_and_log(f"DELETED: {path}")
            del self.records[path]
            self.save_records()
            send_webhook("DELETED", "File deleted", path)
        else:
            print_and_log(f"DELETED (untracked): {path}")
            send_webhook("DELETED_UNTRACKED", "Untracked file deleted", path)

# ---------- Periodic verifier ----------
def periodic_verifier(handler):
    while True:
        time.sleep(VERIFY_INTERVAL)
        print_and_log("🧭 Periodic verification starting...")
        # 1) verify on-disk signature (so external edits get caught)
        ok = check_on_disk_signature()
        if not ok:
            # if tampering detected, do not continue automatic repair; alert done above
            continue
        # 2) load latest on-disk records (should match in-memory if no tamper)
        on_disk = load_hash_records_from_disk()
        # 3) scan each recorded path and verify hashes
        for path, meta in list(on_disk.items()):
            if any(ig in path for ig in IGNORE_FILENAMES):
                continue
            if not os.path.exists(path):
                print_and_log(f"❌ Missing file during periodic check: {path}")
                send_webhook("MISSING", "File missing during periodic check", path)
                # delete from records and save
                handler.records.pop(path, None)
                handler.save_records()
                continue
            new_h = generate_hash(path)
            if new_h and new_h != meta.get("hash"):
                print_and_log(f"🚨 Tampered file detected during periodic check: {path}")
                send_webhook("TAMPERED", "Hash mismatch on periodic check", path)
                # update record to new hash (so we don't repeatedly alert on same change)
                handler.update_record(path, new_h)
        print_and_log("✅ Periodic verification complete.")

# ---------- CLI / main ----------
def main():
    global WATCH_FOLDER, WEBHOOK_URL, VERIFY_INTERVAL
    parser = argparse.ArgumentParser(description="Secure File Integrity Monitor (Phase2 fixed)")
    parser.add_argument("--verify", action="store_true", help="Run one-shot full verify and exit")
    parser.add_argument("--watch", type=str, default=WATCH_FOLDER, help="Folder to watch (overrides default)")
    parser.add_argument("--webhook", type=str, help="Enable webhook (override config)")
    parser.add_argument("--interval", type=int, help="Periodic verify interval in seconds")
    args = parser.parse_args()

    # global WATCH_FOLDER, WEBHOOK_URL, VERIFY_INTERVAL
    WATCH_FOLDER = os.path.abspath(args.watch)
    if args.webhook:
        WEBHOOK_URL = args.webhook
    if args.interval:
        VERIFY_INTERVAL = args.interval

    print_and_log("🚀 Starting Phase-2 secure monitor (fixed)...")
    # basic checks
    if not os.path.exists(WATCH_FOLDER):
        print_and_log(f"[ERROR] Watch folder does not exist: {WATCH_FOLDER}")
        return

    handler = IntegrityHandler()

    if args.verify:
        # run a one-shot periodic check now and exit
        periodic_verifier(handler)
        return

    observer = Observer()
    observer.schedule(handler, WATCH_FOLDER, recursive=True)
    observer.start()
    # start periodic thread
    t = threading.Thread(target=periodic_verifier, args=(handler,), daemon=True)
    t.start()

    print("Monitoring:", WATCH_FOLDER)
    print("Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print_and_log("🛑 Monitor stopped by user.")
    observer.join()

if __name__ == "__main__":
    main()
