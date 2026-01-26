# phase_2_secure_monitor_fixed.py
"""
Secure File Integrity Monitor — Phase 2 (fixed)
Features:
- Real-time monitoring (watchdog) with clear console logs
- Optional webhook (disabled by default)
- HMAC-signed hash_records.json (hash_records.sig)
- HMAC-signed integrity_log.txt (integrity_log.sig)
- Atomic save of records + signature
- Periodic verification: (a) check on-disk HMAC vs sig, (b) scan files for hash mismatches
- CLI: --verify for one-shot verify + exit
- Clean logging with better file filtering
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
LOG_SIG_FILE = "integrity_log.sig"
WEBHOOK_URL = None  # set your webhook URL string to enable
SECRET_KEY = b"Lisa_cutie_baby"  # set via env in prod
VERIFY_INTERVAL = 60  # seconds for testing; set 1800 (30m) in real run

# Enhanced ignore patterns - both filenames and patterns
IGNORE_FILENAMES = ["hash_records.json", "integrity_log.txt", "hash_records.sig", "integrity_log.sig"]
IGNORE_PATTERNS = [".tmp", ".temp", "~RF", "~$", ".~tmp", ".cache", ".log"]
HASH_ALGO = "sha256"

# File access retry settings
MAX_RETRIES = 3
RETRY_DELAY = 0.5  # seconds
# ----------------------------------------

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def should_ignore_file(filepath):
    """Check if file should be ignored based on name and patterns"""
    filename = os.path.basename(filepath)
    
    # Check exact filenames
    if filename in IGNORE_FILENAMES:
        return True
    
    # Check patterns
    for pattern in IGNORE_PATTERNS:
        if pattern in filename:
            return True
    
    # Check if it's a temporary/hidden file
    if filename.startswith('~') or filename.startswith('.'):
        return True
    
    return False

def append_log_signature(line):
    """Append HMAC signature for a log line to the signature file"""
    try:
        # Only sign the message part (after timestamp)
        message_part = line.split(" - ", 1)[-1].strip() if " - " in line else line.strip()
        sig = hmac.new(SECRET_KEY, message_part.encode("utf-8"), hashlib.sha256).hexdigest()
        with open(LOG_SIG_FILE, "a", encoding="utf-8") as f:
            f.write(sig + "\n")
    except Exception as e:
        print(f"⚠️ Failed to write log signature: {e}")

def append_log(msg):
    """Append message to log file with HMAC signature"""
    os.makedirs(os.path.dirname(os.path.abspath(LOG_FILE)), exist_ok=True)
    full_message = f"{now()} - {msg}"
    
    # Append to log file
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(full_message + "\n")
    
    # Create HMAC signature for this log entry
    append_log_signature(full_message)

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

# ---------- Log integrity verification ----------
def verify_log_integrity():
    """Verify the integrity of the log file using HMAC signatures"""
    if not os.path.exists(LOG_FILE) or not os.path.exists(LOG_SIG_FILE):
        if not os.path.exists(LOG_FILE) and not os.path.exists(LOG_SIG_FILE):
            # Both files don't exist - this is normal on first run
            return True
        elif os.path.exists(LOG_FILE) and not os.path.exists(LOG_SIG_FILE):
            # Log file exists but signature doesn't - possible tampering
            msg = "🚨 ALERT: Log signature file missing — possible tampering!"
            print_and_log(msg)
            send_webhook("LOG_TAMPER", msg, LOG_FILE)
            return False
        else:
            # Signature exists but log doesn't - also suspicious
            msg = "🚨 ALERT: Log file missing but signature exists — possible tampering!"
            print_and_log(msg)
            send_webhook("LOG_TAMPER", msg, LOG_SIG_FILE)
            return False

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as log, open(LOG_SIG_FILE, "r", encoding="utf-8") as sig:
            log_lines = log.readlines()
            sig_lines = sig.readlines()

            if len(log_lines) != len(sig_lines):
                msg = "🚨 ALERT: Log file length mismatch — possible tampering!"
                print_and_log(msg)
                send_webhook("LOG_TAMPER", msg, LOG_FILE)
                return False

            for i, (line, sig_value) in enumerate(zip(log_lines, sig_lines)):
                # Extract just the message part for verification (everything after timestamp)
                line = line.strip()
                if " - " in line:
                    message_part = line.split(" - ", 1)[-1]
                else:
                    message_part = line
                
                recalculated = hmac.new(SECRET_KEY, message_part.encode("utf-8"), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(recalculated, sig_value.strip()):
                    msg = f"🚨 ALERT: Log file content tampered at line {i+1}!"
                    print_and_log(msg)
                    send_webhook("LOG_TAMPER", msg, LOG_FILE)
                    return False
        return True
    except Exception as e:
        msg = f"🚨 ALERT: Error during log integrity verification: {e}"
        print_and_log(msg)
        send_webhook("LOG_TAMPER", msg, LOG_FILE)
        return False

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
    """Generate hash with retry logic for file access"""
    for attempt in range(MAX_RETRIES):
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
            if attempt == MAX_RETRIES - 1:  # Last attempt
                append_log(f"⚠️ Access denied after {MAX_RETRIES} attempts: {os.path.basename(path)}")
                return None
            time.sleep(RETRY_DELAY)
        except Exception as e:
            if attempt == MAX_RETRIES - 1:  # Last attempt
                append_log(f"ERROR hashing {os.path.basename(path)}: {e}")
                return None
            time.sleep(RETRY_DELAY)
    return None

# ---------- load/save records ----------
def load_hash_records_from_disk():
    """Load hash records with better error handling"""
    if not os.path.exists(HASH_RECORD_FILE):
        # create empty file
        atomic_write_json(HASH_RECORD_FILE, {})
        atomic_write_text(HASH_SIGNATURE_FILE, "")
        return {}
    
    try:
        with open(HASH_RECORD_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
            else:
                append_log("WARNING: hash_records.json structure invalid - recreating")
                return {}
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        append_log(f"WARNING: hash_records.json corrupted ({e}) - recreating")
        # Backup corrupted file
        if os.path.exists(HASH_RECORD_FILE):
            backup_name = f"{HASH_RECORD_FILE}.backup.{int(time.time())}"
            try:
                os.rename(HASH_RECORD_FILE, backup_name)
                append_log(f"Backed up corrupted file to {backup_name}")
            except:
                pass
        # Create new empty file
        atomic_write_json(HASH_RECORD_FILE, {})
        atomic_write_text(HASH_SIGNATURE_FILE, "")
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
        # Verify log integrity first
        if not verify_log_integrity():
            print("⚠️ Log integrity check failed on startup!")
        else:
            print("✅ Log integrity verified on startup.")
        
        # load in-memory records from disk
        self.records = load_hash_records_from_disk()
        print_and_log(f"Loaded records (in-memory): {len(self.records)}")
        
        # immediately check signature on disk
        ok = check_on_disk_signature()
        if ok:
            print_and_log("HMAC signature OK on startup.")
        else:
            print_and_log("HMAC signature FAILED on startup.")
        
        # run initial scan to populate missing entries
        self.initial_scan()

    def save_records(self):
        save_hash_records_to_disk(self.records)

    def initial_scan(self):
        print_and_log("🔍 Performing initial folder scan...")
        changed = False
        scanned_count = 0
        ignored_count = 0
        
        for root, _, files in os.walk(WATCH_FOLDER):
            for name in files:
                path = os.path.abspath(os.path.join(root, name))
                
                if should_ignore_file(path):
                    ignored_count += 1
                    continue
                
                scanned_count += 1
                if path not in self.records:
                    h = generate_hash(path)
                    if h:
                        self.records[path] = {"hash": h, "last_checked": now()}
                        append_log(f"INITIALIZED: {os.path.basename(path)}")
                        changed = True
        
        if changed:
            self.save_records()
            print_and_log(f"Initial scan complete: {scanned_count} files scanned, {ignored_count} ignored, {len([k for k in self.records if not should_ignore_file(k)])} files tracked")
        else:
            print_and_log(f"Initial scan complete: {scanned_count} files scanned, {ignored_count} ignored, no new files added")

    def update_record(self, path, new_hash):
        self.records[path] = {"hash": new_hash, "last_checked": now()}
        self.save_records()

    def handle_file_event(self, event_type, path, is_directory=False):
        """Common handler for file events with clean logging"""
        if is_directory:
            return
        
        if should_ignore_file(path):
            return
            
        filename = os.path.basename(path)
        
        if event_type == "CREATED":
            h = generate_hash(path)
            if h:
                self.update_record(path, h)
                print_and_log(f"📄 CREATED: {filename}")
                send_webhook("CREATED", "New file created", path)
                
        elif event_type == "MODIFIED":
            h = generate_hash(path)
            if not h:
                return
            old = self.records.get(path, {}).get("hash")
            if not old:
                # previously untracked (treat as created)
                self.update_record(path, h)
                print_and_log(f"📝 CREATED (modified): {filename}")
                send_webhook("CREATED_ON_MODIFY", "Untracked file observed on modify", path)
            elif old != h:
                self.update_record(path, h)
                print_and_log(f"✏️ MODIFIED: {filename}")
                send_webhook("MODIFIED", "File content changed", path)
                
        elif event_type == "DELETED":
            if path in self.records:
                print_and_log(f"🗑️ DELETED: {filename}")
                del self.records[path]
                self.save_records()
                send_webhook("DELETED", "File deleted", path)
            else:
                print_and_log(f"🗑️ DELETED (untracked): {filename}")
                send_webhook("DELETED_UNTRACKED", "Untracked file deleted", path)

    # explicit event handlers
    def on_created(self, event):
        self.handle_file_event("CREATED", os.path.abspath(event.src_path), event.is_directory)

    def on_modified(self, event):
        self.handle_file_event("MODIFIED", os.path.abspath(event.src_path), event.is_directory)

    def on_deleted(self, event):
        self.handle_file_event("DELETED", os.path.abspath(event.src_path), event.is_directory)

# ---------- Periodic verifier ----------
def periodic_verifier(handler):
    while True:
        time.sleep(VERIFY_INTERVAL)
        print_and_log("🧭 Periodic verification starting...")
        
        # 1) Verify log integrity
        if not verify_log_integrity():
            print_and_log("⚠️ Log integrity check failed during periodic verification!")
        
        # 2) verify on-disk signature (so external edits get caught)
        ok = check_on_disk_signature()
        if not ok:
            # if tampering detected, do not continue automatic repair; alert done above
            continue
            
        # 3) load latest on-disk records (should match in-memory if no tamper)
        on_disk = load_hash_records_from_disk()
        
        # 4) scan each recorded path and verify hashes
        verified_count = 0
        issues_count = 0
        
        for path, meta in list(on_disk.items()):
            if should_ignore_file(path):
                continue
                
            if not os.path.exists(path):
                filename = os.path.basename(path)
                print_and_log(f"❌ MISSING: {filename}")
                send_webhook("MISSING", "File missing during periodic check", path)
                # delete from records and save
                handler.records.pop(path, None)
                handler.save_records()
                issues_count += 1
                continue
                
            new_h = generate_hash(path)
            if new_h and new_h != meta.get("hash"):
                filename = os.path.basename(path)
                print_and_log(f"🚨 TAMPERED: {filename}")
                send_webhook("TAMPERED", "Hash mismatch on periodic check", path)
                # update record to new hash (so we don't repeatedly alert on same change)
                handler.update_record(path, new_h)
                issues_count += 1
            elif new_h:
                verified_count += 1
                
        if issues_count == 0:
            print_and_log(f"✅ Periodic verification complete: {verified_count} files verified, no issues found")
        else:
            print_and_log(f"⚠️ Periodic verification complete: {verified_count} files verified, {issues_count} issues found")

# ---------- CLI / main ----------
def main():
    global WATCH_FOLDER, WEBHOOK_URL, VERIFY_INTERVAL
    parser = argparse.ArgumentParser(description="Secure File Integrity Monitor (Phase2 fixed)")
    parser.add_argument("--verify", action="store_true", help="Run one-shot full verify and exit")
    parser.add_argument("--watch", type=str, default=WATCH_FOLDER, help="Folder to watch (overrides default)")
    parser.add_argument("--webhook", type=str, help="Enable webhook (override config)")
    parser.add_argument("--interval", type=int, help="Periodic verify interval in seconds")
    parser.add_argument("--verify-log", action="store_true", help="Verify log integrity and exit")
    args = parser.parse_args()

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

    if args.verify_log:
        # Verify only log integrity and exit
        if verify_log_integrity():
            print("✅ Log integrity verified successfully.")
        else:
            print("❌ Log integrity verification failed!")
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