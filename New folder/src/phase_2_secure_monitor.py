import os
import hashlib
import json
import threading
import time
import hmac
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import requests

# ---------------- CONFIG ----------------
WATCH_FOLDER = r"D:\Study\LISA_PROJECT\FileIntegrityChecker\tests"
HASH_RECORD_FILE = "hash_records.json"
HASH_SIGNATURE_FILE = "hash_records.sig"
LOG_FILE = "integrity_log.txt"
WEBHOOK_URL = "https://webhook.site/eeaa3926-d2da-4bd8-bd36-bf9994a4a5f2"  # replace with yours
# WEBHOOK_URL = "https://webhook.site/your_custom_url_here"  # replace with yours
SECRET_KEY = b"Lisamerijaanu"  # change for your project
VERIFY_INTERVAL = 60  # 30 minutes
# ----------------------------------------

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def append_log(line):
    with open(LOG_FILE, "a",encoding="utf-8") as f:
        f.write(f"{now()} - {line}\n")

def send_webhook_alert(event_type, message, file_path=None):
    data = {
        "timestamp": now(),
        "event": event_type,
        "message": message,
        "file": file_path
    }
    try:
        requests.post(WEBHOOK_URL, json=data, timeout=5)
    except Exception as e:
        append_log(f"⚠️ Webhook send failed: {e}")

# --------------- HMAC FUNCTIONS ----------------
def generate_hmac(data_dict):
    json_bytes = json.dumps(data_dict, sort_keys=True).encode()
    return hmac.new(SECRET_KEY, json_bytes, hashlib.sha256).hexdigest()

def verify_hmac(data_dict, signature):
    expected_sig = generate_hmac(data_dict)
    return hmac.compare_digest(expected_sig, signature)

def save_hmac_signature(data):
    sig = generate_hmac(data)
    with open(HASH_SIGNATURE_FILE, "w") as f:
        f.write(sig)

def load_hmac_signature():
    if os.path.exists(HASH_SIGNATURE_FILE):
        with open(HASH_SIGNATURE_FILE, "r") as f:
            return f.read().strip()
    return None

# ---------------- HASH UTILITIES ----------------
def generate_hash(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except (PermissionError, FileNotFoundError) as e:
        append_log(f"⚠️ Skipped {path} ({e})")
        return None

def load_hash_records():
    if os.path.exists(HASH_RECORD_FILE):
        with open(HASH_RECORD_FILE, "r") as f:
            return json.load(f)
    return {}

def save_hash_records(data):
    with open(HASH_RECORD_FILE, "w") as f:
        json.dump(data, f, indent=4)
    save_hmac_signature(data)

# ---------------- EVENT HANDLER ----------------
class IntegrityHandler(FileSystemEventHandler):
    def __init__(self):
        self.records = load_hash_records()
        self.verify_record_integrity()
        self.initial_scan()

    def verify_record_integrity(self):
        saved_sig = load_hmac_signature()
        if not saved_sig:
            append_log("⚠️ No previous HMAC signature found. Creating new one.")
            save_hmac_signature(self.records)
        elif not verify_hmac(self.records, saved_sig):
            append_log("🚨 ALERT: hash_records.json integrity FAILED!")
            send_webhook_alert("INTEGRITY_FAIL", "hash_records.json tampered!")

    def initial_scan(self):
        append_log("🔍 Performing initial folder scan...")
        for root, _, files in os.walk(WATCH_FOLDER):
            for name in files:
                path = os.path.join(root, name)
                file_hash = generate_hash(path)
                if file_hash:
                    self.records[path] = {"hash": file_hash, "last_checked": now()}
        save_hash_records(self.records)
        append_log("✅ Initial scan complete!")

    def update_record(self, path, new_hash):
        self.records[path] = {"hash": new_hash, "last_checked": now()}
        save_hash_records(self.records)

    def on_any_event(self, event):
        if event.is_directory:
            return
        path = os.path.abspath(event.src_path)

        if event.event_type == "created":
            file_hash = generate_hash(path)
            if file_hash:
                self.update_record(path, file_hash)
                append_log(f"CREATED: {path}")
                send_webhook_alert("CREATED", "New file created", path)

        elif event.event_type == "modified":
            new_hash = generate_hash(path)
            old_hash = self.records.get(path, {}).get("hash")
            if new_hash and old_hash and new_hash != old_hash:
                append_log(f"MODIFIED: {path}")
                send_webhook_alert("MODIFIED", "File content changed", path)
                self.update_record(path, new_hash)

        elif event.event_type == "deleted":
            if path in self.records:
                append_log(f"DELETED: {path}")
                send_webhook_alert("DELETED", "File deleted", path)
                del self.records[path]
                save_hash_records(self.records)

# ---------------- PERIODIC VERIFICATION ----------------
def periodic_verifier(handler):
    while True:
        time.sleep(VERIFY_INTERVAL)
        append_log("🧭 Running periodic verification...")
        modified_files = []
        for path, meta in handler.records.copy().items():
            if not os.path.exists(path):
                append_log(f"❌ Missing file detected: {path}")
                send_webhook_alert("MISSING", "File missing during periodic check", path)
                continue
            new_hash = generate_hash(path)
            if new_hash and new_hash != meta["hash"]:
                append_log(f"🚨 Tampered file detected: {path}")
                send_webhook_alert("TAMPERED", "File hash mismatch in periodic check", path)
                handler.update_record(path, new_hash)
                modified_files.append(path)
        append_log("✅ Periodic verification complete.")

# ---------------- MAIN EXECUTION ----------------
if __name__ == "__main__":
    append_log("🚀 Starting secure real-time integrity monitor...")
    handler = IntegrityHandler()
    observer = Observer()
    observer.schedule(handler, WATCH_FOLDER, recursive=True)
    observer.start()

    threading.Thread(target=periodic_verifier, args=(handler,), daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        append_log("🛑 Monitor stopped by user.")
    observer.join()
