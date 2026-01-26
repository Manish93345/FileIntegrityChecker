import os
import hashlib
import json
import time
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

WATCH_FOLDER = r"D:\Study\LISA_PROJECT\FileIntegrityChecker\tests"
HASH_RECORD_FILE = "hash_records.json"
LOG_FILE = "integrity_log.txt"

# ==========================
# Helper Functions
# ==========================
def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def append_log(message):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{now()} - {message}\n")

def generate_hash(file_path, retries=3, delay=0.5):
    """Generate SHA256 hash with retry mechanism."""
    for attempt in range(retries):
        try:
            with open(file_path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except (PermissionError, FileNotFoundError) as e:
            if attempt < retries - 1:
                time.sleep(delay)
            else:
                append_log(f"⚠️ Skipped {file_path} ({e})")
                return None

def load_hash_records():
    if not os.path.exists(HASH_RECORD_FILE):
        with open(HASH_RECORD_FILE, "w") as f:
            json.dump({}, f)
    with open(HASH_RECORD_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}

def save_hash_records(data):
    with open(HASH_RECORD_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

def initial_scan(records):
    append_log("🔍 Performing initial folder scan...")
    for root, _, files in os.walk(WATCH_FOLDER):
        for file in files:
            path = os.path.abspath(os.path.join(root, file))
            file_hash = generate_hash(path)
            if file_hash:
                records[path] = {"hash": file_hash, "last_checked": now()}
    save_hash_records(records)
    append_log("✅ Initial scan complete!")

# ==========================
# Event Handler
# ==========================
class IntegrityHandler(FileSystemEventHandler):
    def __init__(self):
        self.records = load_hash_records()

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

        elif event.event_type == "modified":
            new_hash = generate_hash(path)
            old_hash = self.records.get(path, {}).get("hash")
            if new_hash and old_hash and new_hash != old_hash:
                append_log(f"MODIFIED: {path}")
                self.update_record(path, new_hash)

        elif event.event_type == "deleted":
            if path in self.records:
                append_log(f"DELETED: {path}")
                del self.records[path]
                save_hash_records(self.records)
            else:
                append_log(f"DELETED (untracked): {path}")

# ==========================
# Main Execution
# ==========================
if __name__ == "__main__":
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            f.write(f"{now()} - Log started\n")

    append_log("🚀 Starting real-time integrity monitor...")

    handler = IntegrityHandler()
    initial_scan(handler.records)

    observer = Observer()
    observer.schedule(handler, WATCH_FOLDER, recursive=True)
    observer.start()
    print("🔍 Real-time integrity monitor started... (Press Ctrl+C to stop)")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        append_log("🛑 Monitor stopped by user.")
    observer.join()
