# WORKS FOR THE ENTIRE FOLDER, AS FOR NOW, THE TESTS FOLDER IS ADDED IN IT

import time
import os
import json
from datetime import datetime
from hash_generator import generate_file_hash
from datetime import datetime, timezone

HASH_RECORD_FILE = "hash_records.json"
LOG_FILE = "integrity_log.txt"
MONITOR_FOLDERS = [
    r"D:\Study\LISA_PROJECT\FileIntegrityChecker\tests"
]
POLL_INTERVAL = 30  # seconds

def now_iso():
    return datetime.now().strftime("%Y-%m-%d %I:%M:%S %p")

def load_hash_records():
    if os.path.exists(HASH_RECORD_FILE):
        with open(HASH_RECORD_FILE, "r") as f:
            data = json.load(f)

            # Convert old string hashes to dictionary format
            for k, v in list(data.items()):
                if isinstance(v, str):
                    data[k] = {
                        "hash": v,
                        "last_checked": None,
                        "last_changed": None,
                        "missing": False
                    }
            return data
    return {}


def save_hash_records(records):
    with open(HASH_RECORD_FILE, "w") as f:
        json.dump(records, f, indent=4)

def append_log(line):
    with open(LOG_FILE, "a") as f:
        f.write(f"{now_iso()} - {line}\n")

def scan_and_check(folders):
    records = load_hash_records()
    seen_paths = set()

    for folder in folders:
        for root, dirs, files in os.walk(folder):
            for fname in files:
                fpath = os.path.abspath(os.path.join(root, fname))
                seen_paths.add(fpath)
                try:
                    current_hash = generate_file_hash(fpath)
                except Exception as e:
                    append_log(f"ERROR reading {fpath}: {e}")
                    continue

                rec = records.get(fpath)
                if not rec:
                    records[fpath] = {
                        "hash": current_hash,
                        "last_checked": now_iso(),
                        "last_changed": None,
                        "missing": False
                    }
                    append_log(f"NEW file added: {fpath}")
                else:
                    if rec["hash"] != current_hash:
                        append_log(f"CHANGED: {fpath}")
                        rec["hash"] = current_hash
                        rec["last_changed"] = now_iso()
                        rec["last_checked"] = now_iso()
                    else:
                        rec["last_checked"] = now_iso()

                if rec:
                    if rec["hash"] != current_hash:
                        ...
                    else:
                        rec["last_checked"] = now_iso()
                    records[fpath] = rec


    # detect deleted files
    for path in list(records.keys()):
        if path not in seen_paths:
            append_log(f"REMOVED/MISSING: {path}")
            records[path]["missing"] = True
            records[path]["last_checked"] = now_iso()

    save_hash_records(records)

def run_monitor():
    print("Starting polling folder monitor. Press Ctrl+C to stop.")
    try:
        while True:
            scan_and_check(MONITOR_FOLDERS)
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print("Monitor stopped by user.")

if __name__ == "__main__":
    run_monitor()
