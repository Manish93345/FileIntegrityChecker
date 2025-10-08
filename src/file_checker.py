# WORK FOR SINGLE FILE, CHECK WHETHER THE FILE IS TAMPERED OR NOT BY COMPAIRNG THE HASH VALUE

import json
import os
from hash_generator import generate_file_hash

HASH_RECORD_FILE = "hash_records.json"

def load_hash_records():
    if os.path.exists(HASH_RECORD_FILE):
        with open(HASH_RECORD_FILE, "r") as f:
            return json.load(f)
    return {}

def save_hash_records(records):
    with open(HASH_RECORD_FILE, "w") as f:
        json.dump(records, f, indent=4)

def check_file_integrity(file_path):
    records = load_hash_records()
    current_hash = generate_file_hash(file_path)

    if file_path in records:
        if records[file_path] == current_hash:
            print(f"✅ File '{file_path}' is safe and unchanged.")
        else:
            print(f"⚠️ File '{file_path}' has been modified or tampered!")
    else:
        print(f"ℹ️ New file detected. Storing its hash for future checks.")
    
    # Update or add record
    records[file_path] = current_hash
    save_hash_records(records)

if __name__ == "__main__":
    path = input("Enter file path: ")
    check_file_integrity(path)
