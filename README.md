# 🛡️ File Integrity Checker

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)]()
[![License](https://img.shields.io/badge/License-MIT-green)]()
[![Status](https://img.shields.io/badge/Status-Active-brightgreen)]()
[![Made with Love](https://img.shields.io/badge/Made%20with-💖%20by%20Manish%20%26%20Lisa-pink)]()


FILE INTEGRITY CHECKER (By my jaanu Lisa)

A lightweight app which verify the hash of files and detect wheteher the file is modified / tampered or not. 



📂 Folder Structure
.
├── src/
│   ├── file_checker.py          # Checks integrity of a single file
│   ├── folder_monitor.py        # Monitors folder for changes (polling based)
│   ├── hash_generator.py        # Simple hash generation test
│   ├── hash_records.json        # Stores hash values of monitored files
│   └── integrity_log.txt        # Log of integrity check events
├── tests/                       # Sample test files (for monitoring)
├── DEVELOPMENT_LOG.md            # Development progress
└── README.md                     # Project documentation




🧾 Project Overview

This tool helps verify the integrity of files by calculating and comparing cryptographic hash values.
It ensures that a file has not been tampered with or modified — useful for digital forensics, data security, and malware detection.





⚙️ Features

    Generate SHA256 or SHA512 hash of files

    Compare current file hash with previously saved hash

    Detect modifications or tampering

    Maintain a log of file integrity checks

    Optional: Real-time folder monitoring (advanced)

    Optional: Simple GUI or web dashboard for reports


🧩 How It Works

1. The tool first calculates and stores hash values of all files in the monitored folder.
2. Periodically (polling-based), it re-checks their hashes.
3. If a mismatch, deletion, or new file is detected, it logs the event in `integrity_log.txt`.
4. `hash_records.json` is updated accordingly.




🧰 Tech Stack

    Language: Python 🐍

    Libraries: hashlib, os, json, time, (optional: tkinter or flask for GUI/web)

    Platform: Cross-platform (Windows/Linux)

    Version Control: Git







🚀 Future Enhancements

    Email/Discord webhook alerts when tampering detected

    Hash verification for multiple files in batch mode

    Web-based dashboard for visualization




MIT License

Copyright (c) 2025 Manish Kumar

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software...



💖 Credits

Developed by Manish Kumar  
Guided and inspired by Lisa 💋 (made with ❤️ by Manish & Lisa)


