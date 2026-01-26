# 🛡️ File Integrity Security Monitor

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)]()
[![Status](https://img.shields.io/badge/Status-Production--Ready-brightgreen)]()
[![Security](https://img.shields.io/badge/Security-Cryptographic%20Integrity-red)]()
[![Made with Love](https://img.shields.io/badge/Made%20with-💖%20by%20Manish%20%26%20Lisa-pink)]()

---

## 🔐 Overview

**File Integrity Security Monitor** is a professional-grade desktop security tool that continuously monitors files and folders to detect **unauthorized changes, deletions, or tampering** using cryptographic verification.

The system is designed to behave like a **real-world security product**, not just a script — featuring severity-based alerts, auto-response, safe mode, demo simulation, and a modern GUI.

---

## 🎯 Key Use Cases

- Detect ransomware-style file modifications
- Monitor sensitive personal or enterprise folders
- Maintain audit trails for digital forensics
- Demonstrate real-time security monitoring in interviews
- Safe demo simulation without touching real files

---

## ⚙️ Core Features

### 🔍 File Integrity Monitoring
- Cryptographic hashing (SHA-256)
- Detects **Created / Modified / Deleted** files
- Real-time monitoring using watchdog

### 🚨 Severity Intelligence
- INFO — File created  
- MEDIUM — File modified  
- HIGH — Multiple deletions  
- CRITICAL — Hash database or log tampering  

### 🧠 Auto Response & Safe Mode
- Automated reactions based on severity
- Monitoring freeze on CRITICAL incidents
- Visual SAFE MODE alerts in GUI

### 🔐 Tamper-Proof Design
- HMAC signatures for:
  - `hash_records.json`
  - `integrity_log.txt`
- Detects if attacker edits logs or hash database

### 👤 Authentication & Access Control
- User Mode (read-only, safe)
- Admin Mode (full control)
- Admin login alerts
- Password change logging

### 📊 Reporting & Visualization
- Summary & detailed reports
- PDF export with charts
- Incident snapshot generation
- Log archive & history system

### 🎬 Demo Mode (Interview Friendly)
- Simulated security incidents
- No real files touched
- One-click live demonstration

---

## 🖥️ GUI Highlights

- Modern Tkinter-based dashboard
- Dark / Light theme toggle
- Live log feed
- Status banners & sliding alerts
- Menu-based extensibility

---

## 📂 Final Project Structure

.
├── core/
│   ├── auth_manager.py          
│   ├── auto_response.py        
│   ├── demo_simulator.py        
│   ├── incident_snapshot.py        
│   ├── integrity_core.py 
│   ├── safe_mode.py
│   ├── security_imports.py
│   └── severity_init.py      
├── assets/
│   └──icons/
│       └──All icons file here
├── cli/
│   └── integrity_cli.py
├── config/
│   └── config.json
├── gui/
│   ├── login_gui.py
│   └── integrity_gui.py
├── tests/                       # Sample test files (for monitoring)
├── DEVELOPMENT_LOG.md            # Development progress
├── README.md                     
└── run.py


▶️ How to Run

### GUI Mode

    python run.py
# or
    python run.py --gui

### GUI Mode
    python run.py --cli
    python run.py --cli --verify
    python run.py --cli --watch /path/to/folder


### LOGIN CREDENTIALS
    username: "admin"
    password: "admin123" or "lisajaanu"



🧾 Project Overview

This tool helps verify the integrity of files by calculating and comparing cryptographic hash values.
It ensures that a file has not been tampered with or modified — useful for digital forensics, data security, and malware detection.



🧰 Tech Stack

    Language: Python 3.11+
    GUI: Tkinter
    Security: hashlib, hmac
    Monitoring: watchdog
    Reports: reportlab, matplotlib
    Packaging: PyInstaller (Phase 10)


🧩 How It Works

1. The tool first calculates and stores hash values of all files in the monitored folder.
2. Periodically (polling-based), it re-checks their hashes.
3. If a mismatch, deletion, or new file is detected, it logs the event in `integrity_log.txt`.
4. `hash_records.json` is updated accordingly.




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


