# 📘 Development Log — File Integrity Security Monitor

This document tracks the complete engineering journey of the project,  
from a simple hash checker to a production-ready security product with  
Endpoint Detection and Response (EDR) capabilities.

---

## 🗓️ Phase 0 — Foundations (Oct 2025)
- Project structure created
- Initial README written
- Basic hash generator for single file validation
- Single‑file integrity checker (store & compare hash)

---

## 🗓️ Phase 1 — Folder Monitoring (Oct 2025)
- Polling‑based folder monitor (detect create / modify / delete)
- Persistent hash storage (JSON) and event logging (plain text)
- Introduction of baseline snapshot for a monitored directory

---

## 🗓️ Phase 2 — Security Hardening (Oct 2025)
- HMAC protection for hash database to prevent tampering
- Periodic background verification thread
- Startup integrity checks (self‑audit of records)
- Optional webhook alerts for critical events
- Enhanced CLI controls (manual verify, interval settings)

---

## 🗓️ Phase 3 — Audit & Logs (Nov 2025)
- Tamper‑proof logging with HMAC signatures for log files
- Automatic log rotation (size‑based, with backup limits)
- Verification summary reports (JSON + human‑readable)
- Performance optimizations (chunked hashing, retry logic)

---

## 🗓️ Phase 4 — Configuration System (Nov 2025)
- External `config.json` for all settings (watch folder, secret key, webhook)
- Runtime configuration reload
- Separation of core logic from user‑facing interfaces

---

## 🗓️ Phase 5 — GUI Introduction (Nov 2025)
- Backend split into core engine and UI layers
- Command‑line interface (CLI) for terminal users
- Graphical interface (GUI) with:
  - Folder selection
  - Start/stop monitoring
  - Manual verification trigger
  - Live log feed

---

## 🗓️ Phase 6 — GUI & Reporting Enhancements (Dec 2025)
- Dark / Light theme toggle
- Icons and visual polish
- PDF report export with embedded charts (matplotlib, reportlab)
- Sliding status window for real‑time event summary
- In‑window alerts instead of pop‑ups

---

## 🗓️ Phase 7 — UX & Visual Intelligence (Dec 2025)
- Color‑coded alerts (INFO / MEDIUM / HIGH / CRITICAL)
- Dashboard widgets with live counters
- Improved user feedback (status banners, progress indicators)

---

## 🗓️ Phase 8 — Security Intelligence (Dec 2026)

### Phase 8.1 — Authentication
- User / Admin role separation
- Admin login alerts
- Password change logging
- Credential storage with hashing

### Phase 8.2 — Severity Engine
- Severity classification for all events
- Severity‑aware alerting (different webhook colors)

### Phase 8.3 — Auto Response & Safe Mode
- Automated actions per severity:
  - **INFO** → log only
  - **MEDIUM** → alert + log
  - **HIGH** → alert + incident snapshot
  - **CRITICAL** → Safe Mode (monitoring freeze, admin alert)
- Incident snapshot generation (mini‑report with last events)

---

## 🗓️ Phase 9 — Cleanup & Demo Mode (Jan 2026)
- Production‑ready folder structure (core, gui, config, reports, logs)
- Internal files hidden from casual view
- Demo simulation mode (fake events, tamper scenarios)
- Log archive & reset menu
- Interview‑ready demo assets (screenshots, videos)
- Fixed system tray bugs, logout issues, session restoration

---

## 🗓️ Phase 10 — Performance & Forensic Enhancements (Jan 2026)
- **Multithreaded hashing** – reduced scan time for large folders (119 GB from 2m18s → 1m5s)
- **Rename detection** – OS‑level move events captured and logged
- **Hidden file tracking** – Windows file attributes (hidden, system) now monitored
- **Atomic save handling** – debounce timer prevents false alerts during file writes
- **Encryption at rest** – AES‑128 for logs, user database, and hash records (separate key per installation)
- **Audit log viewer** – on‑the‑fly decryption of encrypted `.dat` logs inside GUI

---

## 🗓️ Phase 11 — Active Defense & Automated Response (Feb 2026)
- **Auto‑Healing Vault**:
  - Selective backup of small, critical files (size & extension filters)
  - Encrypted, hidden vault in AppData
  - Instant restoration on modification or deletion
- **Ransomware Killswitch**:
  - Burst detection (≥5 files modified in 10s) triggers OS‑level folder lockdown (icacls)
  - Strips write/modify permissions, paralyzing encryption attempts
- **Honeypot Tripwire**:
  - Fake file monitored
  - Any access instantly detonates killswitch and alerts admin

---

## 🗓️ Phase 12 — Enterprise Readiness (Feb 2026)
- **Webhook & Email Alerting**:
  - Rich embed alerts for Slack/Discord (color‑coded)
  - SMTP email alerts for compliance trail
- **Cloud Disaster Recovery** (Google Drive Sync):
  - OAuth 2.0 authentication
  - Per‑user encrypted cloud vaults
  - Two‑tier restore (local vault → cloud rescue)
- **Google OAuth Login** (optional):
  - “Continue with Google” for seamless authentication
- **Watchdog Stealth Mode**:
  - Background process that resurrects main app if killed
  - Stateful recovery (auto‑login and resume monitoring)
- **USB Device Control**:
  - Real‑time detection of USB insertion
  - Forced read‑only or eject via Windows Registry (DLP)

---

## 🗓️ Phase 13 — Admin UX & Hardening (Feb 2026)
- **Profile Panel** – user info, license status, subscription management
- **Password‑Protected Controls** – Stop Monitoring and Settings now require admin password
- **License System**:
  - Offline license generation with HMAC signing
  - PRO feature unlocking (Active Defense, Cloud Sync, etc.)
- **First‑Time Setup** – registration screen with email OTP verification
- **One‑Time Password (OTP)** – SMTP‑based for password recovery / registration

---


## For exe file 
  ### Run it in terminal
  pyinstaller run.py `
  --onedir `
  --noconsole `
  --name SecureFIM `
  --icon=assets/icons/app_icon.ico `
  --clean


pyinstaller run.py --onedir --noconsole --name SecureFIM --icon=assets/icons/app_icon.ico --clean --add-data "credentials.json;."
pyinstaller --onedir --noconsole --name WinSysHost sys_watchdog.py


pyinstaller run.py --onedir --noconsole --name SecureFIM --icon=assets/icons/app_icon.ico --clean --add-data "credentials.json;." --add-data "assets;assets"


pyinstaller run.py --onedir --noconsole --name SecureFIM --icon=assets/icons/app_icon.ico --add-data "assets;assets" --clean