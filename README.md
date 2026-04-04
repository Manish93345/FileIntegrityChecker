# 🛡️ FMSecure: Enterprise Endpoint Detection & Response (EDR)

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows_11-0078D6.svg)
![Build](https://img.shields.io/badge/Build-PyInstaller_%7C_InnoSetup-success.svg)
![Cloud](https://img.shields.io/badge/Cloud-FastAPI_%7C_Google_Drive_%7C_Railway-FF9900.svg)
![License](https://img.shields.io/badge/License-Commercial_SaaS-d29922.svg)
[![Made with Love](https://img.shields.io/badge/Made%20with-💖%20by%20Manish%20%26%20Lisa-pink)]()

**FMSecure** is a production-ready Windows Endpoint Detection and Response (EDR) agent paired with a live cloud Command & Control (C2) server. Built entirely in Python, it delivers real-time file integrity monitoring, cryptographic tamper detection, active ransomware defense, hardware-bound encryption, and consent-based cloud disaster recovery — the full stack from agent to SaaS billing.

---

## 📸 Demo

[![FMSecure Live Demo](https://img.youtube.com/vi/UVaUOYsSVss/0.jpg)](https://www.youtube.com/watch?v=UVaUOYsSVss)

**Live C2 Server:** https://fmsecure-c2-server-production.up.railway.app

---

# 🚀 Core Features

## 1. 🔍 File Integrity Monitoring
Real-time cryptographic surveillance of any monitored directory.

- **SHA-256 state hashing** — content hash combined with Windows file attributes and mtime. Detects not only content changes but hidden/system flag modifications invisible to basic FIMs.
- **Events detected**: Created, Modified, Deleted, Renamed, Attribute Changed (Hidden/System/ReadOnly)
- **Rename-aware**: distinguishes true user renames from editor "atomic save" patterns (no false alerts on VS Code / Photoshop saves)
- **Debounce engine**: 2-second stability window + file size check before hashing large transfers
- **Multithreaded baseline scan**: `concurrent.futures.ThreadPoolExecutor` — 119 GB scanned in ~65 seconds on NVMe hardware (1.83 GB/s sustained)
- **Periodic verification** background thread with configurable interval

---

## 2. 🚨 Severity Intelligence & Automated Response
Every event is classified, countered, and acted upon automatically.

| Severity | Trigger | Auto-Action |
|---|---|---|
| INFO | File created, monitor started | Log only |
| MEDIUM | File modified, deleted | Alert + log |
| HIGH | Multiple deletions, burst | Alert + incident snapshot |
| CRITICAL | Hash DB tampered, log tampered | Safe Mode + monitoring freeze |

- **Safe Mode**: lockdown flag file + monitoring freeze + admin alert
- **Incident Snapshots**: AES-encrypted `.dat` files with system state, disk info, process info, last 15 log lines — viewable only inside FMSecure

---

## 3. 🛑 Ransomware Killswitch & Behavioral Heuristics
OS-level defense that activates in milliseconds.

- **Burst detection**: ≥5 file modification events in 10 seconds triggers killswitch
- **OS lockdown**: `icacls` command strips Write/Delete/Modify permissions for Everyone on monitored directories — ransomware's encryption loop gets `Access Denied` at the kernel level
- **Honeypot Tripwire**: `secret_passwords.txt` in the monitored folder acts as a canary. Any access instantly detonates the killswitch and sends a CRITICAL alert
- **Remote Killswitch**: IT admin can isolate any endpoint from the cloud C2 dashboard

---

## 4. 🛡️ Active Defense — Auto-Healing Vault
Responds to threats without waiting for admin action.

- **Selective vaulting**: files < 10 MB with configurable extension allowlist (`.py`, `.json`, `.html`, `.js`, etc.)
- **Encrypted, hidden vault**: `AppData/system32_vault/`, filenames obfuscated as `SHA256(original_path).enc`
- **Instant restoration**: on modification or deletion, the clean file is restored from vault before the next event fires
- **Infinite-loop prevention**: content-hash comparison detects vault write-back events and ignores them

---

## 5. ☁️ Cloud Disaster Recovery (Google Drive OAuth 2.0)
Industry-grade key management and off-site backup.

### Hardware-Bound Encryption (KEK Architecture)
```
AES-256 master key (DEK)
    └── Encrypted by KEK (Key Encryption Key)
            └── KEK = PBKDF2(hostname + machine + processor, 200,000 iterations)
                    └── Never written to disk — re-derived from hardware on every boot
```
Stolen `sys.key` on any other machine → wrong KEK → permanently unreadable.

### Three-Layer Key Resilience
| Layer | Location | Format |
|---|---|---|
| Primary | `AppData/system32_config/sys.key` | KEK-encrypted, hidden |
| Shadow backup | `AppData/system32_shadow/.sys_backup.key` | KEK-encrypted, hidden |
| Cloud escrow | `Google Drive/FMSecure_{MACHINE_ID}/keys/` | KEK-encrypted (PRO) |

### Consent-Based Restore (The WhatsApp Pattern)
On reinstall, FMSecure never silently restores data. It:
1. Shows a loading screen while probing Drive in the background
2. Discovers both the active backup and all archived snapshots
3. Presents all options with date, account, and file counts
4. Waits for explicit user selection before downloading anything

### Google Drive Folder Structure
```
MASTER_FOLDER/
  FMSecure_{MACHINE_ID}/          ← active backup
    keys/                          ← KEK-encrypted key files
    vault/                         ← encrypted file vault blobs
    logs/                          ← audit logs + forensic snapshots
    appdata/                       ← users.dat, config.json, hash records
    folder_backup/                 ← complete directory tree backups
    manifest.json                  ← plaintext metadata (email, tier, last_sync)
  FMSecure_{MACHINE_ID}_Archive_YYYYMMDD_HHMMSS/   ← archived on "Start Fresh"
```

### Automatic Background Backup (PRO)
- Logs + forensics: every 15 minutes (if changed)
- Full AppData: every 6 hours
- Encryption keys: immediately after PRO activation

---

## 6. 🏢 Command & Control (C2) Fleet Management
Live visibility and remote control of all deployed endpoints.

- **Async FastAPI server** (Railway.app) — handles thousands of concurrent heartbeats
- **Real-time fleet table**: machine ID, hostname, username, IP, online/offline status, armed/unarmed
- **Remote Lockdown**: one click isolates any endpoint via heartbeat command channel
- **Agent heartbeat**: every 10 seconds, sends tier, armed status, hostname, machine_id

**Live dashboard**: https://fmsecure-c2-server-production.up.railway.app

---

## 7. 🔑 Commercial Licensing (SaaS Model)
Server-validated subscription following the CrowdStrike/SentinelOne pattern.

- License key validated against Railway PostgreSQL on each activation
- 24-hour AES-encrypted local cache for offline operation
- Graceful Free-tier degradation if server unreachable
- **License Transfer**: OTP-based device reassignment for users who reinstall
- **Key Recovery**: re-send lost key to purchase email (enumeration-safe)
- Tiers: `pro_monthly`, `pro_annual`

---

## 8. 👤 Authentication & Access Control
Multi-layer identity with zero-trust principles.

- **Admin / User role separation** — read-only viewer mode requires no credentials
- **Manual auth**: SHA-256 + salt password hashing, brute-force lockout (3 attempts, 30s)
- **Google SSO**: OAuth 2.0 with email allowlist + device PIN as second factor
- **Password-protected controls**: Stop Monitor, Settings, and Lockdown Disable require re-authentication
- **Email OTP**: registration verification and password recovery via SMTP pipeline

---

## 9. 🔌 Data Loss Prevention (DLP)
Prevents unauthorized data exfiltration at the hardware layer.

- Windows Registry `HKLM\System\CurrentControlSet\Control\StorageDevicePolicies\WriteProtect`
- Forces all USB mass storage to Read-Only mode — files cannot be copied out
- PRO feature, requires Administrator privileges (UAC manifest enforced in compiled EXE)

---

## 10. 👻 Self-Healing Watchdog Process
The agent cannot be killed by a threat actor.

- Separate stealth process (`WinSysHost.exe`) monitors the main agent
- If main process is terminated (Task Manager, malware), Watchdog resurrects it in 2 seconds
- Resurrection passes `--recovery` flag → bypasses login → auto-starts monitoring → hides to tray
- Stateful recovery: previous watch folders, monitoring state, and settings are preserved

---

## 11. 📊 Reporting & Forensics
Complete audit trail with cryptographic integrity guarantees.

- **Encrypted audit logs**: AES-256 encrypted `.dat` files, decrypted on-the-fly inside GUI only
- **HMAC log integrity**: per-line HMAC signature, auto-heals missing signatures
- **PDF reports**: embedded charts (matplotlib), severity summary, file change lists (ReportLab)
- **Forensic Incident Vault**: encrypted snapshots viewable only inside FMSecure
- **Log archive**: session archive with encrypted history viewer
- **Severity counters**: thread-safe in-memory cache with disk persistence

---

# 🏗️ Technical Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    FMSecure Desktop Agent                    │
│                                                             │
│  integrity_core.py    ← watchdog + hashing + HMAC          │
│  vault_manager.py     ← AES vault + auto-heal              │
│  encryption_manager.py← KEK + cloud key escrow             │
│  cloud_sync.py        ← Google Drive OAuth2 + batch upload │
│  auth_manager.py      ← users.dat + license activation     │
│  license_verifier.py  ← server validation + local cache    │
│  safe_mode.py         ← lockdown flag + monitoring freeze  │
│  lockdown_manager.py  ← icacls OS permission control       │
│  sys_watchdog.py      ← self-healing stealth process       │
└─────────────────────────────────────────────────────────────┘
                              │ HTTPS heartbeat (10s)
                              ▼
┌─────────────────────────────────────────────────────────────┐
│           FMSecure C2 Server (Railway FastAPI)               │
│                                                             │
│  /api/heartbeat          ← agent telemetry                  │
│  /api/trigger_lockdown   ← remote isolation command         │
│  /api/license/validate   ← server-side license check       │
│  /api/license/request_transfer ← OTP device reassignment   │
│  /api/license/recover_key      ← lost key re-delivery      │
│  /dashboard              ← fleet management UI             │
│  PostgreSQL              ← license database                 │
└─────────────────────────────────────────────────────────────┘
                              │ OAuth 2.0
                              ▼
                    Google Drive API
                    (per-machine encrypted vaults)
```

---

# 🛠️ Installation & Build

## Run from Source

```bash
git clone https://github.com/Manish93345/FileIntegrityChecker.git
cd FMSecure

pip install -r requirements.txt

# Start the C2 server (separate terminal)
cd FMSecure_Cloud
uvicorn main:app --reload

# Run the desktop agent
python run.py
```

## Compile to Windows EXE

```powershell
# Stealth Watchdog
pyinstaller --onedir --noconsole --name WinSysHost sys_watchdog.py

# Main EDR Agent (UAC Admin elevation)
pyinstaller run.py --onedir --noconsole --name SecureFIM `
  --icon=assets/icons/app_icon.ico `
  --uac-admin `
  --add-data "assets;assets" `
  --clean
```

Use the provided `setup_config.iss` with **Inno Setup** to produce the final installer.


# 🔮 Future Scope

- **Network Isolation** — `netsh advfirewall` to physically sever LAN on Killswitch
- **ML Heuristics** — isolation forest model replacing static burst threshold
- **Memory Scanning** — API hooking to detect fileless malware in RAM
- **bcrypt Password Hashing** — upgrade from SHA-256 + salt
- **Public/Private Key License Signing** — eliminate HMAC-only forgery risk

---

## 👨‍💻 Author

Developed by **Manish** as a comprehensive study in Systems Architecture, OS-Level Security, and Enterprise Cybersecurity product engineering — from a single hash checker to a full SaaS EDR platform with live cloud infrastructure, commercial licensing, and hardware-bound encryption.