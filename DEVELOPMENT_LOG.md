# 📘 Development Log — FMSecure: Enterprise EDR

This document tracks the complete engineering journey of the project,
from a simple file hash checker to a production-ready Endpoint Detection
and Response (EDR) platform with a live cloud Command & Control server,
server-validated licensing, and consent-based disaster recovery.

---

## 🗓️ Phase 0 — Foundations (Oct 2025)
- Project structure created, initial README written
- Basic hash generator for single-file validation (`hash_generation.py`)
- Single-file integrity checker — stores hash, detects tampering on re-run (`file_checker.py`)
- Polling-based folder monitor detecting create / modify / delete, writes `integrity_log.txt` and `hash_record.json`

---

## 🗓️ Phase 1 — Real-Time Monitoring (Oct 2025)
- Replaced polling with event-driven monitoring via `watchdog` library
- `realtime_monitor.py` — generates `hash_records.json` and `integrity_log.txt` on live events
- Chunked hashing with retry logic for `PermissionError` and transient file locks
- Optional webhook alert on any event if `WEBHOOK_URL` is configured

---

## 🗓️ Phase 2 — Security Hardening (Oct 2025)
- HMAC signature for `hash_records.json` — any external modification is immediately detected
- Periodic auto-verification background thread (configurable interval)
- Atomic save of records + signature — no partial-write window
- Smart log rotation (size-based with configurable backup count)
- Enhanced CLI: `--verify`, `--periodic`, `--check-integrity`, `--watch`, `--webhook`

---

## 🗓️ Phase 3 — Audit & Logs (Nov 2025)
- Tamper-proof logging — HMAC signature applied per log line
- Log rotation: `integrity_log.txt.1 → .2 → .3`, matching `.sig` backups
- Verification summary reports (JSON + human-readable text)
- Performance optimizations: chunked hashing, retry on lock

---

## 🗓️ Phase 4 — Configuration System (Nov 2025)
- External `config.json` for all settings (watch folder, secret key, webhook URL, intervals)
- Runtime configuration reload without restart
- Separation of core engine from user-facing interface layers

---

## 🗓️ Phase 5 — GUI Introduction (Nov 2025)
- Backend split: `integrity_core.py` (engine), `integrity_cli.py` (terminal), `integrity_gui.py` (desktop)
- GUI features: folder selection, start/stop monitoring, manual verification, live log feed

---

## 🗓️ Phase 6 — GUI & Reporting Enhancements (Dec 2025)
- Dark / Light theme toggle
- PDF report export with embedded matplotlib charts (ReportLab)
- Sliding status window for real-time event summary
- In-window alerts replacing modal pop-ups

---

## 🗓️ Phase 7 — UX & Visual Intelligence (Dec 2025)
- Color-coded severity alerts: INFO (blue) / MEDIUM (yellow) / HIGH (orange) / CRITICAL (red)
- Dashboard widgets with live counters
- Status banners and progress indicators

---

## 🗓️ Phase 8 — Security Intelligence (Jan 2026)

### 8.1 — Authentication & Access Control
- Admin / User role separation
- Password hashing with SHA-256 + salt
- Login attempt logging and brute-force protection

### 8.2 — Severity Engine
- Event-to-severity mapping for all 20+ event types
- Severity-aware webhook embeds (color-coded Discord/Slack cards)
- Persistent severity counters with thread-safe in-memory cache + disk fallback

### 8.3 — Auto Response & Safe Mode
- Automated response rules per severity:
  - **INFO** → log only
  - **MEDIUM** → alert + log
  - **HIGH** → alert + encrypted incident snapshot
  - **CRITICAL** → Safe Mode (monitoring freeze + admin alert)
- `safe_mode.py` — lockdown flag file, state persistence, admin override
- `incident_snapshot.py` — AES-encrypted forensic capture with system state, disk info, process info, recent log lines

---

## 🗓️ Phase 9 — Cleanup, Demo Mode & Production Structure (Jan–Feb 2026)
- Production folder structure: `core/`, `gui/`, `assets/`, `logs/`
- Internal files hidden via Windows file attributes
- Demo simulation mode — generates realistic fake events for live demonstrations
- Log archive & session reset menu
- System tray integration — minimize to tray, authenticate before showing dashboard
- Fixed: alert pop-ups appearing when app is minimized to tray
- Fixed: logout bug, watchdog recovery GUI flash

---

## 🗓️ Phase 10 — Performance & Forensic Enhancements (Jan 2026)
- **Multithreaded hashing** with `concurrent.futures.ThreadPoolExecutor`
  - 119 GB folder: 2m 18s → 1m 5s (sequential → 16-thread parallel)
  - Achieved 1,830 MB/s sustained read throughput on NVMe SSD
  - Python code is no longer the bottleneck — hardware I/O is the limit
- **Rename detection** — `on_moved` handler distinguishes true rename from editor "atomic save" pattern
- **Hidden file tracking** — `os.stat().st_file_attributes` captures Windows Hidden/System/Archive bits
- **State hashing** — master hash = SHA-256(content_hash | attributes | mtime), detects property-only changes
- **Debounce timer** — 2-second stability window prevents false alerts during large file writes
- **Encryption at rest** — AES-256 (Fernet) for `users.dat`, `hash_records.dat`, `integrity_log.dat`
- **Secure Audit Log Viewer** — on-the-fly AES decryption in RAM, files stay encrypted on disk

---

## 🗓️ Phase 11 — Active Defense & Automated Response (Feb 2026)
- **Auto-Healing Vault** (`vault_manager.py`):
  - Selective backup: files < 10 MB with allowed extensions only
  - Hidden, obfuscated vault (`AppData/system32_vault/`, sha256(path).enc filenames)
  - Instant file restoration on modification or deletion
  - Infinite-loop prevention via debounce timer + content-hash comparison
- **Ransomware Killswitch** (`lockdown_manager.py`):
  - Burst detection: ≥5 file events in 10 seconds
  - OS-level lockdown via Windows `icacls` — strips Write/Delete for Everyone
  - Parallelizes ransomware encryption attempts at kernel level
- **Honeypot Tripwire**:
  - `secret_passwords.txt` monitored separately
  - Any access instantly detonates killswitch + sends CRITICAL alert
- **AES Forensic Snapshots**: encrypted `.dat` captures with system state, disk, process, last 15 log lines

---

## 🗓️ Phase 12 — Enterprise Readiness (Feb 2026)
- **Dual-Channel Alerting**:
  - Discord/Slack Rich Embeds (color-coded, real-time, mobile push)
  - SMTP email alerts with forensic `.dat` attachment for compliance trail
- **Cloud Disaster Recovery** (Google Drive OAuth 2.0):
  - Per-machine encrypted cloud vaults identified by hardware `machine_id`
  - Two-tier restore: local vault → cloud rescue
  - Folder structure backup with selective extension/size filtering
- **Google OAuth Login**: "Continue with Google" with device PIN as secondary factor
- **Watchdog Stealth Mode** (`sys_watchdog.py`):
  - Separate process masquerading as `WinSysHost.exe`
  - Resurrects app with `--recovery` flag, auto-starts monitoring
- **USB Device Control** (`usb_policy.py`): Windows Registry `StorageDevicePolicies` enforcement

---

## 🗓️ Phase 13 — Admin UX & Commercial Licensing (Feb–Mar 2026)
- **Profile Panel** — live user info, license tier, subscription status
- **Password-Protected Controls** — Stop Monitoring and Settings require re-authentication
- **License System**:
  - Server-validated (POST `/api/license/validate` to Railway FastAPI)
  - 24-hour AES-encrypted local cache for offline operation
  - Graceful degradation to Free tier if server unreachable
  - PRO tiers: `pro_monthly`, `pro_annual`
- **Registration with Email OTP**: SMTP-based 6-digit code, 5-minute TTL, burns on use
- **Password Recovery**: OTP-based reset via purchase email
- **In-App Update Banner**: GitHub Gist version check on startup
  - Gist URL: https://gist.github.com/Manish93345/f339aeaae5ef231abf2be28bb750e4d8

---

## 🗓️ Phase A — GUI Upgrade to Production Quality (Mar 2026)
- Migrated from Tkinter to **CustomTkinter** — 10× visual improvement
- Branded splash screen with animated loading bar and app logo
- Professional taskbar icon (`.ico`) injected at runtime
- Fixed all Google SSO edge cases:
  - Email allowlist enforcement — only pre-registered emails can sign in with Google
  - Device PIN as secondary factor for Google SSO users (no password set)
  - PIN change dialog for Google SSO users (`_create_pin_change_window`)
  - `_authenticate_action()` now routes to PIN or password depending on `auth_method`
- Live Security Feed with severity filter pills (ALL / CRITICAL / HIGH / MEDIUM / INFO)
- Multi-folder monitoring with per-tier folder limit enforcement
- Menu animation smooth slide (ghost frame pattern to eliminate Tkinter redraw lag)

---

## 🗓️ Phase B — Cloud C2 Server Deployment (Mar 2026)
- **Railway.app deployment**: FastAPI + PostgreSQL, live at `fmsecure-c2-server-production.up.railway.app`
- **C2 Fleet Dashboard**: real-time heartbeat table, online/offline status, ARMED/UNARMED badge
- **Remote Lockdown**: ISOLATE HOST button queues `LOCKDOWN` command, agent executes on next heartbeat
- **Cookie-based admin sessions** with token-bucket rate limiting (SlowAPI)
- **Server-validated licensing**: Razorpay payment → Stripe webhook → license row in PostgreSQL → SendGrid key delivery email
- **Admin endpoints**: `/api/license/list`, `/api/license/create_manual`, `/api/license/release_device`

---

## 🗓️ Phase C — Encryption Hardening & Full Disaster Recovery (Mar 2026)
- **Hardware Key Encryption Key (KEK)**:
  - AES master key protected by a second key derived from hardware (PBKDF2 × 200,000 over hostname + machine + processor)
  - KEK never written to disk — lives in RAM only, re-derived on every boot
  - Stolen `sys.key` on a different machine → KEK mismatch → unreadable
  - Legacy upgrade path: 44-byte plaintext keys auto-upgraded to KEK format on first boot
- **Three-Layer Key Protection**:
  - L1: `system32_config/sys.key` (KEK-encrypted, hidden)
  - L2: `system32_shadow/.sys_backup.key` (KEK-encrypted, hidden)
  - L3: Google Drive `FMSecure_{MACHINE_ID}/keys/` (PRO only)
- **Machine-ID as single source of truth** for all cloud folders:
  - Industry pattern from CrowdStrike/SentinelOne: hardware identity, not email
  - Eliminates `Vault_UnknownUser` proliferation and email injection race conditions
- **Full AppData backup** every 6 hours (PRO, background scheduler)
- **Folder Structure Vault** (`folder_structure_vault.py`):
  - Backs up complete directory tree to Drive `folder_backup/` subfolder
  - Selective restore: original location or new destination
  - Skipped-files report for size/extension violations
- **Concurrent batch upload** with `ThreadPoolExecutor(max_workers=4)`, live progress callback
- **Two-Phase Initialization** to avoid circular import at startup:
  - Phase 1 (at import): local-only key load, no network
  - Phase 2 (after cloud_sync ready): cloud recovery if needed

---

## 🗓️ Phase D — Consent-Based Recovery, Archive Browser & License Hardening (Apr 2026)

### D.1 — Machine ID Determinism Fix
The `license_verifier._get_machine_id()` was appending `uuid.uuid4().hex[:8]` — a random suffix that regenerated after reinstall. After reinstall, the stored `machine_id.dat` was gone, a new random suffix appeared, and the server returned `device_mismatch` for a key the user legitimately owned. Fixed by replacing the entire function with pure hardware derivation identical to `encryption_manager.get_machine_id()`. No random component, deterministic forever.

### D.2 — License Transfer Flow (for old activations)
Users who activated before the D.1 fix have the old random machine_id in the database. Added a two-step OTP transfer flow: user provides purchase email → server sends 6-digit OTP via SendGrid → user enters OTP → server updates `machine_id` in PostgreSQL. OTP TTL: 15 minutes. Constant-time responses throughout to prevent timing and enumeration attacks. Transfer dialog built into the new styled activation window, appearing only when `device_mismatch` is detected.

### D.3 — Consent-Based Restore (The WhatsApp Pattern)
On a fresh install, the app previously silently probed Drive and restored everything without asking. Now: probe runs in a background thread while the UI shows a loading screen with a braille spinner. Both active backup and all archives are fetched. If one option exists → single detection screen. If multiple exist → picker screen lists all with date, email, and file count. User explicitly chooses which backup to restore or clicks "Start Fresh". Archives are never deleted — renamed atomically to `FMSecure_{MID}_Archive_{Timestamp}/`.

### D.4 — Wrong Password After Restore (Critical Bug)
Root cause: `users.dat` on Drive was encrypted with the backup's key (K2). Local key K1 existed, so `attempt_cloud_recovery_if_needed()` returned immediately without downloading K2. K2 was never loaded. K1 tried to decrypt K2-encrypted `users.dat` → failure → empty auth database → every password rejected. Fix: before restoring, delete local key files and reset all `crypto_manager` state flags, forcing it to download K2 from Drive. Then restore `users.dat`. Then `auth.reload()` twice with OS flush gap.

### D.5 — Archive Browser Improvements
- TclError crash fixed with `winfo_exists()` guard before `_populate()`
- Window enlarged to 1100×680, fixed size
- Progress label given fixed width (80 chars) to prevent window resizing on long filenames
- "Restore All" button added — restores subfolders in correct order (keys first)
- Folder structure backup scope option added
- All archives now shown in startup picker (was only showing active folder)

### D.6 — Splash Screen Logo Fix
Two bugs: Tkinter `PhotoImage` garbage collection (fixed by pinning reference to canvas widget with `canvas.logo_img = self.logo_img`), and a duplicate `_show_splash_screen()` call in `__init__` that created a second windowless splash that overwrote the reference.

### D.7 — Activation Dialog Redesign
Replaced plain `simpledialog.askstring()` with a full styled 500×560 window: app logo, gold accent, feature highlights, activation in background thread, inline error messages, "Buy PRO" button linking to pricing page, "Recover Lost Key" button, "Transfer License" button appearing dynamically on `device_mismatch` only.

### D.8 — Lost License Key Recovery
New server endpoint `POST /api/license/recover_key` — looks up all active non-expired keys for the provided email and re-sends each via SendGrid. Always returns `{ok: true}` regardless of whether the email exists (enumeration prevention). New `_show_key_recovery_dialog()` in the GUI.

### D.9 — Two-Phase Encryption Manager Consent Gate
`attempt_cloud_recovery_if_needed()` now requires `user_consented=True` to touch the cloud. Default (`False`) generates a fresh local key without any network call. This ensures the cloud is never restored without explicit user action, completing the consent architecture.

---

## 🔮 Pending / Future Scope
- Fix vault width — label changes cause window resize
- Progress animation during backup restore download
- Cloud sync progress bar and last-synced timestamp in GUI
- Cloud sync window freeze when closed before OAuth completes
- Password hardening — upgrade SHA-256 to bcrypt
- Server-side decompile protection — public/private key signing for license keys
- Network Isolation — `netsh advfirewall` integration during Killswitch
- ML Heuristics — isolation forest for anomaly detection replacing static burst threshold
- Memory Scanning — API hooking for fileless malware detection

# FMSecure — Development Changelog

All notable changes to FMSecure are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) conventions.  
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.5.0] — April 2026

### ✨ New Features

#### Account & Authentication
- **Username Recovery** — Users who forget their username can now recover it via registered email with OTP verification. A clean 3-step flow (email entry → OTP verification → username display with copy button) was added to the login screen alongside the existing password recovery path.
- **Google SSO Device PIN** — Returning Google SSO users now verify physical presence on the device using a 4-digit PIN set at first login. PIN change is available from the admin panel. The PIN is stored hashed (PBKDF2-SHA256) alongside the Google account record.
- **License Transfer Flow** — Users who reinstall FMSecure on the same hardware can transfer their PRO license to the new device via a 2-step OTP verification against their purchase email. Server-side machine_id column is updated on success.

#### Active Defense — Major Hardening
- **Watched Folder Protection** — Deleting the entire monitored directory (not just files inside it) is now detected and countered. A heartbeat thread polls every 2 seconds independently of the watchdog Observer (which silently stops on Windows when the watched root is deleted). On detection: directory is recreated, all tracked files are restored from vault individually, observer is re-scheduled, and a CRITICAL alert is sent.
- **Full Folder Content Restoration** — When an entire watched folder is deleted at once, individual `on_deleted` events for files inside do not fire on Windows. The heartbeat handles mass restoration by iterating vault records for every tracked file under the deleted path and restoring them in sequence.
- **Ghost Event Suppression** — Vault restoration writes temporary files (`.restore_tmp`) to disk during the restore process. These temporary files previously triggered new watchdog events, causing a cascade of repeated restore attempts and false killswitch triggers. All restoration temporaries are now ignored at the pattern level.
- **Per-File Restore Cooldown** — A 10-second cooldown per file path prevents the same file from triggering repeated restore attempts within a burst window. Defensive restore actions are explicitly excluded from ransomware burst detection.

#### Cloud Disaster Recovery
- **Restore From Cloud (Fixed)** — The "Restore from Cloud" button now correctly downloads vault `.enc` files from the user's Google Drive `vault/` subfolder with live per-file progress feedback. Previously the button silently did nothing.
- **Pre-Archive Cloud Sync** — When a user archives their session (System Backup), logs and forensics are now synced to Google Drive before being moved to local history. Previously, archived files were invisible to the cloud backup scheduler.
- **PRO Status Resilience** — Cloud sync, vault backup, and all PRO-gated operations now query the live authentication tier directly when `CONFIG["is_pro_user"]` has been reset by a `load_config()` call. PRO status is re-asserted into CONFIG before every critical operation.

#### Update System
- **In-App Update Banner** — The desktop app now checks the FMSecure server on every launch for a newer version. If a newer version is published, a dismissible banner appears below the top navigation bar with "What's New" and "Download Now →" buttons.
- **Centralised Version Management** — A single `version.py` file controls `APP_VERSION`, `DRIVE_FILE_ID`, `DOWNLOAD_PAGE_URL`, and `CHANGELOG_URL`. Updating to a new release requires changing one file on the client and one entry on the server dashboard.
- **Server Version Management** — Admin dashboard includes a "Publish New Version" panel. Publishing a new version updates all running desktop clients within seconds of their next launch.

#### Server — Public Pages
- **`/download` Page** — Public download page showing the latest version number, release notes, direct download button, and a feature overview grid. Linked from the in-app update banner.
- **`/changelog` Page** — Full public version history with a timeline layout. Each release shows version, publish date, release notes, and a per-version download link.
- **`/version.json` Endpoint** — Machine-readable version metadata served with `Cache-Control: no-store` headers. Read by every desktop client on launch.

#### Developer Tooling
- **Crypto Tools Panel** — Available from the side menu. Shows live key health: primary key status, shadow backup status, in-memory Fernet state, cloud escrow status (PRO), machine ID. Action buttons: Force Key Backup, Copy Machine ID.
- **Network & Device Policy Panel** — Available from the side menu. Shows current USB write protection state. Lists upcoming network isolation and process allow-listing features as designed tiles.

---

### 🛠 Bug Fixes

| ID | Area | Description |
|---|---|---|
| BUG-001 | UI | Vault tab width reflowed on every cloud progress update due to recursive `<Configure>` binding |
| BUG-002 | UI | Reinstall restore screen was a blank unresponsive window with no progress indication |
| BUG-003 | Cloud | Session archive logs were moved locally before cloud sync ran, making them invisible to Drive |
| BUG-004 | Cloud | "Restore from Cloud" button silently did nothing — called a legacy stub method |
| BUG-005 | Config | `CONFIG["is_pro_user"]` and `CONFIG["admin_email"]` reset to defaults on every `load_config()` call, breaking all PRO features mid-session |
| BUG-006 | Cloud | `IndentationError` on `cloud_sync.py:143` crashed all cloud operations after OAuth cancel patch |
| BUG-007 | Auth | No username recovery path — users who forgot their username were permanently locked out |
| BUG-008 | UI | Popup windows and Toplevel dialogs showed the default Python/Tk icon instead of the FMSecure logo |
| BUG-009 | Auth | App crashed with unhandled exception when OAuth browser was closed without completing sign-in |
| BUG-010 | Defense | Vault file restoration triggered ghost watchdog events, causing 4–5 duplicate RESTORED log entries and false ransomware killswitch triggers |
| BUG-011 | Defense | Watched folder deletion went undetected — watchdog Observer silently stops on Windows when the watched root is removed |
| BUG-012 | Defense | Watched folder was recreated by heartbeat but remained empty — file restoration was not part of the recovery sequence |
| BUG-013 | UI | System Backup / archive blocked the main UI thread for several seconds causing visible freeze |
| BUG-014 | Server | Update banner never appeared — `NameError` on server line 2004 was silently swallowed, causing `/version.json` to always return the hardcoded fallback version |
| BUG-015 | DX | No single place to update the download link — required changes in multiple files across server and client |

---

### 🏗 Architecture Changes

- **Heartbeat Thread** — `FileIntegrityMonitor` now starts a `FMSecure-FolderHeartbeat` daemon thread alongside the watchdog Observer. The heartbeat is the authoritative source for watched folder existence; the Observer handles file-level events within existing folders.
- **Two-Tier PRO Verification** — PRO checks now use a fast path (CONFIG) with an authoritative fallback (live auth query). CONFIG is healed on every authoritative check so subsequent fast-path checks succeed.
- **`version.py` as Single Source of Truth** — All version-related constants (`APP_VERSION`, `DRIVE_FILE_ID`, all URLs) live in one importable file. Every component (GUI title bar, update checker, banner) reads from it.
- **`versions` Database Table** — Server now maintains a `versions` table with full publish history. `is_current=TRUE` marks the active version. Publishing a new version marks all previous rows `FALSE`.

---

## [2.0.0] — Initial Release

- File integrity monitoring with SHA-256 + metadata hashing
- Real-time watchdog-based file event detection (create, modify, delete, rename)
- AES-256 encrypted audit logs with per-line HMAC signatures
- Encrypted hash record database
- Active Defense vault with auto-restore on delete or modification
- Ransomware burst detection with OS-level folder killswitch (icacls)
- Honeypot file tripwire (`secret_passwords.txt`)
- Google Drive cloud backup with machine-ID-based folder structure
- PRO licensing via Razorpay + Railway-hosted license server
- Google SSO login
- Email OTP for registration and password reset
- USB write protection via Windows Registry policy
- Forensic incident snapshots (AES-encrypted, indexed)
- PDF report export
- Discord/Slack webhook integration for real-time alerts
- Admin email alert with encrypted forensic attachment
- Demo simulation mode
- System tray integration with background monitoring
- Light/dark theme with live toggle
- CustomTkinter professional UI
- Multi-folder monitoring support (PRO)
- Folder structure backup to Google Drive (PRO)
- Archive browser for previous installation backups
- Auto-backup scheduler (logs every 15 min, AppData every 6 hours, keys every 24 hours)
- Remote emergency lockdown via C2 server command
- OTA update checking via server version endpoint


---




---

## 🗓️ Phase E — EDR Engine Expansion (Apr 2026)

### E.1 — Process Attribution
Every file event now records which process caused it. Attribution runs fully asynchronously — file events log instantly, attribution appears as a follow-up line within seconds. LOLBin detection identifies 25+ known-malicious Windows binaries (PowerShell, certutil, mshta, etc.) with a trusted-parent whitelist that suppresses false positives from IDEs (VS Code, PyCharm) and terminals.

### E.2 — System Path Protection
Monitoring expanded beyond user-chosen folders to include Windows persistence locations: startup folders (HKCU + All Users), scheduled tasks directory, and hosts file. Events from these paths are automatically escalated — files created or modified in startup folders trigger CRITICAL severity regardless of file type.

### E.3 — Registry Persistence Monitor
14 Windows Registry keys used by malware families for persistence are now monitored using `RegNotifyChangeKeyValue()` — a kernel-level API that sleeps until a change occurs, using zero CPU when idle. New Run key entries, IFEO debugger hijacks, AppInit DLL modifications, and Winlogon changes trigger CRITICAL alerts with forensic snapshots and dual-channel email/webhook notifications.

### E.4 — Threat Intelligence Engine
SHA-256 hash of every new or modified file is checked asynchronously against MalwareBazaar (abuse.ch). Results cached locally in SQLite for 7 days — zero network calls on repeat encounters. Optional VirusTotal integration available via API key. Known malware triggers CRITICAL alert with malware name, family, and reference URL.

### E.5 — Performance Fixes
- Eliminated 15-20 second lag caused by `NtQuerySystemInformation` being called on the event handler thread
- Removed all per-process API calls (`open_files()`, `io_counters()`) that competed for Windows kernel locks
- Process snapshot now uses one bulk OS call per cycle — GIL hold reduced from ~200ms to under 1ms
- Active Defense false-restore bug fixed: files less than 10 seconds old skip vault restoration (prevents conflict with editor atomic-save patterns)
- Archive session WinError 32 fixed with 5-attempt retry loop + copy+truncate fallback



## 🛠️ Build Commands
```powershell
# Compile the invisible Watchdog
pyinstaller --onedir --noconsole --name WinSysHost sys_watchdog.py

# Compile the Main Agent
pyinstaller run.py --onedir --noconsole --name SecureFIM --icon=assets/icons/app_icon.ico --add-data "assets;assets" --clean
```


## 🛠️ Build Commands
```powershell
# Compile the invisible Watchdog
python -m nuitka --standalone --windows-disable-console --output-dir=dist --output-filename=WinSysHost.exe --lto=yes sys_watchdog.py

# Compile the Main Agent
python -m nuitka --standalone --windows-disable-console --output-dir=dist --output-filename=SecureFIM.exe --windows-icon-from-ico=assets/icons/app_icon.ico --include-data-dir=assets=assets --lto=yes run.py
```

python -m nuitka --standalone --windows-console-mode=disable --output-dir=dist --output-filename=SecureFIM.exe --windows-icon-from-ico=assets/icons/app_icon.ico --include-data-dir=assets=assets --lto=no --jobs=1 --enable-plugin=tk-inter --show-progress run.py



python -m nuitka ^
  --standalone ^
  --windows-disable-console ^
  --enable-plugin=tk-inter ^
  --enable-plugin=anti-bloat ^
  --output-dir=dist ^
  --output-filename=SecureFIM.exe ^
  --windows-icon-from-ico=assets/icons/app_icon.ico ^
  --include-data-dir=assets=assets ^
  --include-package=customtkinter ^
  --include-package=pystray ^
  --include-package=PIL ^
  --include-package=cryptography ^
  --include-package=google ^
  --include-package=googleapiclient ^
  --include-package=google_auth_oauthlib ^
  --include-package=requests ^
  --include-package=watchdog ^
  --include-package=core ^
  --include-package=gui ^
  --lto=yes ^
run.py