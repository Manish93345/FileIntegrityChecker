### 7 Oct 2025
- Created project folder and structure
- Wrote initial README.md
- Planned tech stack and features 


    hash_generation.py
        It is just a simple program to check whether it is generating hash of a file or not. 


    Now created first file_checker.py 
        This is for only one file, like we give the path of a file and it first saves tha hash value of the file.
        Now if the file will tampered later then we can detect it using the same program. 
    

    folder_monitor.py
        This is a polling based integrity checker. Polling based means that program will check the specific folder (./tests) that if the 
        file inside that folder is modified, deleted or new file added or not. It will create two files -> integrity_log.txt and hash_record.json. 




### 8 Oct 2025
    -For real time monitoring
    -Install watchdog -> pip install watchdog
    -realtime_monitor.py
    -Creates two files
        -First one is hash_records.json which contain the hash record of all the files of that specific folder.
        -Second one is integrity_log.txt which show that at which date and at which time any file is deleted, modified or newly added.



### 9 Oct 2025
    File Integrity Checker (realtime_monitor_enhanced.py)— Enhanced (Phase 1)
    pip install watchdog requests

    Features:
        - Startup checks: auto-create log & records, validate watch folder
        - Initial scan to register existing files
        - generate_hash: chunked hashing + retry for PermissionError / transient locks
        - verify_all_files(): manual full re-check and summary report
        - Real-time monitoring with watchdog (CREATE / MODIFY / DELETE)
        - Optional webhook alert call if WEBHOOK_URL set in config
        - CLI: run monitor (default) or --verify then exit

    Phase 2: Security + Verification Enhancements  (phase__secure_monitor.py)
        -goal: make our system trustworthy & tamper-proof — not just a passive monitor.

        -1. Integrity of “hash_records.json” itself (HMAC signature)
            -Problem: agar koi malicious user hash_records.json ko modify kar de (replace stored hashes), to system soch lega sab safe hai.
            -Solution: har update ke baad hum ek HMAC (Hash-based Message Authentication Code) signature generate karenge ek secret key se, aur usko ek separate file (hash_records.sig) mein store karenge.
            Startup par system verify karega ki hashes tampered nahi hue.
        -2. Periodic Auto-Verification Thread
            -hum ek background thread daalenge jo har X minutes (e.g., 30) pe verify_all_files() run kare silently aur summary webhook bheje — agar koi unnoticed change hua ho.
        -3. Smart Log Rotation (optional but neat)
            -integrity_log.txt ko unlimited grow hone se rokne ke liye —
            -jab size > 5MB ho jaaye toh rename karo integrity_log_1.txt etc. aur naya file start karo.
        -4. CLI Enhancement (better control)
            CLI commands:
            --verify       # manual verification
            --periodic 30  # run verify every 30 mins
            --check-integrity  # verify hash_records.json authenticity



### 10 Oct 2025
    -phase_2_secure_monitor_fixed.py
    -key changes 
        -Startup prints + logs
        -Optional webhook.
        -Atomic save of records + signature
        -Periodic disk HMAC verification (detect external tamper)
        -Clearer alerts when signature mismatch (tamper) or missing signature




### 11 Oct 2025 PHASE -3
    -Phase 3: phase_3_secure_log_monitor.py

    -Advanced Security & Reporting

    -1: Audit Trail (tamper-proof log system)
        -HMAC for integrity_log.txt

        phase_3_secure_log_monitor_fixed.py
            -Default max size is 10 mb after that rotation will happen
            -All backups are shifted (.1 → .2, .2 → .3, etc.)
            -MAX_BACKUP_COUNT = 5  # Keep 5 backup files
            -python phase_3_secure_log_monitor_fixed.py --max-log-size 50 --max-backups 10
            -Example: 
                integrity_log.txt          (current, active log)
                integrity_log.txt.1        (most recent backup)
                integrity_log.txt.2        (older backup)
                integrity_log.txt.3        (even older backup)
                integrity_log.sig          (current signatures)
                integrity_log.sig.1        (most recent signatures backup)
                integrity_log.sig.2        (older signatures backup)


    
    -2: Verification Summary Report (auto-generated JSON + text) ❌PENING -> PHASE 3.5
        -Create a summary report after periodic verification

    -3: Performance Optimization
        -Will try to make hashing paraller or thread based

    -4: CLI improvement (user options) ✅
        -For user convenience like --verify, --summary, etc.

                    # Verify log integrity only
            python phase_2_secure_monitor_fixed.py --verify-log

            # Full verification (hash records + files)
            python phase_2_secure_monitor_fixed.py --verify

            # With webhook enabled
            python phase_2_secure_monitor_fixed.py --webhook "https://your-webhook-url.com"

            # Custom watch folder and interval
            python phase_2_secure_monitor_fixed.py --watch "/path/to/folder" --interval 300




### 12 Oct 2025 - PHASE 3.5
    -phase_3.5_secure_monitor.py  (SOME ISSUE WITH INTEGRITY_LOG.TXT)
    -phase_3.5_secure_monitor_fixed.py

    -1: Report Summary Feature
        -Generate summary after program start or periodic verification


### 12 Oct 2025 - PHASE 4
    -1: Config System (config.json)
        -A config file where the user is able to change the settings like secret key, webhook url, etc.

    




### 12 Oct 2025 - PHASE 4.5 GUI
    
    -1: integrity_core.py
        -main backend logic (monitoring, hashing, HMAC, verification)
    -2: integrity_cli.py
        -command-line interface (for terminal users)
    -3: integrity_gui.py 
        -To import file from backend

    -4: As for now, 4 button on gui
        -Select folder
        -Start Monitoring
        -Run full verification
        -Show summary report

    -5 Live log feed
        -Integrity_log.txt will be auto-refreshed in GUI textbox



### 21 Oct 2025 - PHASE 5 GUI
    -1: Improvement in gui
    -2: Making feature to edit config in gui direclty



### 21 Oct 2025 - PHASE 6 Improvement
    -1: Visual Improvements
        -color themes (light/dark switch)
        -Use icons on buttons (start/stop, verify, settings)
        -Replace pop-ups with in-window alerts or status banners for smooth UX.
            -pip install pillow
            -creating assets folder inside which there should image

    -2: Enhanced Reporting  (Phase_6_step_2.py)
        -pip install reportlab pillow
        -pip install reportlab pillow watchdog requests
        -User can export them as .txt or .pdf.

    -3: Created a new sliding window for showing status 
        -phase_6_step_3.py
        -created a sliding window to show the status


### 2 Dec 2025 - PHASE 7 
    -1: Dark/Light theme toggle
    -2: PDF report export with signatures
    -3: Color-coded alerts for different event types



### 6 January 2026 - PHASE 8
    -1: Report Data Normalization
        -GUI ke report summary ko ek structured dict mein convert karna
        -summary = {
            "total": 120,
            "created": [...],
            "modified": [...],
            "deleted": [...]
            }

    -2: Bar Chart Generator (matplotlib)
        -Created / Modified / Deleted counts ka bar graph
        -Save as PNG
        -Dark + Light theme compatible

    -3: PDF Generator (ReportLab)
        -Title + timestamp
        -Summary numbers
        -Embedded chart image
        -Optional: top-N file list

    -4: GUI Integration
        -“📄 Export PDF Report” button
        -Success popup + “Open Folder”
        -Graceful error handling (library missing etc.)



### 8 January 2026 - PHASE 8.1
    1: Authentication System
        -User Mode (safe)
        -Admin Mode (protected)
        -Hidden dangerous controls
        -Alert on login
        -Wrong password detection
        -Real enterprise-style behavior

        
### 23 January 2026 - PHASE 8.2
    Severity Intelligence
    🔥 CRITICAL — Hash DB tampered
    🟡 MEDIUM — File modified
    🟢 INFO — File created

MAIN FILE FOR NOW -> RUN login_gui.py 
credentials are: username: admin, pass: lisajaanu
imp files -> login_gui.py, integrity_core.py, integrity_gui.py, auth_manager.py, severity_init.py

### 24 January 2026 - PHASE 8.3
        1: AUTO RESPONSE & SAFE MODE
            -AUTO RESPONSE RULES
            -Severity	Auto Action
                INFO	Sirf log
                MEDIUM	Alert + log
                HIGH	Alert + report snapshot
                CRITICAL	🔒 Safe Mode + monitoring freeze

                New files created -> auto_reponse.py (production), safe_mode.py (production),incident_snapshot.py (production), integration_patch.py (one time only, not the core file), test_security_features.py(only to test the features optional)
                Run the python integration_patch.py

        2: SAFE MODE
            -Agar kuch bahut dangerous ho:
                hash_records.json tampered
                integrity_log.txt tampered
                👉 system:
                    Monitoring pause kar de
                    Admin ko CRITICAL alert
                Status bar:
                    🚨 SAFE MODE ENABLED — SYSTEM COMPROMISED

        3: INCIDENT SNAPSHOT
            -CRITICAL event par:
                Ek mini report auto-generate ho
                Timestamp
                File
                Severity
                Last 10 events
            Saved as:
                incident_2025-10-XX_22-41.txt


### 25-26 January 2026 - PHASE 9
    Cleanup & Structure
        Folder structure clean
        Internal files hide (logs, hash db)
        README.md final version
        requirements.txt

        ok i have to structure it like this 
        FileIntegritySecurity/

        │

        ├── core/

        │   ├── integrity_core.py

        │   ├── auto_response.py

        │   ├── severity_init.py

        │   ├── verifier.py

        │

        ├── gui/

        │   ├── integrity_gui.py

        │

        ├── config/

        │   └── config.json

        │

        ├── reports/

        │   ├── report_summary.txt

        │   ├── detailed_reports.txt

        │   └── incidents/

        │       └── incident_2025-xx-xx.txt

        │

        ├── logs/

        │   └── integrity_log.txt

        │

        ├── assets/

        │   └── icons/

        │

        ├── requirements.txt

        ├── README.md

        └── run.py



    Demo Mode
        Button: “Run Demo Simulation”
        Fake events generate:
        File modified
        Critical tamper
        Safe mode
        Interviewer ke saamne live demo 🔥


    FILES REQUIRED -> 
        integrity_cli.py
        auth_manager.py
        login_gui.py
        severity_init.py
        auto_response.py
        integrity_gui.py
        incident_snapshot.py
        integrity_core.py
        safe_mode.py
        security_imports.py

        config.json
        requirements.txt


# GUI MODE
bash
python run.py  or  python run.py --gui

# CLI Mode
bash
python run.py --cli
python run.py --cli --verify
python run.py --cli --watch /path/to/folder


Structure finalized


### 25-26 January 2026 - PHASE 9
    TODO
        next phase
        menu button jisme ki reports and logs ko reset kiya jaa sake
        report_data.json, users.json, severity_counters.json, detailed_reports.txt  DONE ✅
        demo video and screenshots in demo folder



### February 2026 - PHASE 9
    -> Improved the overall gui to look like security app
    -> updated menu gui 
    -> Fixed the alert message box problem to be appering even after in hidden tray
    -> Fixed logout bug


    -> fixed notification issue when minimized
    -> fixed demo simualator error
    -> authentication while opening from system tray
        Session restoration without re-authentication vulnerability.

    

### Moving to implement premium features
    subscription_manager.py :-> Its only job is to handle premium logic.

    PHASE 1: 
        Created subscritption_manager.py
        Updated auth_manager.py

    PHASE 2:
        Modified the following files
            integrity_core.py
            integrity_gui.py

### Creating liscense for the premium user
    PHASE 1:
        license_generator.py -> (Keep this safe!)  DO NOT include it in the installer
        core/license_manager.py
        core/license_verifier.py

    