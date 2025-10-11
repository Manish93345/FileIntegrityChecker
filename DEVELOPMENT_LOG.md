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















    -TODO
        -1) Alerts (high value, small effort) ✅
        -2) Tamper-evident records (HMAC) (high value) ✅
        -3) Ignore-list & config (medium effort) ✅
        -4) Log rotation & backups (medium) ❌
        -5) Small Flask API + Dashboard (bigger, very visible)
        -6) Tests + Demo script + Packaging (essential polish)
        -7) GUI
    