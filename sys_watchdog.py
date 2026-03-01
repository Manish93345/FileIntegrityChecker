import time
import subprocess
import sys
import os
from datetime import datetime

def log_event(message):
    """Log watchdog events to a simple text file"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_msg = f"[{timestamp}] {message}\n"
    print(log_msg.strip())
    try:
        with open("watchdog_log.txt", "a") as f:
            f.write(log_msg)
    except:
        pass

def start_watchdog():
    log_event("🐕 Watchdog Service Initialized. Protecting FMSecure...")
    
    # --- NEW: DETECT IF COMPILED (.EXE) OR SCRIPT (.PY) ---
    is_compiled = getattr(sys, 'frozen', False)
    
    if is_compiled:
        app_target = "FMSecure.exe"
        base_cmd = [app_target]
    else:
        app_target = "run.py"
        base_cmd = [sys.executable, app_target]
        
    if not os.path.exists(app_target):
        log_event(f"❌ CRITICAL ERROR: Could not find {app_target}")
        return

    is_recovery = False

    while True:
        log_event(f"🚀 Launching {app_target}...")
        try:
            # Add the recovery flag if we are resurrecting it
            cmd = base_cmd + ["--recovery"] if is_recovery else base_cmd
            
            process = subprocess.Popen(cmd)
            process.wait()
            exit_code = process.returncode
            
            if exit_code == 0:
                log_event("🛑 FMSecure closed normally. Watchdog sleeping.")
                break 
            else:
                log_event(f"⚠️ ALERT: FMSecure killed unexpectedly (Exit Code: {exit_code})!")
                log_event("🔄 Resurrecting in 2 seconds...")
                is_recovery = True
                time.sleep(2)
                
        except Exception as e:
            log_event(f"❌ Watchdog error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    start_watchdog()