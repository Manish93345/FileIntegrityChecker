import time
import sys
import os

# Ensure we can import from core
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import integrity_core as ic
import safe_mode

class DemoSimulator:
    def __init__(self, alert_callback=None):
        """
        :param alert_callback: Function to call on GUI to show alert (title, msg, severity)
        """
        self.alert_callback = alert_callback
        self.running = False

    def run_simulation(self):
        self.running = True
        
        # 1. INFO EVENT: File Creation
        if not self.running: return
        self._trigger_step(
            "INFO", 
            "CREATED", 
            "demo_test_file.txt", 
            "New file created in monitored directory (SIMULATED)"
        )
        time.sleep(2)

        # 2. MEDIUM EVENT: File Modification
        if not self.running: return
        self._trigger_step(
            "MEDIUM", 
            "MODIFIED", 
            "config.json", 
            "Configuration file modified externally (SIMULATED)"
        )
        time.sleep(2)

        # 3. HIGH EVENT: Burst Deletion
        if not self.running: return
        self._trigger_step(
            "HIGH", 
            "MULTIPLE_DELETES", 
            "data/*.log", 
            "Burst deletion detected: 5 files removed in 1s (SIMULATED)"
        )
        time.sleep(2)

        # 4. CRITICAL EVENT: Tampering
        if not self.running: return
        self._trigger_step(
            "CRITICAL", 
            "TAMPERED_RECORDS", 
            "hash_records.json", 
            "Cryptographic signature mismatch in hash database (SIMULATED)"
        )
        time.sleep(1.5)

        # 5. SAFE MODE TRIGGER
        if not self.running: return
        self._trigger_safe_mode()
        
        # --- FIX: STOP IMMEDIATELY ---
        self.running = False 
        # Wait a moment to ensure backend processes the lock
        time.sleep(0.5)

    def _trigger_step(self, severity, event_type, file_path, message):
        """Log event, update counters, and trigger GUI alert"""
        
        # 1. Write to Log (Prefix with [DEMO])
        log_msg = f"[DEMO] {message}"
        ic.append_log_line(log_msg, event_type=event_type, severity=severity)
        
        # 2. Trigger GUI Alert
        if self.alert_callback:
            self.alert_callback(f"DEMO: {event_type}", message, severity.lower())

    def _trigger_safe_mode(self):
        """Simulate entering Safe Mode"""
        reason = "[DEMO] Critical Tampering Simulation"
        
        # 1. Actually trigger safe mode logic (creates lock files)
        safe_mode.enable_safe_mode(reason, "hash_records.json")
        
        # 2. Log it
        ic.append_log_line(f"[DEMO] ⛔ SAFE MODE ENABLED: {reason}", severity="CRITICAL")
        
        # 3. GUI Alert
        if self.alert_callback:
            self.alert_callback("SYSTEM LOCKDOWN", f"Safe Mode Triggered: {reason}", "critical")

    def stop(self):
        self.running = False