# [Create a new file: severity_init.py]
#!/usr/bin/env python3
"""
Initialize severity counters and ensure proper event mapping
"""

import json
import os


# Initialize severity counters
def init_severity_counters():
    counters = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "INFO": 0
    }
    target_file = os.path.join("logs", "severity_counters.json")
    # Ensure logs dir exists (just in case)
    if not os.path.exists("logs"):
        os.makedirs("logs")
    
    with open(target_file, "w", encoding="utf-8") as f:
        json.dump(counters, f, indent=2)
    
    print("✅ Severity counters initialized")

# Create event mapping file for reference
def create_event_mapping():
    event_mapping = {
        # File operations
        "CREATED": "INFO",
        "CREATED_ON_MODIFY": "INFO",
        "MODIFIED": "MEDIUM",
        "DELETED": "MEDIUM",
        "DELETED_UNTRACKED": "MEDIUM",
        
        # Security events
        "TAMPERED_RECORDS": "CRITICAL",
        "TAMPERED_LOGS": "CRITICAL",
        "LOG_INTEGRITY_FAIL": "CRITICAL",
        "INTEGRITY_FAIL": "CRITICAL",
        "SIGNATURE_MISMATCH": "CRITICAL",
        
        # Configuration changes
        "CONFIG_CHANGED": "HIGH",
        "SETTINGS_UPDATED": "HIGH",
        
        # Multiple/burst operations
        "MULTIPLE_DELETES": "HIGH",
        "BURST_OPERATION": "HIGH",
        
        # System events
        "MONITOR_STARTED": "INFO",
        "MONITOR_STOPPED": "INFO",
        "VERIFICATION_STARTED": "INFO",
        "VERIFICATION_COMPLETED": "INFO",
        "LOG_ROTATED": "INFO",
        "WEBHOOK_SENT": "INFO",
        "WEBHOOK_FAIL": "MEDIUM",
    }
    
    with open("event_severity_mapping.json", "w", encoding="utf-8") as f:
        json.dump(event_mapping, f, indent=2, sort_keys=True)
    
    print("✅ Event severity mapping created")

if __name__ == "__main__":
    init_severity_counters()
    create_event_mapping()
    print("\n🎯 Severity system initialized successfully!")
    print("   - severity_counters.json created")
    print("   - event_severity_mapping.json created")
    print("\nNow run your File Integrity Monitor with enhanced security severity tracking!")