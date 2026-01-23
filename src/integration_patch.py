"""
integration_patch.py
One-time setup script to integrate new security features
Run this once to set up everything
"""

import os
import json
import shutil
import sys

def create_config_files():
    """Create configuration files for new features"""
    
    auto_response_rules = {
        "INFO": "log_only",
        "MEDIUM": "alert_and_log", 
        "HIGH": "alert_and_snapshot",
        "CRITICAL": "safe_mode",
        "TAMPERED_RECORDS": "safe_mode",
        "TAMPERED_LOGS": "safe_mode",
        "SIGNATURE_MISMATCH": "safe_mode",
        "MULTIPLE_DELETES": "alert_and_snapshot",
        "BURST_OPERATION": "alert_and_snapshot"
    }
    
    safe_mode_config = {
        "auto_enable_for": ["TAMPERED_RECORDS", "TAMPERED_LOGS", "SIGNATURE_MISMATCH"],
        "notify_admin": True,
        "admin_webhook": None,
        "freeze_monitoring": True,
        "create_forensic_copy": True,
        "auto_disable_after_hours": 24
    }
    
    incident_config = {
        "generate_for_severities": ["HIGH", "CRITICAL"],
        "include_forensic_files": True,
        "max_snapshots": 100,
        "compress_old_snapshots": False,
        "auto_cleanup_days": 30
    }
    
    try:
        with open('auto_response_rules.json', 'w') as f:
            json.dump(auto_response_rules, f, indent=2)
        print("✓ Created auto_response_rules.json")
        
        with open('safe_mode_config.json', 'w') as f:
            json.dump(safe_mode_config, f, indent=2)
        print("✓ Created safe_mode_config.json")
        
        with open('incident_config.json', 'w') as f:
            json.dump(incident_config, f, indent=2)
        print("✓ Created incident_config.json")
        
        return True
    except Exception as e:
        print(f"✗ Error creating config files: {e}")
        return False

def create_directories():
    """Create necessary directories"""
    directories = ["incident_snapshots", "forensic_backups", "security_logs"]
    
    for directory in directories:
        try:
            if not os.path.exists(directory):
                os.makedirs(directory)
                print(f"✓ Created directory: {directory}")
        except Exception as e:
            print(f"✗ Error creating {directory}: {e}")

def create_initial_files():
    """Create initial state files"""
    
    if not os.path.exists("safe_mode_state.json"):
        try:
            initial_state = {
                'active': False,
                'reason': '',
                'start_time': None,
                'last_updated': None
            }
            with open("safe_mode_state.json", 'w') as f:
                json.dump(initial_state, f, indent=2)
            print("✓ Created safe_mode_state.json")
        except Exception as e:
            print(f"✗ Error creating safe_mode_state.json: {e}")

def patch_integrity_core():
    """Show what needs to be added to integrity_core.py"""
    print("\n=== MANUAL INTEGRATION STEPS FOR integrity_core.py ===")
    print("\n1. Add these imports at the top of the file (after other imports):")
    print("""
# Import security features
try:
    from auto_response import trigger_auto_response, handle_tamper_event
except ImportError:
    trigger_auto_response = None
    handle_tamper_event = None

try:
    from safe_mode import enable_safe_mode, is_safe_mode_enabled
except ImportError:
    enable_safe_mode = None
    is_safe_mode_enabled = lambda: False
""")
    
    print("\n2. In verify_records_signature_on_disk() function, add after detecting tampering:")
    print("""
    if not ok:
        # Existing code...
        
        # Auto-response for CRITICAL tampering
        if handle_tamper_event:
            handle_tamper_event("records", HASH_RECORD_FILE)
""")
    
    print("\n3. In verify_log_signatures() function, add after detecting tampering:")
    print("""
    if not ok_logs:
        # Auto-response for CRITICAL tampering  
        if handle_tamper_event:
            handle_tamper_event("logs", LOG_FILE)
""")
    
    print("\n4. Save the file and restart your application.")

def patch_gui_for_safe_mode():
    """Show how to add safe mode indicator to GUI"""
    print("\n=== GUI INTEGRATION (integrity_gui.py) ===")
    print("\nAdd safe mode status checking in _update_dashboard() method:")
    print("""
    # Check safe mode status
    try:
        from safe_mode import is_safe_mode_enabled
        if is_safe_mode_enabled():
            # Update status to show safe mode
            self.status_var.set("🚨 SAFE MODE ACTIVE - SYSTEM COMPROMISED")
    except ImportError:
        pass
""")

def create_integration_guide():
    """Create integration guide file"""
    guide_content = """# Security Features Integration Guide

## Files Created:
1. auto_response.py - Auto-response rules engine
2. safe_mode.py - Safe mode management
3. incident_snapshot.py - Incident snapshot generator
4. test_security_features.py - Test script

## Configuration Files:
- auto_response_rules.json - Response rules
- safe_mode_config.json - Safe mode settings
- incident_config.json - Snapshot settings
- safe_mode_state.json - Safe mode state

## Directories Created:
- incident_snapshots/ - Stores incident reports
- forensic_backups/ - Forensic file copies
- security_logs/ - Additional security logs

## How to Use:

### Auto-Response System:
Events are automatically handled based on severity:
- INFO: Just log
- MEDIUM: Alert + log
- HIGH: Alert + report snapshot  
- CRITICAL: Safe Mode + monitoring freeze

### Safe Mode:
When CRITICAL tampering is detected:
1. Monitoring automatically freezes
2. Admin is notified
3. System shows "SAFE MODE ACTIVE"
4. Forensic copies are created

### Incident Snapshots:
For HIGH/CRITICAL events:
1. Detailed snapshot is generated
2. Includes system state
3. Last 10 events
4. File hashes
5. Forensic copies

## Manual Integration Required:

### 1. Update integrity_core.py:
Add imports at top and auto-response calls in:
- verify_records_signature_on_disk()
- verify_log_signatures()

### 2. Update integrity_gui.py:
Add safe mode status check in _update_dashboard()

## Testing:
Run: python test_security_features.py

## Production:
After integration, your system will:
1. Automatically respond to security events
2. Enter safe mode on critical tampering
3. Generate incident snapshots
4. Preserve forensic evidence

## Notes:
- integration_patch.py is one-time setup only
- test_security_features.py is for testing only
- Main application starts from login_gui.py
"""
    
    try:
        with open('SECURITY_INTEGRATION_GUIDE.md', 'w') as f:
            f.write(guide_content)
        print("\n✓ Created SECURITY_INTEGRATION_GUIDE.md")
    except Exception as e:
        print(f"✗ Error creating guide: {e}")

def main():
    """Main integration function"""
    print("=" * 60)
    print("SECURITY FEATURES INTEGRATION SETUP")
    print("=" * 60)
    
    print("\n1. Creating configuration files...")
    create_config_files()
    
    print("\n2. Creating directories...")
    create_directories()
    
    print("\n3. Creating initial state files...")
    create_initial_files()
    
    print("\n4. Showing manual integration steps...")
    patch_integrity_core()
    patch_gui_for_safe_mode()
    
    print("\n5. Creating integration guide...")
    create_integration_guide()
    
    print("\n" + "=" * 60)
    print("SETUP COMPLETE!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Manually update integrity_core.py with the code above")
    print("2. Optionally update integrity_gui.py for safe mode display")
    print("3. Run: python test_security_features.py")
    print("4. Start your application: python login_gui.py")
    print("\nNote: This setup script is for one-time use only.")

if __name__ == "__main__":
    main()