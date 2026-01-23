"""
debug_security.py
Debug script to identify why security features aren't working
"""

import os
import sys
import json
import traceback
from datetime import datetime

def check_imports():
    """Check if all modules can be imported"""
    print("=" * 70)
    print("IMPORT CHECK")
    print("=" * 70)
    
    modules_to_check = [
        'auto_response',
        'safe_mode', 
        'incident_snapshot',
        'integrity_core',
        'security_imports'
    ]
    
    for module in modules_to_check:
        try:
            imported = __import__(module)
            print(f"✓ {module}: OK")
            
            # Check specific functions for key modules
            if module == 'auto_response':
                if hasattr(imported, 'trigger_auto_response'):
                    print(f"  • trigger_auto_response: OK")
                if hasattr(imported, 'handle_tamper_event'):
                    print(f"  • handle_tamper_event: OK")
                    
            elif module == 'safe_mode':
                if hasattr(imported, 'enable_safe_mode'):
                    print(f"  • enable_safe_mode: OK")
                if hasattr(imported, 'is_safe_mode_enabled'):
                    print(f"  • is_safe_mode_enabled: OK")
                    
            elif module == 'incident_snapshot':
                if hasattr(imported, 'generate_incident_snapshot'):
                    print(f"  • generate_incident_snapshot: OK")
                    
        except ImportError as e:
            print(f"✗ {module}: {e}")
        except Exception as e:
            print(f"✗ {module}: {type(e).__name__}: {e}")

def check_integrity_core_integration():
    """Check if integrity_core.py has the integration code"""
    print("\n" + "=" * 70)
    print("INTEGRITY_CORE INTEGRATION CHECK")
    print("=" * 70)
    
    integrity_core_file = "integrity_core.py"
    if not os.path.exists(integrity_core_file):
        print(f"✗ {integrity_core_file} not found")
        return False
    
    with open(integrity_core_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    checks = [
        ("Security imports at top", "from security_imports import"),
        ("handle_tamper_event call in verify_records", "handle_tamper_event(\"records\""),
        ("handle_tamper_event call in verify_logs", "handle_tamper_event(\"logs\""),
        ("Auto-response imports", "AUTO_RESPONSE_AVAILABLE"),
        ("Safe mode imports", "SAFE_MODE_AVAILABLE")
    ]
    
    all_passed = True
    for check_name, search_text in checks:
        if search_text in content:
            print(f"✓ {check_name}: Found")
        else:
            print(f"✗ {check_name}: NOT FOUND")
            all_passed = False
    
    return all_passed

def test_auto_response_directly():
    """Test auto-response directly"""
    print("\n" + "=" * 70)
    print("DIRECT AUTO-RESPONSE TEST")
    print("=" * 70)
    
    try:
        from auto_response import trigger_auto_response, get_auto_response_engine
        
        print("1. Testing INFO level...")
        result = trigger_auto_response(
            severity="INFO",
            event_type="DEBUG_TEST_INFO",
            message="Debug test info message",
            file_path="/debug/test.txt"
        )
        print(f"   Result: {'✓ Success' if result else '✗ Failed'}")
        
        print("\n2. Testing HIGH level (should create snapshot)...")
        result = trigger_auto_response(
            severity="HIGH",
            event_type="DEBUG_TEST_HIGH",
            message="Debug test high message - should create snapshot",
            file_path="/debug/critical.txt",
            data={"test": True, "debug": "yes"}
        )
        print(f"   Result: {'✓ Success' if result else '✗ Failed'}")
        
        if result:
            # Check if snapshot was created
            snapshot_dir = "incident_snapshots"
            if os.path.exists(snapshot_dir):
                snapshots = [f for f in os.listdir(snapshot_dir) 
                           if f.endswith('.txt') and "DEBUG_TEST_HIGH" in f]
                if snapshots:
                    print(f"   ✓ Snapshot created: {snapshots[0]}")
                else:
                    print("   ✗ No snapshot found")
            else:
                print("   ✗ incident_snapshots directory doesn't exist")
        
        print("\n3. Testing CRITICAL level (should enable safe mode)...")
        result = trigger_auto_response(
            severity="CRITICAL",
            event_type="DEBUG_TEST_CRITICAL",
            message="Debug test critical message - should enable safe mode",
            file_path="/debug/tampered.json"
        )
        print(f"   Result: {'✓ Success' if result else '✗ Failed'}")
        
        # Check safe mode
        try:
            from safe_mode import is_safe_mode_enabled
            if is_safe_mode_enabled():
                print("   ✓ Safe mode enabled")
            else:
                print("   ✗ Safe mode NOT enabled (problem)")
        except:
            print("   ✗ Cannot check safe mode")
        
        return result
        
    except Exception as e:
        print(f"✗ Auto-response test failed: {e}")
        traceback.print_exc()
        return False

def test_tamper_detection():
    """Test tamper detection workflow"""
    print("\n" + "=" * 70)
    print("TAMPER DETECTION WORKFLOW TEST")
    print("=" * 70)
    
    # Create a test hash file if it doesn't exist
    hash_file = "hash_records.json"
    if not os.path.exists(hash_file):
        print("Creating test hash_records.json...")
        test_data = {
            "test_file.txt": {
                "hash": "abc123",
                "last_checked": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        }
        with open(hash_file, 'w') as f:
            json.dump(test_data, f, indent=2)
        print("✓ Created test hash_records.json")
    
    # Tamper the file
    print("\n1. Tampering hash_records.json...")
    with open(hash_file, 'r') as f:
        data = json.load(f)
    
    # Corrupt it
    if data:
        first_key = list(data.keys())[0]
        original_hash = data[first_key]["hash"]
        data[first_key]["hash"] = "TAMPERED_HASH_" + datetime.now().strftime("%H%M%S")
    
    with open(hash_file, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"   ✓ Tampered: Changed hash from {original_hash} to {data[first_key]['hash']}")
    
    # Now verify
    print("\n2. Running verification (should detect tampering)...")
    try:
        from integrity_core import verify_records_signature_on_disk
        
        result = verify_records_signature_on_disk()
        print(f"   Verification result: {'✓ OK' if result else '✗ TAMPERED (expected)'}")
        
        if not result:
            print("   ✓ Tampering detected!")
            
            # Check if safe mode was activated
            try:
                from safe_mode import is_safe_mode_enabled
                if is_safe_mode_enabled():
                    print("   ✓ Safe mode activated!")
                else:
                    print("   ✗ Safe mode NOT activated (problem!)")
            except:
                print("   ✗ Cannot check safe mode status")
        else:
            print("   ✗ Tampering NOT detected (problem!)")
        
        return not result
        
    except Exception as e:
        print(f"✗ Verification failed: {e}")
        traceback.print_exc()
        return False

def check_config_files():
    """Check configuration files"""
    print("\n" + "=" * 70)
    print("CONFIGURATION FILES CHECK")
    print("=" * 70)
    
    config_files = [
        ("config.json", "Main configuration"),
        ("auto_response_rules.json", "Auto-response rules"),
        ("safe_mode_config.json", "Safe mode configuration"),
        ("incident_config.json", "Incident snapshot configuration"),
        ("safe_mode_state.json", "Safe mode state")
    ]
    
    for filename, description in config_files:
        if os.path.exists(filename):
            print(f"✓ {filename}: Exists")
            
            # Check content
            try:
                with open(filename, 'r') as f:
                    content = json.load(f)
                print(f"  • Valid JSON")
                
                # Check specific keys for important files
                if filename == "auto_response_rules.json":
                    required_keys = ["INFO", "MEDIUM", "HIGH", "CRITICAL"]
                    missing = [k for k in required_keys if k not in content]
                    if missing:
                        print(f"  ✗ Missing keys: {missing}")
                    else:
                        print(f"  • All severity rules present")
                        
            except json.JSONDecodeError as e:
                print(f"  ✗ Invalid JSON: {e}")
            except Exception as e:
                print(f"  ✗ Error reading: {e}")
        else:
            print(f"✗ {filename}: Missing")

def check_log_for_events():
    """Check log file for security events"""
    print("\n" + "=" * 70)
    print("LOG FILE ANALYSIS")
    print("=" * 70)
    
    log_file = "integrity_log.txt"
    if not os.path.exists(log_file):
        print("✗ Log file not found")
        return False
    
    with open(log_file, 'r') as f:
        lines = f.readlines()
    
    print(f"Total lines: {len(lines)}")
    
    # Count by severity
    severities = ["CRITICAL", "HIGH", "MEDIUM", "INFO"]
    counts = {s: 0 for s in severities}
    
    print("\nRecent security events (last 20 lines):")
    recent_lines = lines[-20:] if len(lines) > 20 else lines
    
    found_events = False
    for line in recent_lines:
        line = line.strip()
        for severity in severities:
            if f"[{severity}]" in line:
                counts[severity] += 1
                print(f"  {line}")
                found_events = True
                break
    
    if not found_events:
        print("  No recent security events found")
    
    print("\nSeverity counts (total):")
    for severity in severities:
        if counts[severity] > 0:
            print(f"  {severity}: {counts[severity]}")
    
    # Check for specific event types
    print("\nLooking for specific events:")
    event_types = [
        "TAMPERED_RECORDS",
        "TAMPERED_LOGS",
        "MULTIPLE_DELETES",
        "BURST_OPERATION",
        "SAFE_MODE",
        "INCIDENT_SNAPSHOT"
    ]
    
    for event_type in event_types:
        count = sum(1 for line in lines if event_type in line)
        if count > 0:
            print(f"  ✓ {event_type}: {count} occurrence(s)")
    
    return True

def cleanup_and_reset():
    """Clean up and reset for testing"""
    print("\n" + "=" * 70)
    print("CLEANUP AND RESET")
    print("=" * 70)
    
    # Disable safe mode if active
    try:
        from safe_mode import is_safe_mode_enabled, disable_safe_mode
        if is_safe_mode_enabled():
            print("Disabling safe mode...")
            if disable_safe_mode("Debug cleanup"):
                print("✓ Safe mode disabled")
            else:
                print("✗ Failed to disable safe mode")
        else:
            print("✓ Safe mode not active")
    except:
        print("⚠ Cannot check/disable safe mode")
    
    # Restore original hash if we tampered it
    hash_file = "hash_records.json"
    if os.path.exists(hash_file):
        # Check if it contains our tampered hash
        with open(hash_file, 'r') as f:
            content = f.read()
            if "TAMPERED_HASH_" in content:
                print("\nRestoring original hash_records.json...")
                backup = hash_file + ".backup"
                if os.path.exists(backup):
                    import shutil
                    shutil.copy2(backup, hash_file)
                    print("✓ Restored from backup")
                else:
                    # Create fresh
                    fresh_data = {
                        "restored.txt": {
                            "hash": "restored_hash",
                            "last_checked": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        }
                    }
                    with open(hash_file, 'w') as f:
                        json.dump(fresh_data, f, indent=2)
                    print("✓ Created fresh hash_records.json")
    
    print("\n✓ Cleanup complete")

def main():
    """Run all debug checks"""
    print("\n" * 2)
    print("=" * 70)
    print("SECURITY FEATURES DEBUGGER")
    print("=" * 70)
    print("Diagnosing why security features aren't working")
    print("=" * 70)
    
    results = []
    
    # Run checks
    results.append(("Import Check", True))  # check_imports() doesn't return bool
    check_imports()
    
    results.append(("Core Integration", check_integrity_core_integration()))
    
    check_config_files()
    
    results.append(("Direct Auto-response", test_auto_response_directly()))
    
    # Ask before tamper test
    print("\n" + "=" * 70)
    print("⚠️  TAMPER DETECTION TEST")
    print("=" * 70)
    response = input("Run tamper detection test? (y/n): ").strip().lower()
    if response == 'y':
        # Backup hash file first
        hash_file = "hash_records.json"
        if os.path.exists(hash_file):
            import shutil
            shutil.copy2(hash_file, hash_file + ".backup")
            print("✓ Backed up hash_records.json")
        
        results.append(("Tamper Detection", test_tamper_detection()))
    else:
        print("Skipping tamper test")
        results.append(("Tamper Detection", "Skipped"))
    
    check_log_for_events()
    
    cleanup_and_reset()
    
    # Summary
    print("\n" + "=" * 70)
    print("DEBUG SUMMARY")
    print("=" * 70)
    
    passed = 0
    total = 0
    
    for test_name, result in results:
        if result == "Skipped":
            print(f"{test_name:30} SKIPPED")
        elif result:
            print(f"{test_name:30} ✓ PASS")
            passed += 1
            total += 1
        elif not result:
            print(f"{test_name:30} ✗ FAIL")
            total += 1
    
    print("\n" + "=" * 70)
    if total > 0:
        print(f"RESULTS: {passed}/{total} tests passed")
    
    print("\nCOMMON FIXES:")
    print("1. Make sure all files are in the same directory:")
    print("   • auto_response.py, safe_mode.py, incident_snapshot.py")
    print("   • security_imports.py (new file from this script)")
    print("   • integrity_core.py (updated with imports)")
    
    print("\n2. Check integrity_core.py has these lines added:")
    print("   - 'from security_imports import ...' at the top")
    print("   - 'handle_tamper_event(\"records\", HASH_RECORD_FILE)' in verify_records_signature_on_disk()")
    print("   - 'handle_tamper_event(\"logs\", LOG_FILE)' in verify_log_signatures()")
    
    print("\n3. If snapshots not generated, check incident_snapshots/ directory exists")
    print("   If not, create it: mkdir incident_snapshots")
    
    print("\n4. Run direct test again:")
    print("   python debug_security.py")
    
    print("\n5. If still not working, check logs for errors:")
    print("   tail -n 50 integrity_log.txt")
    
    print("\n" + "=" * 70)

if __name__ == "__main__":
    main()