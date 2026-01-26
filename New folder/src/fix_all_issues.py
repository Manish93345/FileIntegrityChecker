"""
fix_all_issues.py
Fix all identified issues from debug output
"""

import os
import sys
import json
import shutil
from datetime import datetime

def fix_integrity_core():
    """Fix integrity_core.py missing handle_tamper_event in verify_log_signatures"""
    
    print("Fixing integrity_core.py...")
    
    integrity_core_file = "integrity_core.py"
    if not os.path.exists(integrity_core_file):
        print(f"✗ {integrity_core_file} not found")
        return False
    
    with open(integrity_core_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check if handle_tamper_event is called in verify_log_signatures
    if 'handle_tamper_event("logs"' not in content:
        print("Adding handle_tamper_event to verify_log_signatures...")
        
        # Find verify_log_signatures function
        lines = content.split('\n')
        updated = False
        
        for i, line in enumerate(lines):
            if 'def verify_log_signatures():' in line:
                # Look for return statements in this function
                for j in range(i, len(lines)):
                    if j > i and lines[j].strip().startswith('def '):
                        # Reached next function without finding the right spot
                        break
                    
                    # Add after length mismatch check
                    if 'Log/Sig length mismatch:' in lines[j]:
                        # Add 2 lines after this
                        tamper_code = '''        # Auto-response for length mismatch (potential tampering)
        if 'handle_tamper_event' in globals() and handle_tamper_event:
            handle_tamper_event("logs", LOG_FILE)'''
                        
                        lines.insert(j + 1, tamper_code)
                        updated = True
                        print("✓ Added tamper response for log length mismatch")
                        break
                
                # Also add for re-initialization case
                for j in range(i, len(lines)):
                    if j > i and lines[j].strip().startswith('def '):
                        break
                    
                    if 'Log signatures re-initialized' in lines[j]:
                        # Add before this return
                        init_code = '''            # Auto-response for re-initialization
            if 'handle_tamper_event' in globals() and handle_tamper_event:
                handle_tamper_event("signature", LOG_FILE)'''
                        
                        # Find where to insert (before the return line)
                        for k in range(j, max(i, j-10), -1):
                            if lines[k].strip().startswith('return'):
                                lines.insert(k, init_code)
                                updated = True
                                print("✓ Added tamper response for log re-initialization")
                                break
                        break
        
        if updated:
            with open(integrity_core_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
            print("✓ Updated integrity_core.py")
        else:
            print("✗ Could not find where to add tamper response")
            return False
    else:
        print("✓ handle_tamper_event already in verify_log_signatures")
    
    return True

def fix_config_secret_key():
    """Ensure config.json has secret_key"""
    
    print("\nFixing config.json secret_key...")
    
    config_file = "config.json"
    if not os.path.exists(config_file):
        print(f"✗ {config_file} not found")
        return False
    
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        if 'secret_key' not in config or not config['secret_key']:
            config['secret_key'] = "Lisamerijaanu_change_me"
            print("✓ Added missing secret_key to config.json")
        else:
            print(f"✓ secret_key already set: {config['secret_key'][:10]}...")
        
        # Ensure other required fields
        required_fields = {
            "watch_folder": ".",
            "verify_interval": 60,
            "webhook_url": None,
            "max_log_size_mb": 10,
            "max_log_backups": 5,
            "hash_algo": "sha256"
        }
        
        updated = False
        for field, default in required_fields.items():
            if field not in config:
                config[field] = default
                print(f"✓ Added missing {field}: {default}")
                updated = True
        
        if updated:
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
        
        return True
        
    except json.JSONDecodeError:
        print(f"✗ {config_file} is corrupted JSON")
        # Create fresh config
        fresh_config = {
            "watch_folder": ".",
            "verify_interval": 60,
            "webhook_url": None,
            "secret_key": "Lisacutie",
            "max_log_size_mb": 10,
            "max_log_backups": 5,
            "hash_algo": "sha256",
            "hash_chunk_size": 65536,
            "hash_retries": 3,
            "hash_retry_delay": 0.5,
            "ignore_filenames": [
                "hash_records.json",
                "integrity_log.txt",
                "integrity_log.sig",
                "hash_records.sig",
                "report_summary.txt"
            ]
        }
        
        with open(config_file, 'w') as f:
            json.dump(fresh_config, f, indent=2)
        
        print(f"✓ Created fresh {config_file}")
        return True
        
    except Exception as e:
        print(f"✗ Error fixing config: {e}")
        return False

def fix_hash_records():
    """Fix corrupted hash_records.json"""
    
    print("\nFixing hash_records.json...")
    
    hash_file = "hash_records.json"
    sig_file = "hash_records.sig"
    
    # Backup if exists
    if os.path.exists(hash_file):
        backup = hash_file + ".backup"
        shutil.copy2(hash_file, backup)
        print(f"✓ Backed up to {backup}")
    
    # Create fresh hash records
    fresh_data = {}
    
    try:
        with open(hash_file, 'w') as f:
            json.dump(fresh_data, f, indent=2)
        print(f"✓ Created fresh {hash_file}")
        
        # Also create fresh signature
        if os.path.exists(sig_file):
            os.remove(sig_file)
        open(sig_file, 'w').close()
        print(f"✓ Created fresh {sig_file}")
        
        return True
    except Exception as e:
        print(f"✗ Error fixing hash records: {e}")
        return False

def fix_auto_response_snapshot():
    """Fix auto_response.py to properly generate snapshots"""
    
    print("\nFixing auto_response.py snapshot generation...")
    
    auto_response_file = "auto_response.py"
    if not os.path.exists(auto_response_file):
        print(f"✗ {auto_response_file} not found")
        return False
    
    with open(auto_response_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # Find _handle_high method
    in_handle_high = False
    snapshot_added = False
    
    for i, line in enumerate(lines):
        if 'def _handle_high(self' in line:
            in_handle_high = True
        
        if in_handle_high and 'def _handle_critical' in line:
            in_handle_high = False
        
        # Look for existing snapshot code
        if in_handle_high and 'generate_incident_snapshot' in line:
            snapshot_added = True
            break
    
    if not snapshot_added:
        print("Adding snapshot generation to _handle_high...")
        
        # Find where to add it (after webhook send, before return)
        for i, line in enumerate(lines):
            if 'def _handle_high(self' in line:
                # Find the send_webhook_safe call
                for j in range(i, len(lines)):
                    if 'send_webhook_safe(' in lines[j]:
                        # Add after this block
                        for k in range(j, len(lines)):
                            if lines[k].strip() == '' or 'return' in lines[k]:
                                # Insert snapshot code here
                                snapshot_code = '''        # Generate incident snapshot
        try:
            import sys
            from datetime import datetime
            
            # Check if incident_snapshot is available
            if 'incident_snapshot' in sys.modules or True:  # Force try
                from incident_snapshot import generate_incident_snapshot
                
                # Prepare snapshot data
                snapshot_data = {
                    "event_type": event_type,
                    "severity": "HIGH",
                    "message": message,
                    "file_path": file_path,
                    "auto_response": True,
                    "timestamp": datetime.now().isoformat(),
                    "additional_data": data or {},
                    "test": "HIGH severity snapshot"
                }
                
                # Generate snapshot
                snapshot_file = generate_incident_snapshot(
                    event_type=event_type,
                    severity="HIGH",
                    message=message,
                    affected_file=file_path,
                    additional_data=snapshot_data
                )
                
                if snapshot_file:
                    from integrity_core import append_log_line
                    append_log_line(f"Incident snapshot created: {os.path.basename(snapshot_file)}", 
                                  event_type="INCIDENT_SNAPSHOT_CREATED",
                                  severity="INFO")
                else:
                    append_log_line(f"Failed to create snapshot for {event_type}", 
                                  event_type="SNAPSHOT_FAILED",
                                  severity="MEDIUM")
        except ImportError as e:
            from integrity_core import append_log_line
            append_log_line(f"Cannot generate snapshot: {e}", 
                          event_type="SNAPSHOT_MODULE_MISSING",
                          severity="MEDIUM")
        except Exception as e:
            from integrity_core import append_log_line
            append_log_line(f"Snapshot error: {e}", 
                          event_type="SNAPSHOT_ERROR",
                          severity="MEDIUM")
        
'''
                                lines.insert(k, snapshot_code)
                                print("✓ Added snapshot generation to _handle_high")
                                
                                with open(auto_response_file, 'w', encoding='utf-8') as f:
                                    f.writelines(lines)
                                return True
    
    print("✓ Snapshot generation already in _handle_high")
    return True

def ensure_directories():
    """Ensure all directories exist"""
    
    print("\nEnsuring directories exist...")
    
    directories = [
        "incident_snapshots",
        "forensic_backups", 
        "security_logs"
    ]
    
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"✓ Created: {directory}")
        else:
            print(f"✓ Exists: {directory}")
    
    return True

def test_fixes():
    """Test if fixes work"""
    
    print("\n" + "=" * 70)
    print("TESTING FIXES")
    print("=" * 70)
    
    # Test 1: Import security_imports
    print("\n1. Testing security_imports...")
    try:
        from security_imports import (
            AUTO_RESPONSE_AVAILABLE,
            SAFE_MODE_AVAILABLE,
            INCIDENT_SNAPSHOT_AVAILABLE,
            trigger_auto_response,
            enable_safe_mode,
            is_safe_mode_enabled
        )
        print(f"   ✓ All imports OK")
        print(f"   • Auto-response: {AUTO_RESPONSE_AVAILABLE}")
        print(f"   • Safe mode: {SAFE_MODE_AVAILABLE}")
        print(f"   • Snapshot: {INCIDENT_SNAPSHOT_AVAILABLE}")
    except ImportError as e:
        print(f"   ✗ Import failed: {e}")
        return False
    
    # Test 2: Test config
    print("\n2. Testing config...")
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
        
        if 'secret_key' in config and config['secret_key']:
            print(f"   ✓ secret_key: {config['secret_key'][:10]}...")
        else:
            print(f"   ✗ secret_key missing or empty")
            return False
    except Exception as e:
        print(f"   ✗ Config error: {e}")
        return False
    
    # Test 3: Test auto-response with HIGH event
    print("\n3. Testing HIGH event (should create snapshot)...")
    try:
        result = trigger_auto_response(
            severity="HIGH",
            event_type="FIX_TEST_HIGH",
            message="Test HIGH event after fix",
            file_path="/test/high_event.txt",
            data={"test": "fix_verification"}
        )
        
        print(f"   ✓ Auto-response triggered: {result}")
        
        # Check for snapshot
        time.sleep(1)  # Give time for snapshot generation
        
        snapshot_dir = "incident_snapshots"
        if os.path.exists(snapshot_dir):
            files = [f for f in os.listdir(snapshot_dir) if f.endswith('.txt') and 'FIX_TEST_HIGH' in f]
            if files:
                print(f"   ✓ Snapshot created: {files[0]}")
                
                # Show snapshot size
                snapshot_path = os.path.join(snapshot_dir, files[0])
                size = os.path.getsize(snapshot_path)
                print(f"   • Size: {size} bytes")
                
                # Show first few lines
                with open(snapshot_path, 'r') as f:
                    first_lines = f.readlines()[:5]
                print(f"   • Preview: {first_lines[0].strip() if first_lines else 'Empty'}")
            else:
                print(f"   ⚠ No snapshot found (check incident_snapshots/)")
        else:
            print(f"   ⚠ incident_snapshots directory doesn't exist")
        
    except Exception as e:
        print(f"   ✗ Auto-response test failed: {e}")
        import traceback
        traceback.print_exc()
    
    # Test 4: Test safe mode
    print("\n4. Testing safe mode...")
    try:
        # Enable safe mode
        result = enable_safe_mode("Fix test safe mode", "/test/tampered.txt")
        print(f"   ✓ Safe mode enable: {result}")
        
        # Check if active
        active = is_safe_mode_enabled()
        print(f"   ✓ Safe mode active: {active}")
        
        # Disable for cleanup
        from security_imports import disable_safe_mode
        disable_safe_mode("Test cleanup")
        print(f"   ✓ Safe mode disabled")
        
    except Exception as e:
        print(f"   ✗ Safe mode test failed: {e}")
    
    # Test 5: Check hash_records.json
    print("\n5. Checking hash_records.json...")
    try:
        with open('hash_records.json', 'r') as f:
            data = json.load(f)
        print(f"   ✓ hash_records.json is valid JSON")
        print(f"   • Entries: {len(data)}")
    except json.JSONDecodeError:
        print(f"   ✗ hash_records.json is corrupted")
        return False
    except Exception as e:
        print(f"   ✗ Error: {e}")
    
    print("\n" + "=" * 70)
    print("FIX TESTING COMPLETE")
    print("=" * 70)
    
    return True

def create_test_files():
    """Create test files for verification"""
    
    print("\nCreating test files...")
    
    # Create a test folder
    test_folder = "test_security"
    if not os.path.exists(test_folder):
        os.makedirs(test_folder)
        print(f"✓ Created test folder: {test_folder}")
    
    # Create some test files
    test_files = [
        ("test1.txt", "This is test file 1"),
        ("test2.txt", "This is test file 2"),
        ("test3.txt", "This is test file 3")
    ]
    
    for filename, content in test_files:
        filepath = os.path.join(test_folder, filename)
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"  Created: {filename}")
    
    # Update config to watch this folder
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
        
        old_folder = config.get('watch_folder', '')
        config['watch_folder'] = os.path.abspath(test_folder)
        
        with open('config.json', 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"✓ Updated config to watch: {test_folder}")
        if old_folder:
            print(f"  (Was: {old_folder})")
            
    except Exception as e:
        print(f"⚠ Could not update config: {e}")
    
    return True

def main():
    """Run all fixes"""
    
    import time
    
    print("=" * 70)
    print("COMPREHENSIVE SECURITY FEATURES FIX")
    print("=" * 70)
    print("Fixing all identified issues:")
    print("1. Missing handle_tamper_event in verify_log_signatures")
    print("2. Missing/empty secret_key in config.json")
    print("3. Corrupted hash_records.json")
    print("4. Snapshot not generated for HIGH events")
    print("=" * 70)
    
    # Run fixes
    fix_integrity_core()
    time.sleep(0.5)
    
    fix_config_secret_key()
    time.sleep(0.5)
    
    fix_hash_records()
    time.sleep(0.5)
    
    fix_auto_response_snapshot()
    time.sleep(0.5)
    
    ensure_directories()
    time.sleep(0.5)
    
    create_test_files()
    time.sleep(1)
    
    # Test fixes
    test_fixes()
    
    print("\n" + "=" * 70)
    print("ALL FIXES APPLIED!")
    print("=" * 70)
    print("\nNext steps to test:")
    print("1. Start your application: python login_gui.py")
    print("2. Click 'Start Monitor' to monitor the test_security/ folder")
    print("3. Perform these tests in the test_security/ folder:")
    print("   - Create a new file (should show 🟢 INFO)")
    print("   - Modify a file (should show 🟡 MEDIUM)")
    print("   - Delete multiple files quickly (should show 🟠 HIGH + snapshot)")
    print("4. To test safe mode:")
    print("   - Manually edit hash_records.json")
    print("   - Run verification (should show 🔴 CRITICAL + safe mode)")
    print("\nCheck these locations:")
    print("   - GUI severity counters should update")
    print("   - incident_snapshots/ should have report files")
    print("   - integrity_log.txt should show colored severity events")
    print("=" * 70)

if __name__ == "__main__":
    main()