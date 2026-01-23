"""
test_security_features.py
Test script for security features (testing only, not for production)
Run this to verify all security features work correctly
"""

import os
import sys
import time
import json
from datetime import datetime

def setup_test_environment():
    """Create test environment"""
    print("Setting up test environment...")
    
    if not os.path.exists("test_logs"):
        os.makedirs("test_logs")
    
    if not os.path.exists("config.json"):
        test_config = {
            "watch_folder": ".",
            "verify_interval": 60,
            "webhook_url": None,
            "secret_key": "test_secret_key",
            "max_log_size_mb": 10,
            "max_log_backups": 5,
            "hash_algo": "sha256"
        }
        with open("config.json", 'w') as f:
            json.dump(test_config, f, indent=2)
        print("✓ Created test config.json")
    
    if not os.path.exists("integrity_log.txt"):
        with open("integrity_log.txt", 'w') as f:
            f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Test log started\n")
        print("✓ Created test integrity_log.txt")
    
    return True

def test_auto_response():
    """Test auto-response system"""
    print("\n" + "=" * 60)
    print("TEST 1: AUTO-RESPONSE SYSTEM")
    print("=" * 60)
    
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from auto_response import trigger_auto_response, handle_tamper_event
        
        print("\n1. Testing INFO severity...")
        result = trigger_auto_response(
            severity="INFO",
            event_type="TEST_INFO",
            message="Information level test event",
            file_path="/test/file.txt"
        )
        print(f"   Result: {'✓ PASS' if result else '✗ FAIL'}")
        
        time.sleep(0.5)
        
        print("\n2. Testing MEDIUM severity...")
        result = trigger_auto_response(
            severity="MEDIUM",
            event_type="TEST_MEDIUM",
            message="Medium severity test",
            file_path="/test/important.txt"
        )
        print(f"   Result: {'✓ PASS' if result else '✗ FAIL'}")
        
        time.sleep(0.5)
        
        print("\n3. Testing HIGH severity...")
        result = trigger_auto_response(
            severity="HIGH",
            event_type="TEST_HIGH",
            message="High severity test",
            file_path="/test/critical.txt"
        )
        print(f"   Result: {'✓ PASS' if result else '✗ FAIL'}")
        
        time.sleep(0.5)
        
        print("\n4. Testing CRITICAL severity...")
        result = trigger_auto_response(
            severity="CRITICAL",
            event_type="TEST_CRITICAL",
            message="Critical severity test",
            file_path="/test/tampered.json"
        )
        print(f"   Result: {'✓ PASS' if result else '✗ FAIL'}")
        
        time.sleep(0.5)
        
        print("\n5. Testing tamper event handler...")
        result = handle_tamper_event("records", "/test/hash_records.json")
        print(f"   Result: {'✓ PASS' if result else '✗ FAIL'}")
        
        print("\n✓ Auto-response tests completed")
        return True
        
    except Exception as e:
        print(f"\n✗ Auto-response test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_safe_mode():
    """Test safe mode system"""
    print("\n" + "=" * 60)
    print("TEST 2: SAFE MODE SYSTEM")
    print("=" * 60)
    
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from safe_mode import enable_safe_mode, disable_safe_mode, is_safe_mode_enabled, get_safe_mode_status
        
        print("\n1. Enabling safe mode...")
        result = enable_safe_mode(
            reason="Test: Tampering detected in hash records",
            file_path="/test/hash_records.json"
        )
        print(f"   Result: {'✓ Enabled' if result else '✗ Failed'}")
        
        if result:
            status = get_safe_mode_status()
            print(f"   Status: Active={status.get('active', False)}")
            print(f"   Reason: {status.get('reason', 'N/A')}")
            
            active = is_safe_mode_enabled()
            print(f"   Check: {'✓ Active' if active else '✗ Not active'}")
        
        time.sleep(1)
        
        print("\n2. Disabling safe mode...")
        result = disable_safe_mode(reason="Test completed")
        print(f"   Result: {'✓ Disabled' if result else '✗ Failed'}")
        
        if result:
            active = is_safe_mode_enabled()
            print(f"   Check: {'✓ Inactive' if not active else '✗ Still active (error)'}")
        
        print("\n✓ Safe mode tests completed")
        return True
        
    except Exception as e:
        print(f"\n✗ Safe mode test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_incident_snapshot():
    """Test incident snapshot system"""
    print("\n" + "=" * 60)
    print("TEST 3: INCIDENT SNAPSHOT SYSTEM")
    print("=" * 60)
    
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from incident_snapshot import generate_incident_snapshot, list_incident_snapshots
        
        print("\n1. Generating HIGH severity snapshot...")
        snapshot_path = generate_incident_snapshot(
            event_type="TEST_SECURITY_BREACH",
            severity="HIGH",
            message="Test security breach detected",
            affected_file="/test/sensitive_data.txt",
            additional_data={
                "test_id": "TEST-001",
                "user": "security_tester",
                "action": "unauthorized_access"
            }
        )
        
        if snapshot_path and os.path.exists(snapshot_path):
            file_size = os.path.getsize(snapshot_path)
            print(f"   ✓ Snapshot created: {os.path.basename(snapshot_path)}")
            print(f"   Size: {file_size} bytes")
        else:
            print(f"   ✗ Failed to create snapshot")
            return False
        
        time.sleep(0.5)
        
        print("\n2. Generating CRITICAL severity snapshot...")
        snapshot_path = generate_incident_snapshot(
            event_type="TEST_CRITICAL_TAMPER",
            severity="CRITICAL",
            message="Critical tampering detected",
            affected_file="/test/hash_records.json",
            additional_data={
                "test_id": "TEST-002",
                "severity": "CRITICAL",
                "response": "safe_mode_activated"
            }
        )
        
        if snapshot_path and os.path.exists(snapshot_path):
            file_size = os.path.getsize(snapshot_path)
            print(f"   ✓ Snapshot created: {os.path.basename(snapshot_path)}")
            print(f"   Size: {file_size} bytes")
        else:
            print(f"   ✗ Failed to create snapshot")
        
        time.sleep(0.5)
        
        print("\n3. Listing all snapshots...")
        snapshots = list_incident_snapshots()
        
        if snapshots:
            print(f"   Found {len(snapshots)} snapshot(s):")
            for i, snap in enumerate(snapshots[:3], 1):
                print(f"   {i}. {snap['filename']} ({snap['size']} bytes)")
            
            if len(snapshots) > 3:
                print(f"   ... and {len(snapshots) - 3} more")
        else:
            print("   ✗ No snapshots found")
        
        print("\n✓ Incident snapshot tests completed")
        return True
        
    except Exception as e:
        print(f"\n✗ Incident snapshot test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_integrated_features():
    """Test integrated features working together"""
    print("\n" + "=" * 60)
    print("TEST 4: INTEGRATED FEATURES")
    print("=" * 60)
    
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from auto_response import handle_tamper_event
        from safe_mode import is_safe_mode_enabled, disable_safe_mode
        from incident_snapshot import list_incident_snapshots
        
        print("\n1. Testing tamper event triggers safe mode...")
        
        tamper_types = ["records", "logs", "signature"]
        results = []
        
        for tamper_type in tamper_types:
            print(f"\n   Testing {tamper_type} tamper...")
            
            initial_snapshots = len(list_incident_snapshots())
            
            result = handle_tamper_event(
                tamper_type=tamper_type,
                file_path=f"/test/{tamper_type}_file.bin"
            )
            
            safe_mode_active = is_safe_mode_enabled()
            final_snapshots = len(list_incident_snapshots())
            
            snapshot_created = final_snapshots > initial_snapshots
            
            print(f"     Auto-response: {'✓ OK' if result else '✗ Failed'}")
            print(f"     Safe mode: {'✓ Activated' if safe_mode_active else '✗ Not activated'}")
            print(f"     Snapshot: {'✓ Created' if snapshot_created else '✗ Not created'}")
            
            if safe_mode_active:
                disable_safe_mode("Cleaning up for next test")
            
            time.sleep(0.5)
            
            test_passed = result and safe_mode_active and snapshot_created
            results.append((tamper_type, test_passed))
        
        passed_count = sum(1 for _, passed in results if passed)
        
        if passed_count == len(tamper_types):
            print("\n✓ All integrated tests passed")
            return True
        else:
            print(f"\n✗ {len(tamper_types) - passed_count}/{len(tamper_types)} integrated tests failed")
            return False
        
    except Exception as e:
        print(f"\n✗ Integrated features test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def cleanup_test():
    """Clean up test files"""
    print("\n" + "=" * 60)
    print("CLEANUP")
    print("=" * 60)
    
    files_to_remove = []
    if os.path.exists("config.json"):
        try:
            with open("config.json", 'r') as f:
                content = f.read()
                if "test_secret_key" in content:
                    files_to_remove.append("config.json")
        except:
            pass
    
    for file in files_to_remove:
        try:
            os.remove(file)
            print(f"✓ Removed test file: {file}")
        except:
            print(f"✗ Failed to remove: {file}")
    
    print("\nNote: Test snapshots remain in incident_snapshots/ for inspection")
    return True

def main():
    """Run all tests"""
    print("=" * 60)
    print("SECURITY FEATURES TEST SUITE")
    print("=" * 60)
    print("Note: This is a test script only, not for production use")
    print("=" * 60)
    
    setup_test_environment()
    
    results = []
    
    results.append(("Auto-Response", test_auto_response()))
    time.sleep(1)
    
    results.append(("Safe Mode", test_safe_mode()))
    time.sleep(1)
    
    results.append(("Incident Snapshot", test_incident_snapshot()))
    time.sleep(1)
    
    results.append(("Integrated Features", test_integrated_features()))
    
    cleanup_test()
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{test_name:20} {status}")
        if result:
            passed += 1
    
    print("\n" + "=" * 60)
    print(f"RESULTS: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 ALL SECURITY FEATURES ARE WORKING CORRECTLY!")
        print("\nYou can now integrate these features into your main application.")
        print("Start your application with: python login_gui.py")
    else:
        print(f"\n⚠️  {total - passed} test(s) failed.")
        print("Check the error messages above and fix the issues.")
    
    print("\n" + "=" * 60)
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)