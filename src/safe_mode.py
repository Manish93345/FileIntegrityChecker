"""
safe_mode.py
Safe Mode management for critical security incidents
- Freeze monitoring when dangerous events occur
- Admin notifications
- System lockdown
"""

import json
import os
import time
import threading
from datetime import datetime
import traceback

# Safe Mode state
SAFE_MODE_ACTIVE = False
SAFE_MODE_REASON = ""
SAFE_MODE_START_TIME = None
SAFE_MODE_LOCK = threading.Lock()

# State file
SAFE_MODE_STATE_FILE = "safe_mode_state.json"

class SafeModeManager:
    def __init__(self):
        self.active = False
        self.reason = ""
        self.start_time = None
        self.previous_monitor_state = None
        self._load_state()
    
    def _load_state(self):
        """Load safe mode state from file"""
        try:
            if os.path.exists(SAFE_MODE_STATE_FILE):
                with open(SAFE_MODE_STATE_FILE, 'r') as f:
                    state = json.load(f)
                    self.active = state.get('active', False)
                    self.reason = state.get('reason', '')
                    self.start_time = state.get('start_time')
                    
                    # Update global state
                    global SAFE_MODE_ACTIVE, SAFE_MODE_REASON, SAFE_MODE_START_TIME
                    SAFE_MODE_ACTIVE = self.active
                    SAFE_MODE_REASON = self.reason
                    SAFE_MODE_START_TIME = self.start_time
        except Exception as e:
            print(f"Error loading safe mode state: {e}")
    
    def _save_state(self):
        """Save safe mode state to file"""
        try:
            state = {
                'active': self.active,
                'reason': self.reason,
                'start_time': self.start_time,
                'last_updated': datetime.now().isoformat()
            }
            
            with open(SAFE_MODE_STATE_FILE, 'w') as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            print(f"Error saving safe mode state: {e}")
    
    def enable_safe_mode(self, reason="Unknown critical incident", file_path=None):
        """Enable safe mode and freeze monitoring"""
        with SAFE_MODE_LOCK:
            if self.active:
                print("Safe mode already active")
                return False
            
            try:
                # Log safe mode activation
                from integrity_core import append_log_line
                append_log_line(f"🚨 SAFE MODE ACTIVATED: {reason}", 
                              event_type="SAFE_MODE_ACTIVATED", 
                              severity="CRITICAL")
                
                # Store previous state
                self.previous_monitor_state = self._get_monitor_state()
                
                # Set safe mode state
                self.active = True
                self.reason = reason
                self.start_time = datetime.now().isoformat()
                
                # Update global state
                global SAFE_MODE_ACTIVE, SAFE_MODE_REASON, SAFE_MODE_START_TIME
                SAFE_MODE_ACTIVE = True
                SAFE_MODE_REASON = reason
                SAFE_MODE_START_TIME = self.start_time
                
                # Save state
                self._save_state()
                
                # Notify admin (webhook)
                self._notify_admin(reason, file_path)
                
                # Stop monitoring (if available)
                self._freeze_monitoring()
                
                # Create lockdown file
                self._create_lockdown_file(reason, file_path)
                
                print(f"SAFE MODE ENABLED: {reason}")
                return True
                
            except Exception as e:
                print(f"Error enabling safe mode: {e}")
                traceback.print_exc()
                return False
    
    def disable_safe_mode(self, reason="Manually disabled by admin"):
        """Disable safe mode and restore monitoring"""
        with SAFE_MODE_LOCK:
            if not self.active:
                print("Safe mode not active")
                return False
            
            try:
                # Log safe mode deactivation
                from integrity_core import append_log_line
                append_log_line(f"SAFE MODE DISABLED: {reason}", 
                              event_type="SAFE_MODE_DISABLED", 
                              severity="INFO")
                
                # Reset state
                self.active = False
                self.reason = ""
                self.start_time = None
                
                # Update global state
                global SAFE_MODE_ACTIVE, SAFE_MODE_REASON, SAFE_MODE_START_TIME
                SAFE_MODE_ACTIVE = False
                SAFE_MODE_REASON = ""
                SAFE_MODE_START_TIME = None
                
                # Save state
                self._save_state()
                
                # Restore monitoring (if applicable)
                self._restore_monitoring()
                
                # Remove lockdown file
                self._remove_lockdown_file()
                
                # Notify admin
                self._notify_admin(f"Safe mode disabled: {reason}", None)
                
                print("SAFE MODE DISABLED")
                return True
                
            except Exception as e:
                print(f"Error disabling safe mode: {e}")
                traceback.print_exc()
                return False
    
    def is_safe_mode_active(self):
        """Check if safe mode is active"""
        return self.active
    
    def get_status(self):
        """Get safe mode status information"""
        return {
            'active': self.active,
            'reason': self.reason,
            'start_time': self.start_time,
            'duration': self._get_duration(),
            'lockdown_file': os.path.exists(".lockdown") or os.path.exists("lockdown.flag")
        }
    
    def _get_duration(self):
        """Calculate how long safe mode has been active"""
        if not self.start_time:
            return "Not active"
        
        try:
            start = datetime.fromisoformat(self.start_time)
            now = datetime.now()
            diff = now - start
            
            hours, remainder = divmod(diff.seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            
            if diff.days > 0:
                return f"{diff.days}d {hours}h {minutes}m"
            else:
                return f"{hours}h {minutes}m {seconds}s"
        except:
            return "Unknown"
    
    def _get_monitor_state(self):
        """Get current monitoring state (placeholder for integration)"""
        # This should be implemented based on your monitoring system
        return {
            'monitoring_active': False,  # Placeholder
            'watch_folder': None,
            'verification_interval': 0
        }
    
    def _freeze_monitoring(self):
        """Freeze/stop monitoring activities"""
        try:
            # Import the monitor if available
            from integrity_core import FileIntegrityMonitor
            global _monitor_instance
            
            # Store reference to stop it
            if '_monitor_instance' in globals() and _monitor_instance:
                if hasattr(_monitor_instance, 'stop_monitoring'):
                    _monitor_instance.stop_monitoring()
                    print("Monitoring frozen due to safe mode")
            
        except ImportError:
            print("Monitor module not available for freezing")
        except Exception as e:
            print(f"Error freezing monitoring: {e}")
    
    def _restore_monitoring(self):
        """Restore monitoring activities"""
        try:
            # This is a placeholder - actual implementation depends on your system
            print("Monitoring restoration would happen here")
            
        except Exception as e:
            print(f"Error restoring monitoring: {e}")
    
    def _notify_admin(self, message, file_path):
        """Notify admin about safe mode status"""
        try:
            from integrity_core import send_webhook_safe, CONFIG
            
            if 'webhook_url' in CONFIG and CONFIG['webhook_url']:
                send_webhook_safe(
                    "SAFE_MODE_NOTIFICATION",
                    message,
                    file_path
                )
        except:
            pass
    
    def _create_lockdown_file(self, reason, file_path):
        """Create a lockdown flag file"""
        try:
            lockdown_data = {
                'active': True,
                'reason': reason,
                'file_path': file_path,
                'timestamp': datetime.now().isoformat(),
                'message': "SYSTEM LOCKED - Safe Mode Active"
            }
            
            with open("lockdown.flag", 'w') as f:
                json.dump(lockdown_data, f, indent=2)
            
            # Also create a simple .lockdown file for quick detection
            with open(".lockdown", 'w') as f:
                f.write(f"LOCKDOWN ACTIVE\nReason: {reason}\nTime: {datetime.now()}")
                
        except Exception as e:
            print(f"Error creating lockdown file: {e}")
    
    def _remove_lockdown_file(self):
        """Remove lockdown flag files"""
        try:
            if os.path.exists("lockdown.flag"):
                os.remove("lockdown.flag")
            if os.path.exists(".lockdown"):
                os.remove(".lockdown")
        except:
            pass

# Global safe mode manager instance
_safe_mode_manager = None

def get_safe_mode_manager():
    """Get or create safe mode manager singleton"""
    global _safe_mode_manager
    if _safe_mode_manager is None:
        _safe_mode_manager = SafeModeManager()
    return _safe_mode_manager

def is_safe_mode_enabled():
    """Check if safe mode is enabled"""
    return get_safe_mode_manager().is_safe_mode_active()

def enable_safe_mode(reason="Unknown critical incident", file_path=None):
    """Enable safe mode"""
    return get_safe_mode_manager().enable_safe_mode(reason, file_path)

def disable_safe_mode(reason="Manually disabled"):
    """Disable safe mode"""
    return get_safe_mode_manager().disable_safe_mode(reason)

def get_safe_mode_status():
    """Get safe mode status"""
    return get_safe_mode_manager().get_status()

# Convenience functions for integration
def check_and_enable_safe_mode_for_tamper(tamper_type, file_path):
    """Check for tampering and enable safe mode if needed"""
    if tamper_type in ["records", "logs", "signature"]:
        reason = f"{tamper_type.upper()} tampering detected: {file_path}"
        return enable_safe_mode(reason, file_path)
    return False

if __name__ == "__main__":
    # Test safe mode functionality
    print("Testing Safe Mode System...")
    
    manager = get_safe_mode_manager()
    
    print(f"Initial state: {manager.get_status()}")
    
    # Test enabling safe mode
    print("\nEnabling safe mode...")
    result = manager.enable_safe_mode("Test tampering detected", "/test/file.txt")
    print(f"Enable result: {result}")
    print(f"State after enable: {manager.get_status()}")
    
    time.sleep(2)
    
    # Test disabling safe mode
    print("\nDisabling safe mode...")
    result = manager.disable_safe_mode("Test completed")
    print(f"Disable result: {result}")
    print(f"State after disable: {manager.get_status()}")
    
    print("\nSafe mode test completed!")