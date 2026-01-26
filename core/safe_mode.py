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
import hashlib  # <--- CRITICAL FIX: Added missing import
import hmac     # <--- CRITICAL FIX: Added missing import
from datetime import datetime
import traceback

# Safe Mode state
SAFE_MODE_ACTIVE = False
SAFE_MODE_REASON = ""
SAFE_MODE_START_TIME = None
SAFE_MODE_LOCK = threading.Lock()

# State file
SAFE_MODE_STATE_FILE = "logs/safe_mode_state.json"
LOG_FILE = "logs/integrity_log.txt"
LOG_SIG_FILE = "logs/integrity_log.sig"

def _log_direct(message, severity="INFO"):
    """
    Directly append to log file AND SIGN IT to avoid integrity mismatches.
    """
    try:
        # 1. Get Config (for Secret Key)
        secret = "Lisacutie" # Default
        algo = "sha256"
        
        # Try to find config.json in current or parent dir
        config_path = "config.json"
        if not os.path.exists(config_path):
             config_path = os.path.join(os.path.dirname(__file__), "config.json")

        if os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    cfg = json.load(f)
                    secret = cfg.get("secret_key", secret)
                    algo = cfg.get("hash_algo", algo)
            except: pass

        # 2. Prepare Log Line
        emojis = {"INFO": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}
        icon = emojis.get(severity, "⚪")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # The content line (without newline)
        log_content = f"{timestamp} - [{icon} {severity}] {message}"
        
        # 3. Write Log
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_content + "\n")
            f.flush()
            os.fsync(f.fileno())
            
        # 4. Generate & Write Signature
        # Format must match integrity_core: line|UNKNOWN|severity
        payload = f"{log_content}|UNKNOWN|{severity}"
        h = getattr(hashlib, algo)
        sig = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), h).hexdigest()
        
        with open(LOG_SIG_FILE, "a", encoding="utf-8") as f:
            f.write(sig + "\n")
            f.flush()
            os.fsync(f.fileno())
            
    except Exception as e:
        print(f"SafeMode Log Error: {e}")
        traceback.print_exc()

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
        with SAFE_MODE_LOCK:
            if self.active:
                return True
            
            try:
                # 1. Update Internal State
                self.active = True
                self.reason = reason
                self.start_time = datetime.now().isoformat()
                
                # 2. Update Globals
                global SAFE_MODE_ACTIVE, SAFE_MODE_REASON, SAFE_MODE_START_TIME
                SAFE_MODE_ACTIVE = True
                SAFE_MODE_REASON = reason
                SAFE_MODE_START_TIME = self.start_time
                
                # 3. Create Lockdown Files (The physical proof of safe mode)
                self._create_lockdown_file(reason, file_path)
                self._save_state()
                
                # 4. Log it (Using local function, no imports!)
                _log_direct(f"🚨 SAFE MODE ACTIVATED: {reason}", "CRITICAL")
                print(f"SAFE MODE ENABLED: {reason}")
                
                return True
            except Exception as e:
                print(f"Error enabling safe mode: {e}")
                traceback.print_exc()
                return False
    
    def disable_safe_mode(self, reason="Manually disabled"):
        """Disable safe mode and force cleanup of lock files"""
        with SAFE_MODE_LOCK:
            # --- FIX: REMOVED THE "if not self.active" CHECK ---
            # We want to force cleanup regardless of internal state
            # because the GUI relies on the file existence.
            
            try:
                self.active = False
                self.reason = ""
                self.start_time = None
                
                global SAFE_MODE_ACTIVE
                SAFE_MODE_ACTIVE = False
                
                self._save_state()
                
                # Always force remove the files
                self._remove_lockdown_file()
                
                # Log it
                _log_direct(f"SAFE MODE DISABLED: {reason}", "INFO")
                
                print("SAFE MODE DISABLED")
                return True
            except Exception as e:
                print(f"Error disabling safe mode: {e}")
                # Even if logging fails, try to return True if files are gone
                if not os.path.exists("lockdown.flag"):
                    return True
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
            try:
                from integrity_core import FileIntegrityMonitor
                # Get the global monitor instance if it exists
                import integrity_core
                
                # Check if monitor is running in the GUI
                if hasattr(integrity_core, '_global_monitor'):
                    monitor = integrity_core._global_monitor
                    if monitor and hasattr(monitor, 'stop_monitoring'):
                        monitor.stop_monitoring()
                        print("✓ Monitoring frozen due to safe mode")
                        
                        # Log the freeze
                        try:
                            from integrity_core import append_log_line
                            append_log_line("MONITORING FROZEN: Safe mode activated", 
                                        event_type="MONITORING_FROZEN",
                                        severity="CRITICAL")
                        except:
                            pass
                else:
                    print("⚠️ No active monitor found to freeze")
                    
            except ImportError:
                print("Monitor module not available for freezing")
                
        except Exception as e:
            print(f"Error freezing monitoring: {e}")
            import traceback
            traceback.print_exc()
    
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