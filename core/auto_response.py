"""
auto_response.py
Auto-response rules based on severity levels
- INFO: Just log
- MEDIUM: Alert + log
- HIGH: Alert + report snapshot
- CRITICAL: Trigger Safe Mode + monitoring freeze
"""

import json
import os
import time
from datetime import datetime
import traceback
import sys



class AutoResponseEngine:
    def __init__(self, config=None):
        self.config = config or {}
        self.response_rules = {
            "INFO": self._handle_info,
            "MEDIUM": self._handle_medium,
            "HIGH": self._handle_high,
            "CRITICAL": self._handle_critical
        }
        
        # Load custom rules if available
        self._load_custom_rules()
        
    def _load_custom_rules(self):
        """Load custom auto-response rules from JSON file"""
        rules_file = "auto_response_rules.json"
        if os.path.exists(rules_file):
            try:
                with open(rules_file, 'r') as f:
                    custom_rules = json.load(f)
                    # Merge with default rules
                    for severity, action in custom_rules.items():
                        if severity in self.response_rules:
                            # Convert string action to function call
                            action_map = {
                                "log_only": self._handle_info,
                                "alert_and_log": self._handle_medium,
                                "alert_and_snapshot": self._handle_high,
                                "safe_mode": self._handle_critical
                            }
                            if action in action_map:
                                self.response_rules[severity] = action_map[action]
            except Exception as e:
                print(f"Error loading custom rules: {e}")
    
    def execute_response(self, severity, event_type, message, file_path=None, data=None):
        """
        Execute auto-response based on severity
        
        Args:
            severity: INFO/MEDIUM/HIGH/CRITICAL
            event_type: Type of event (TAMPERED_RECORDS, etc.)
            message: Description of event
            file_path: Related file path (optional)
            data: Additional data (optional)
        """
        try:
            handler = self.response_rules.get(severity, self._handle_info)
            return handler(event_type, message, file_path, data)
        except Exception as e:
            print(f"Auto-response error: {e}")
            traceback.print_exc()
            return False
    
    def _handle_info(self, event_type, message, file_path=None, data=None):
        """INFO: Just log the event"""
        try:
            from integrity_core import append_log_line
            append_log_line(f"AUTO_RESPONSE_INFO: {message}", 
                          event_type=f"INFO_{event_type}", 
                          severity="INFO")
            return True
        except:
            return False
    
    def _handle_medium(self, event_type, message, file_path=None, data=None):
        """MEDIUM: Alert + log"""
        try:
            from .integrity_core import append_log_line, send_webhook_safe
        except ImportError:
            from core.integrity_core import append_log_line, send_webhook_safe

            
            # Log the event
            append_log_line(f"AUTO_RESPONSE_MEDIUM: {message}", 
                          event_type=f"ALERT_{event_type}", 
                          severity="MEDIUM")
            
            # Send webhook alert (if configured)
            if 'webhook_url' in self.config and self.config['webhook_url']:
                send_webhook_safe(f"ALERT_{event_type}", 
                                f"MEDIUM Alert: {message}", 
                                file_path)
            
            # Could trigger GUI alert here if needed
            return True
        except:
            return False
    
    def _handle_high(self, event_type, message, file_path=None, data=None):
        """HIGH: Alert + report snapshot"""
        try:
            from .integrity_core import append_log_line, send_webhook_safe
        except ImportError:
            from core.integrity_core import append_log_line, send_webhook_safe
            
            # Log the event
            append_log_line(f"AUTO_RESPONSE_HIGH: {message}", 
                        event_type=f"HIGH_ALERT_{event_type}", 
                        severity="HIGH")
            
            # Send webhook alert
            if 'webhook_url' in self.config and self.config['webhook_url']:
                send_webhook_safe(f"HIGH_ALERT_{event_type}", 
                                f"HIGH Alert: {message}", 
                                file_path)
            
            # Generate incident snapshot - FIXED
            try:
                # Check if incident_snapshot is available
                if 'incident_snapshot' in sys.modules:
                    from .incident_snapshot import generate_incident_snapshot
            except ImportError:
                from core.incident_snapshot import generate_incident_snapshot
                
                # Prepare snapshot data
                snapshot_data = {
                    "event_type": event_type,
                    "severity": "HIGH",
                    "message": message,
                    "file_path": file_path,
                    "auto_response": True,
                    "timestamp": datetime.now().isoformat(),
                    "additional_data": data or {}
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
                    append_log_line(f"Incident snapshot created: {os.path.basename(snapshot_file)}", 
                                event_type="INCIDENT_SNAPSHOT_CREATED",
                                severity="INFO")
                else:
                    append_log_line(f"Failed to create snapshot for {event_type}", 
                                event_type="SNAPSHOT_FAILED",
                                severity="MEDIUM")
            except ImportError as e:
                append_log_line(f"Cannot generate snapshot: {e}", 
                            event_type="SNAPSHOT_MODULE_MISSING",
                            severity="MEDIUM")
            except Exception as e:
                append_log_line(f"Snapshot error: {e}", 
                            event_type="SNAPSHOT_ERROR",
                            severity="MEDIUM")
            
            return True
        except Exception as e:
            print(f"Error in _handle_high: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _handle_critical(self, event_type, message, file_path=None, data=None):
        """CRITICAL: Trigger Safe Mode + monitoring freeze"""
        try:
            # 1. Log to main core (Attempt 1)
            try:
                from core.integrity_core import append_log_line
                append_log_line(f"AUTO_RESPONSE_CRITICAL: {message} - ACTIVATING SAFE MODE", 
                            event_type=f"CRITICAL_{event_type}", 
                            severity="CRITICAL")
            except ImportError:
                print(f"CRITICAL: {message}")

            # 2. ACTIVATE SAFE MODE (Guaranteed)
            from core.safe_mode import enable_safe_mode
            enable_safe_mode(
                reason=f"{event_type}: {message}",
                file_path=file_path
            )
            
            # 3. GENERATE SNAPSHOT (Guaranteed)
            from core.incident_snapshot import generate_incident_snapshot
            generate_incident_snapshot(
                event_type=event_type,
                severity="CRITICAL",
                message=message,
                affected_file=file_path
            )
            
            return True
        except Exception as e:
            print(f"Auto-Response Critical Failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _get_recent_events(self, count=10):
        """Get recent events from log file"""
        recent_events = []
        try:
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, 'r') as f:
                    lines = f.readlines()[-count:]  # Last 'count' lines
                    for line in lines:
                        recent_events.append(line.strip())
        except:
            pass
        return recent_events

# Global instance
_auto_response = None

def get_auto_response_engine(config=None):
    """Get or create auto-response engine singleton"""
    global _auto_response
    if _auto_response is None:
        _auto_response = AutoResponseEngine(config)
    return _auto_response

def trigger_auto_response(severity, event_type, message, file_path=None, data=None):
    """Convenience function to trigger auto-response"""
    try:
        from integrity_core import CONFIG
        engine = get_auto_response_engine(CONFIG)
        return engine.execute_response(severity, event_type, message, file_path, data)
    except Exception as e:
        print(f"Error triggering auto-response: {e}")
        return False

# Export common severity triggers
def handle_tamper_event(tamper_type, file_path):
    """Handle tampering events with auto-response"""
    messages = {
        "records": f"Hash records tampered: {file_path}",
        "logs": f"Log files tampered: {file_path}",
        "signature": f"Signature mismatch: {file_path}"
    }
    
    message = messages.get(tamper_type, f"Tampering detected: {file_path}")
    
    return trigger_auto_response(
        severity="CRITICAL",
        event_type=f"TAMPERED_{tamper_type.upper()}",
        message=message,
        file_path=file_path
    )

if __name__ == "__main__":
    # Test the auto-response system
    print("Testing Auto-Response System...")
    
    # Test different severity levels
    test_cases = [
        ("INFO", "TEST_INFO", "This is an INFO level test"),
        ("MEDIUM", "TEST_MEDIUM", "This is a MEDIUM level test"),
        ("HIGH", "TEST_HIGH", "This is a HIGH level test"),
        ("CRITICAL", "TEST_CRITICAL", "This is a CRITICAL level test")
    ]
    
    for severity, event_type, message in test_cases:
        print(f"\nTesting {severity} severity...")
        result = trigger_auto_response(severity, event_type, message)
        print(f"Result: {'Success' if result else 'Failed'}")
        time.sleep(1)
    
    print("\nAuto-response test completed!")