"""
incident_snapshot.py
Generate incident snapshots for critical events
- Timestamp, file, severity
- Last 10 events
- System state at time of incident
"""

import json
import os
import time
import traceback
from datetime import datetime
import hashlib
import shutil

LOG_FILE = "logs/integrity_log.txt"

def _log_direct(message, severity="INFO"):
    """Direct logging to avoid circular imports"""
    try:
        emojis = {"INFO": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}
        icon = emojis.get(severity, "⚪")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{timestamp} - [{icon} {severity}] {message}\n")
    except: pass


class IncidentSnapshot:
    def __init__(self, base_dir="reports/incidents"):
        self.base_dir = base_dir
        self._ensure_directory()
    
    def _ensure_directory(self):
        """Ensure snapshot directory exists"""
        try:
            if not os.path.exists(self.base_dir):
                os.makedirs(self.base_dir)
                print(f"Created incident snapshot directory: {self.base_dir}")
        except Exception as e:
            print(f"Error creating snapshot directory: {e}")
    
    def generate_incident_snapshot(self, event_type, severity, message, 
                                 affected_file=None, additional_data=None):
        try:
            # Generate Filename
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            safe_event = str(event_type).replace(":", "_").replace("/", "_").replace("\\", "_")
            filename = f"incident_{timestamp}_{safe_event}.txt"
            filepath = os.path.join(self.base_dir, filename)
            
            # Collect Data
            snapshot_data = self._collect_snapshot_data(
                event_type, severity, message, affected_file, additional_data
            )
            
            # Write Text File
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(self._format_snapshot(snapshot_data))
            
            # Write JSON File
            json_filepath = filepath.replace('.txt', '.json')
            with open(json_filepath, 'w', encoding='utf-8') as f:
                json.dump(snapshot_data, f, indent=2, default=str)
            
            # Log Success locally
            _log_direct(f"Incident snapshot created: {filename}", "INFO")
            
            # Attempt to copy forensic files
            self._copy_critical_files(filepath)
            
            return filepath
            
        except Exception as e:
            print(f"SNAPSHOT FAILED: {e}")
            traceback.print_exc()
            return None
    
    def _collect_snapshot_data(self, event_type, severity, message, 
                             affected_file, additional_data):
        """Collect all data for the snapshot"""
        timestamp = datetime.now().isoformat()
        
        data = {
            'incident': {
                'event_type': event_type,
                'severity': severity,
                'message': message,
                'affected_file': affected_file,
                'timestamp': timestamp,
                'human_timestamp': now_pretty() if 'now_pretty' in globals() else timestamp
            },
            'system_state': self._get_system_state(),
            'recent_events': self._get_recent_events(10),
            'file_hashes': self._get_critical_file_hashes(),
            'process_info': self._get_process_info(),
            'additional_data': additional_data or {}
        }
        
        return data
    
    def _get_system_state(self):
        """Get current system state"""
        try:
            state = {
                'time': datetime.now().isoformat(),
                'safe_mode': self._check_safe_mode(),
                'monitoring_active': self._check_monitoring_status(),
                'config': self._get_config_summary(),
                'disk_usage': self._get_disk_usage(),
                'critical_files': self._check_critical_files()
            }
            return state
        except Exception as e:
            return {'error': str(e)}
    
    def _check_safe_mode(self):
        """Check if safe mode is active"""
        try:
            import safe_mode
            return safe_mode.is_safe_mode_enabled()
        except ImportError:
            return False
    
    def _check_monitoring_status(self):
        """Check if monitoring is active"""
        try:
            # This depends on your monitoring system
            # Placeholder - implement based on your system
            return {'status': 'unknown', 'details': 'Monitoring status check not implemented'}
        except:
            return {'status': 'error', 'details': 'Failed to check monitoring status'}
    
    def _get_config_summary(self):
        """Get summary of configuration"""
        try:
            if 'CONFIG' in globals():
                config = globals()['CONFIG']
                return {
                    'watch_folder': config.get('watch_folder', 'Not set'),
                    'verify_interval': config.get('verify_interval', 'Not set'),
                    'hash_algo': config.get('hash_algo', 'Not set'),
                    'secret_key_set': bool(config.get('secret_key', False))
                }
            return {'error': 'Config not available'}
        except:
            return {'error': 'Failed to read config'}
    
    def _get_disk_usage(self):
        """Get disk usage information"""
        try:
            import shutil
            usage = shutil.disk_usage(".")
            return {
                'total_gb': round(usage.total / (1024**3), 2),
                'used_gb': round(usage.used / (1024**3), 2),
                'free_gb': round(usage.free / (1024**3), 2),
                'free_percent': round((usage.free / usage.total) * 100, 2)
            }
        except:
            return {'error': 'Failed to get disk usage'}
    
    def _check_critical_files(self):
        """Check existence of critical files"""
        critical_files = [
            LOG_FILE,
            HASH_RECORD_FILE if 'HASH_RECORD_FILE' in globals() else 'hash_records.json',
            'config.json',
            'severity_counters.json'
        ]
        
        results = {}
        for file in critical_files:
            results[file] = {
                'exists': os.path.exists(file),
                'size': os.path.getsize(file) if os.path.exists(file) else 0,
                'modified': datetime.fromtimestamp(os.path.getmtime(file)).isoformat() 
                          if os.path.exists(file) else None
            }
        
        return results
    
    def _get_recent_events(self, count=10):
        """Get recent events from log file"""
        events = []
        try:
            log_file = LOG_FILE if 'LOG_FILE' in globals() else 'integrity_log.txt'
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    recent_lines = lines[-count:] if len(lines) > count else lines
                    for line in recent_lines:
                        events.append(line.strip())
            else:
                events.append("Log file not found")
        except Exception as e:
            events.append(f"Error reading log: {str(e)}")
        
        return events
    
    def _get_critical_file_hashes(self):
        """Get hashes of critical files"""
        files_to_hash = [
            LOG_FILE if 'LOG_FILE' in globals() else 'integrity_log.txt',
            HASH_RECORD_FILE if 'HASH_RECORD_FILE' in globals() else 'hash_records.json',
            'config.json'
        ]
        
        hashes = {}
        for file in files_to_hash:
            if os.path.exists(file):
                try:
                    with open(file, 'rb') as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()[:16]
                    hashes[file] = file_hash
                except Exception as e:
                    hashes[file] = f"Error: {str(e)}"
            else:
                hashes[file] = "File not found"
        
        return hashes
    
    def _get_process_info(self):
        """Get process information"""
        try:
            import psutil
            process = psutil.Process()
            return {
                'pid': process.pid,
                'name': process.name(),
                'cpu_percent': process.cpu_percent(),
                'memory_mb': round(process.memory_info().rss / (1024**2), 2),
                'status': process.status(),
                'create_time': datetime.fromtimestamp(process.create_time()).isoformat()
            }
        except ImportError:
            return {'error': 'psutil not installed'}
        except Exception as e:
            return {'error': str(e)}
    
    def _format_snapshot(self, data):
        """Format snapshot data as readable text"""
        incident = data['incident']
        
        lines = [
            "=" * 60,
            "INCIDENT SNAPSHOT",
            "=" * 60,
            f"Timestamp: {incident['human_timestamp']}",
            f"Event Type: {incident['event_type']}",
            f"Severity: {incident['severity']}",
            f"Affected File: {incident['affected_file'] or 'N/A'}",
            "",
            f"Message: {incident['message']}",
            "",
            "=" * 60,
            "SYSTEM STATE",
            "=" * 60,
        ]
        
        # System state
        state = data['system_state']
        if 'safe_mode' in state:
            lines.append(f"Safe Mode: {'ACTIVE' if state['safe_mode'] else 'INACTIVE'}")
        
        if 'config' in state and isinstance(state['config'], dict):
            lines.append("\nConfiguration:")
            for key, value in state['config'].items():
                lines.append(f"  {key}: {value}")
        
        if 'disk_usage' in state and isinstance(state['disk_usage'], dict):
            lines.append("\nDisk Usage:")
            for key, value in state['disk_usage'].items():
                lines.append(f"  {key}: {value}")
        
        # Recent events
        lines.extend([
            "",
            "=" * 60,
            f"LAST {len(data['recent_events'])} EVENTS",
            "=" * 60,
        ])
        
        for i, event in enumerate(data['recent_events'], 1):
            lines.append(f"{i:2d}. {event}")
        
        # File hashes
        lines.extend([
            "",
            "=" * 60,
            "CRITICAL FILE HASHES (SHA256 first 16 chars)",
            "=" * 60,
        ])
        
        for file, hash_val in data.get('file_hashes', {}).items():
            lines.append(f"{file}: {hash_val}")
        
        # Process info
        if 'process_info' in data and isinstance(data['process_info'], dict):
            lines.extend([
                "",
                "=" * 60,
                "PROCESS INFORMATION",
                "=" * 60,
            ])
            
            for key, value in data['process_info'].items():
                lines.append(f"{key}: {value}")
        
        lines.extend([
            "",
            "=" * 60,
            "END OF SNAPSHOT",
            "=" * 60,
            f"Snapshot generated by Secure File Integrity Monitor",
            f"Full JSON data available in: {os.path.basename(data.get('json_path', 'N/A'))}",
        ])
        
        return "\n".join(lines)
    
    def _log_snapshot_creation(self, filepath, event_type, severity):
        """Log the snapshot creation"""
        try:
            if 'append_log_line' in globals():
                append_log_line(
                    f"Incident snapshot created: {os.path.basename(filepath)} for {event_type}",
                    event_type="INCIDENT_SNAPSHOT_CREATED",
                    severity="INFO"
                )
        except:
            pass
    
    def _copy_critical_files(self, snapshot_path, snapshot_data=None):
        try:
            base_name = os.path.splitext(os.path.basename(snapshot_path))[0]
            forensic_dir = os.path.join(self.base_dir, f"{base_name}_forensic")
            os.makedirs(forensic_dir, exist_ok=True)
            
            # Copy files if they exist
            for f_name in [LOG_FILE, "hash_records.json", "config.json"]:
                if os.path.exists(f_name):
                    try:
                        shutil.copy2(f_name, os.path.join(forensic_dir, f_name))
                    except: pass
        except Exception as e: 
            print(f"Forensic copy error: {e}")

def generate_incident_snapshot(event_type, severity, message, affected_file=None, additional_data=None):
    snapshot = IncidentSnapshot()
    return snapshot.generate_incident_snapshot(
        event_type, severity, message, affected_file, additional_data
    )

def list_incident_snapshots():
    """List all incident snapshots"""
    snapshot_dir = "incident_snapshots"
    if not os.path.exists(snapshot_dir):
        return []
    
    snapshots = []
    for file in os.listdir(snapshot_dir):
        if file.startswith("incident_") and file.endswith(".txt"):
            filepath = os.path.join(snapshot_dir, file)
            stat = os.stat(filepath)
            snapshots.append({
                'filename': file,
                'path': filepath,
                'size': stat.st_size,
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'created': datetime.fromtimestamp(stat.st_ctime).isoformat()
            })
    
    return sorted(snapshots, key=lambda x: x['created'], reverse=True)

if __name__ == "__main__":
    # Test incident snapshot generation
    print("Testing Incident Snapshot System...")
    
    # Create a test snapshot
    snapshot_path = generate_incident_snapshot(
        event_type="TEST_INCIDENT",
        severity="HIGH",
        message="Test incident snapshot generation",
        affected_file="/test/path/file.txt",
        additional_data={"test": "data", "value": 123}
    )
    
    if snapshot_path:
        print(f"Snapshot created: {snapshot_path}")
        
        # List all snapshots
        print("\nAll snapshots:")
        for snapshot in list_incident_snapshots():
            print(f"  - {snapshot['filename']} ({snapshot['size']} bytes)")
    else:
        print("Failed to create snapshot")
    
    print("\nIncident snapshot test completed!")