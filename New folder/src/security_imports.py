"""
security_imports.py
Centralized imports for security features to avoid warnings
"""

import os
import sys

# Add current directory to path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# Safe imports with proper error handling
def safe_import(module_name, class_names=None):
    """
    Safely import modules without warnings
    
    Args:
        module_name: Name of module to import
        class_names: List of class names to import (optional)
    
    Returns:
        Imported module or None
    """
    try:
        if class_names:
            # Import specific classes
            import importlib
            module = importlib.import_module(module_name)
            result = {}
            for class_name in class_names:
                if hasattr(module, class_name):
                    result[class_name] = getattr(module, class_name)
                else:
                    result[class_name] = None
            return result
        else:
            # Import entire module
            return __import__(module_name)
    except ImportError as e:
        # Don't print warning here - let calling code handle it
        return None
    except Exception as e:
        # Don't print warning here
        return None

# Try to import all security modules
AUTO_RESPONSE_AVAILABLE = False
SAFE_MODE_AVAILABLE = False
INCIDENT_SNAPSHOT_AVAILABLE = False

# Import auto_response
try:
    from auto_response import (
        trigger_auto_response, 
        handle_tamper_event,
        get_auto_response_engine
    )
    AUTO_RESPONSE_AVAILABLE = True
except ImportError:
    # Create dummy functions if import fails
    def trigger_auto_response(*args, **kwargs):
        print("Warning: auto_response module not available")
        return False
    
    def handle_tamper_event(*args, **kwargs):
        print("Warning: auto_response module not available")
        return False
    
    def get_auto_response_engine(*args, **kwargs):
        return None

# Import safe_mode
try:
    from safe_mode import (
        enable_safe_mode,
        disable_safe_mode,
        is_safe_mode_enabled,
        get_safe_mode_status,
        get_safe_mode_manager
    )
    SAFE_MODE_AVAILABLE = True
except ImportError:
    # Create dummy functions
    def enable_safe_mode(*args, **kwargs):
        print("Warning: safe_mode module not available")
        return False
    
    def disable_safe_mode(*args, **kwargs):
        print("Warning: safe_mode module not available")
        return False
    
    def is_safe_mode_enabled():
        return False
    
    def get_safe_mode_status():
        return {'active': False, 'reason': 'Module not available'}
    
    def get_safe_mode_manager():
        return None

# Import incident_snapshot
try:
    from incident_snapshot import (
        generate_incident_snapshot,
        list_incident_snapshots,
        IncidentSnapshot
    )
    INCIDENT_SNAPSHOT_AVAILABLE = True
except ImportError:
    # Create dummy functions
    def generate_incident_snapshot(*args, **kwargs):
        print("Warning: incident_snapshot module not available")
        return None
    
    def list_incident_snapshots():
        return []
    
    class IncidentSnapshot:
        def __init__(self, *args, **kwargs):
            pass
        
        def generate_incident_snapshot(self, *args, **kwargs):
            return None

# Export availability flags
__all__ = [
    # Auto-response
    'AUTO_RESPONSE_AVAILABLE',
    'trigger_auto_response',
    'handle_tamper_event',
    'get_auto_response_engine',
    
    # Safe mode
    'SAFE_MODE_AVAILABLE',
    'enable_safe_mode',
    'disable_safe_mode',
    'is_safe_mode_enabled',
    'get_safe_mode_status',
    'get_safe_mode_manager',
    
    # Incident snapshot
    'INCIDENT_SNAPSHOT_AVAILABLE',
    'generate_incident_snapshot',
    'list_incident_snapshots',
    'IncidentSnapshot',
    
    # Utility
    'safe_import'
]

# Test imports
if __name__ == "__main__":
    print("Security Imports Test:")
    print(f"Auto-response available: {AUTO_RESPONSE_AVAILABLE}")
    print(f"Safe mode available: {SAFE_MODE_AVAILABLE}")
    print(f"Incident snapshot available: {INCIDENT_SNAPSHOT_AVAILABLE}")