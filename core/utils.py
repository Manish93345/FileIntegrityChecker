import sys
import os

def get_base_path():
    """
    Get the path for internal resources (READ-ONLY).
    Used for defaults bundled inside the EXE (like icons, default config).
    """
    if getattr(sys, 'frozen', False):
        # Running as PyInstaller EXE (Temp folder)
        return sys._MEIPASS
    # Running as script
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def get_app_data_dir():
    """
    Get the path for external storage (READ/WRITE).
    Used for Logs, Database, User Config.
    """
    if getattr(sys, 'frozen', False):
        # Running as EXE: Use User's AppData folder to avoid Permission Errors
        # Path: C:\Users\Username\AppData\Local\SecureFIM
        app_data = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "SecureFIM")
        
        # Ensure the directory exists
        if not os.path.exists(app_data):
            try:
                os.makedirs(app_data)
            except OSError:
                pass
        return app_data
        
    # Running as script: Keep using project root
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))