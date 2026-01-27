import sys
import os

def get_app_data_dir():
    """
    Get the path where the application should store data (logs, config).
    
    - If running as EXE: Returns the folder containing the .exe file.
    - If running as script: Returns the project root folder.
    """
    if getattr(sys, 'frozen', False):
        # We are running as a PyInstaller bundle (EXE)
        # return the folder where the .exe is located
        return os.path.dirname(sys.executable)
    else:
        # We are running as a normal Python script
        # return the parent directory of 'core' (the project root)
        return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def get_base_path():
    """
    Get the path for internal resources (like icons, default config).
    """
    if getattr(sys, 'frozen', False):
        return sys._MEIPASS
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))