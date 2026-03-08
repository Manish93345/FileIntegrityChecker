import winreg
import ctypes
import os

def set_usb_read_only(enable=True):
    """
    Modifies the Windows Registry to force all USB storage devices into Read-Only mode.
    Requires Administrator privileges.
    """
    if os.name != 'nt':
        return False, "USB Device Control is only supported on Windows."

    # Check for Admin rights
    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

    if not is_admin:
        return False, "CRITICAL: USB Policy modification requires Administrator privileges!"

    try:
        key_path = r"System\CurrentControlSet\Control\StorageDevicePolicies"
        
        # Try to open the key, create it if it doesn't exist
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
        except FileNotFoundError:
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        
        # 1 = Read Only, 0 = Read/Write
        value = 1 if enable else 0
        
        winreg.SetValueEx(key, "WriteProtect", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        
        status = "LOCKED (Read-Only)" if enable else "UNLOCKED (Read/Write)"
        return True, f"USB Storage Policy successfully updated to: {status}"
        
    except Exception as e:
        return False, f"Registry modification failed: {e}"