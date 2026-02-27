import os
import subprocess
import platform

class LockdownManager:
    def __init__(self):
        # This ensures the tool doesn't crash if run on Linux/Mac in the future
        self.is_windows = platform.system().lower() == "windows"

    def trigger_killswitch(self, folder_path):
        """
        Instantly revokes Write and Delete permissions for Everyone on the folder.
        This completely paralyzes Ransomware trying to encrypt the contents.
        """
        if not self.is_windows:
            return False, "Killswitch is only supported on Windows OS."
        
        if not os.path.exists(folder_path):
            return False, "Folder does not exist."

        try:
            # The Windows icacls command to Deny (W)rite and (D)elete to Everyone.
            # (OI)(CI) means Object Inherit and Container Inherit (applies to all files inside).
            cmd = f'icacls "{folder_path}" /deny Everyone:(OI)(CI)(W,D)'
            
            # Execute silently in the background
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                return True, f"LOCKDOWN SUCCESS: Write permissions revoked for {folder_path}"
            else:
                return False, f"LOCKDOWN FAILED: {result.stderr}"
        except Exception as e:
            return False, f"LOCKDOWN ERROR: {str(e)}"

    def remove_lockdown(self, folder_path):
        """
        Restores normal permissions after the Administrator clears the threat.
        """
        if not self.is_windows:
            return False, "Not on Windows."
            
        try:
            # /remove:d removes the specific Deny rule we created above
            cmd = f'icacls "{folder_path}" /remove:d Everyone'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                return True, f"RESTORE SUCCESS: Permissions restored for {folder_path}"
            else:
                return False, f"RESTORE FAILED: {result.stderr}"
        except Exception as e:
            return False, f"RESTORE ERROR: {str(e)}"

# Global instance
lockdown = LockdownManager()