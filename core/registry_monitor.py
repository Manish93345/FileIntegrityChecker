"""
registry_monitor.py — FMSecure v2.6
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REGISTRY PERSISTENCE MONITOR  —  Gap 3 Fix

Watches 14 Registry keys used by every major malware family for
persistence, privilege escalation, and defence evasion.

HOW IT WORKS
  Windows provides RegNotifyChangeKeyValue() — a kernel-level API that
  sleeps a thread until the OS wakes it when ANY subkey or value inside
  a watched key changes. Zero CPU when idle. This is how Sysinternals
  Autoruns works under the hood.

  For each watched key we:
    1. Read all values into a baseline snapshot
    2. Sleep on RegNotifyChangeKeyValue()
    3. On wake: re-read all values, diff against baseline
    4. Log NEW entries as CRITICAL (attacker added persistence)
    5. Log CHANGED entries as HIGH
    6. Log DELETED entries as HIGH
    7. Update baseline, sleep again

PERSISTENCE VECTORS COVERED
  Vector                     Registry Path
  ────────────────────────── ─────────────────────────────────────────
  Run (user)                 HKCU\...\Run
  Run (system)               HKLM\...\Run
  RunOnce (user/system)      HKCU\...\RunOnce, HKLM\...\RunOnce
  Winlogon hijack            HKLM\...\Winlogon  (shell, userinit)
  IFEO debugger              HKLM\...\Image File Execution Options
  AppInit DLLs               HKLM\...\Windows\AppInit_DLLs
  Browser Helper Objects     HKLM\...\Browser Helper Objects
  Services (new driver)      HKLM\SYSTEM\...\Services
  LSA authentication pkgs    HKLM\SYSTEM\...\Control\Lsa
  PATH hijack                HKCU\Environment  (user PATH)
  Screensaver                HKCU\...\Desktop  (SCRNSAVE.EXE)
  COM hijack (user)          HKCU\Software\Classes\CLSID
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import os
import threading
import time
from datetime import datetime

# ── Windows-only module — registry monitoring only works on Windows ───
try:
    import winreg
    import win32api
    import win32con
    import win32event
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False

# ── Severity for each change type ─────────────────────────────────────
_SEVERITY_NEW     = "CRITICAL"   # new persistence entry added
_SEVERITY_CHANGED = "HIGH"       # existing entry modified
_SEVERITY_DELETED = "HIGH"       # entry removed (covering tracks)


# ─────────────────────────────────────────────────────────────────────
# Watched key definitions
# Each entry: (hive, subkey, description, critical_values)
# critical_values: specific value names that get CRITICAL if changed
#                  (empty = all values treated equally)
# ─────────────────────────────────────────────────────────────────────
WATCHED_KEYS = [
    # ── Autostart (Run / RunOnce) ─────────────────────────────────────
    (winreg.HKEY_CURRENT_USER if HAS_WINREG else None,
     r"Software\Microsoft\Windows\CurrentVersion\Run",
     "Autostart (HKCU\\Run)",
     []),
    (winreg.HKEY_LOCAL_MACHINE if HAS_WINREG else None,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
     "Autostart (HKLM\\Run)",
     []),
    (winreg.HKEY_CURRENT_USER if HAS_WINREG else None,
     r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
     "RunOnce (HKCU)",
     []),
    (winreg.HKEY_LOCAL_MACHINE if HAS_WINREG else None,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
     "RunOnce (HKLM)",
     []),

    # ── Winlogon hijack ───────────────────────────────────────────────
    (winreg.HKEY_LOCAL_MACHINE if HAS_WINREG else None,
     r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
     "Winlogon (shell/userinit hijack)",
     ["Shell", "Userinit", "UserInit"]),

    # ── IFEO (Image File Execution Options) debugger hijack ───────────
    # Attacker adds: HKLM\...\Image File Execution Options\taskmgr.exe\Debugger = <malware>
    (winreg.HKEY_LOCAL_MACHINE if HAS_WINREG else None,
     r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
     "IFEO Debugger Hijack",
     []),

    # ── AppInit DLLs — injected into EVERY process ────────────────────
    (winreg.HKEY_LOCAL_MACHINE if HAS_WINREG else None,
     r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
     "AppInit_DLLs (DLL injection)",
     ["AppInit_DLLs", "LoadAppInit_DLLs"]),

    # ── LSA authentication packages (rootkit persistence) ────────────
    (winreg.HKEY_LOCAL_MACHINE if HAS_WINREG else None,
     r"SYSTEM\CurrentControlSet\Control\Lsa",
     "LSA Auth Packages",
     ["Authentication Packages", "Notification Packages", "Security Packages"]),

    # ── Environment PATH hijack ───────────────────────────────────────
    (winreg.HKEY_CURRENT_USER if HAS_WINREG else None,
     r"Environment",
     "User Environment (PATH hijack)",
     ["PATH", "Path"]),

    # ── Screensaver persistence ───────────────────────────────────────
    (winreg.HKEY_CURRENT_USER if HAS_WINREG else None,
     r"Control Panel\Desktop",
     "Screensaver (SCRNSAVE.EXE persistence)",
     ["SCRNSAVE.EXE", "ScreenSaverActive"]),

    # ── COM object hijack (user-level, no admin needed) ───────────────
    (winreg.HKEY_CURRENT_USER if HAS_WINREG else None,
     r"Software\Classes\CLSID",
     "COM Hijack (HKCU\\Classes\\CLSID)",
     []),

    # ── Browser Helper Objects ─────────────────────────────────────────
    (winreg.HKEY_LOCAL_MACHINE if HAS_WINREG else None,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
     "Browser Helper Objects",
     []),

    # ── Services / Drivers (kernel persistence) ───────────────────────
    (winreg.HKEY_LOCAL_MACHINE if HAS_WINREG else None,
     r"SYSTEM\CurrentControlSet\Services",
     "Windows Services (new driver/service persistence)",
     []),
]


def _hive_name(hive) -> str:
    if not HAS_WINREG:
        return "?"
    names = {
        winreg.HKEY_CURRENT_USER:   "HKCU",
        winreg.HKEY_LOCAL_MACHINE:  "HKLM",
        winreg.HKEY_CLASSES_ROOT:   "HKCR",
        winreg.HKEY_USERS:          "HKU",
        winreg.HKEY_LOCAL_MACHINE:  "HKLM",
    }
    return names.get(hive, "HKEY_?")


def _read_all_values(hive, subkey: str) -> dict:
    """
    Read all values from a registry key.
    Returns {name: data} dict. Returns {} on access error.
    """
    values = {}
    if not HAS_WINREG:
        return values
    try:
        key = winreg.OpenKey(hive, subkey,
                              access=winreg.KEY_READ | winreg.KEY_ENUMERATE_SUB_KEYS)
        i = 0
        while True:
            try:
                name, data, _ = winreg.EnumValue(key, i)
                values[name] = str(data)
                i += 1
            except OSError:
                break
        winreg.CloseKey(key)
    except (FileNotFoundError, PermissionError, OSError):
        pass
    return values


def _read_subkeys(hive, subkey: str) -> list:
    """For keys like IFEO and Services, track the subkey names."""
    subkeys = []
    if not HAS_WINREG:
        return subkeys
    try:
        key = winreg.OpenKey(hive, subkey,
                              access=winreg.KEY_READ | winreg.KEY_ENUMERATE_SUB_KEYS)
        i = 0
        while True:
            try:
                name = winreg.EnumKey(key, i)
                subkeys.append(name)
                i += 1
            except OSError:
                break
        winreg.CloseKey(key)
    except Exception:
        pass
    return subkeys


def _diff_snapshots(before: dict, after: dict) -> list:
    """
    Compare two value snapshots.
    Returns list of (change_type, name, old_val, new_val)
    change_type: 'NEW' | 'CHANGED' | 'DELETED'
    """
    changes = []
    for name, data in after.items():
        if name not in before:
            changes.append(('NEW', name, None, data))
        elif before[name] != data:
            changes.append(('CHANGED', name, before[name], data))
    for name in before:
        if name not in after:
            changes.append(('DELETED', name, before[name], None))
    return changes


# ─────────────────────────────────────────────────────────────────────

class RegistryMonitor:
    """
    Starts one watcher thread per registry key.
    Each thread uses RegNotifyChangeKeyValue to sleep until a change occurs —
    zero CPU when the system is idle.
    """

    def __init__(self):
        self._running    = False
        self._threads:   list = []
        self._callback   = None   # fn(event_type, path, severity, details) → None
        self._log_fn     = None   # fn(message, event_type, severity) → None

    def start(self, log_fn=None, alert_callback=None):
        """
        Start monitoring all watched registry keys.

        log_fn:          integrity_core.append_log_line compatible signature
        alert_callback:  GUI callback fn(event_type, path, severity)
        """
        if not HAS_WINREG:
            print("[REGISTRY] pywin32 not installed — registry monitoring disabled.")
            print("[REGISTRY] Install with: pip install pywin32")
            return False

        self._running  = True
        self._log_fn   = log_fn
        self._callback = alert_callback

        for (hive, subkey, description, critical_values) in WATCHED_KEYS:
            if hive is None:
                continue
            t = threading.Thread(
                target=self._watch_key,
                args=(hive, subkey, description, critical_values),
                daemon=True,
                name=f"FMSecure-Reg-{subkey[:30]}"
            )
            t.start()
            self._threads.append(t)

        print(f"[REGISTRY] Monitoring {len(self._threads)} persistence keys.")
        return True

    def stop(self):
        self._running = False

    def _watch_key(self, hive, subkey: str, description: str,
                   critical_values: list):
        """
        One thread per registry key.
        Uses RegNotifyChangeKeyValue() — wakes only on actual changes.
        """
        hive_str = _hive_name(hive)
        full_path = f"{hive_str}\\{subkey}"

        # Take initial baseline
        baseline = self._snapshot_key(hive, subkey)

        while self._running:
            try:
                key_handle = win32api.RegOpenKeyEx(
                    hive,
                    subkey,
                    0,
                    win32con.KEY_NOTIFY | win32con.KEY_READ
                )
                # Create a manual-reset event
                event = win32event.CreateEvent(None, True, False, None)

                # REG_NOTIFY_CHANGE_LAST_SET  — value data/name changes
                # REG_NOTIFY_CHANGE_NAME      — subkey creation/deletion
                # REG_NOTIFY_CHANGE_ATTRIBUTES — security descriptor changes
                REG_NOTIFY_FLAGS = 0x00000004 | 0x00000001 | 0x00000002

                win32api.RegNotifyChangeKeyValue(
                    key_handle,
                    True,           # watch subtree
                    REG_NOTIFY_FLAGS,
                    event,
                    True            # asynchronous
                )

                # Wait for change (check every 5s so we can respect stop())
                result = win32event.WaitForSingleObject(event, 5000)

                win32api.RegCloseKey(key_handle)

                if not self._running:
                    break

                if result == win32event.WAIT_TIMEOUT:
                    continue  # nothing changed, keep watching

                # ── Change detected! ──────────────────────────────────
                new_snapshot = self._snapshot_key(hive, subkey)
                changes      = _diff_snapshots(baseline, new_snapshot)

                for change_type, name, old_val, new_val in changes:
                    self._handle_change(
                        change_type, full_path, name,
                        old_val, new_val,
                        description, critical_values
                    )

                baseline = new_snapshot

            except Exception as e:
                if self._running:
                    print(f"[REGISTRY] Watcher error for {full_path}: {e}")
                    time.sleep(5)  # back-off on error

    def _snapshot_key(self, hive, subkey: str) -> dict:
        """
        For most keys: read values.
        For IFEO/Services: read subkey names (those ARE the persistence entries).
        """
        high_cardinality = [
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            r"SYSTEM\CurrentControlSet\Services",
            r"Software\Classes\CLSID",
        ]
        for hc in high_cardinality:
            if subkey.lower() == hc.lower():
                # Return subkey names as the "values" dict
                return {k: '[subkey]' for k in _read_subkeys(hive, subkey)}

        return _read_all_values(hive, subkey)

    def _handle_change(self, change_type: str, full_path: str,
                       name: str, old_val, new_val,
                       description: str, critical_values: list):
        """Process one detected registry change."""
        # Determine severity
        if change_type == 'NEW':
            severity = _SEVERITY_NEW
        elif change_type in ('CHANGED', 'DELETED'):
            # Escalate to CRITICAL if it's a known-critical value name
            if critical_values and name in critical_values:
                severity = _SEVERITY_NEW
            else:
                severity = _SEVERITY_CHANGED
        else:
            severity = "MEDIUM"

        # Build the log message
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if change_type == 'NEW':
            msg = (f"REGISTRY PERSISTENCE DETECTED — {description}\n"
                   f"  Path:  {full_path}\n"
                   f"  Value: {name}\n"
                   f"  Data:  {new_val}")
        elif change_type == 'CHANGED':
            msg = (f"REGISTRY VALUE MODIFIED — {description}\n"
                   f"  Path:  {full_path}\n"
                   f"  Value: {name}\n"
                   f"  Was:   {old_val}\n"
                   f"  Now:   {new_val}")
        else:  # DELETED
            msg = (f"REGISTRY VALUE DELETED — {description}\n"
                   f"  Path:  {full_path}\n"
                   f"  Value: {name}\n"
                   f"  Was:   {old_val}")

        print(f"[REGISTRY] [{severity}] {msg}")

        # Write to integrity log
        event_type_map = {
            'NEW':     'REGISTRY_PERSISTENCE_NEW',
            'CHANGED': 'REGISTRY_VALUE_CHANGED',
            'DELETED': 'REGISTRY_VALUE_DELETED',
        }
        event_type = event_type_map.get(change_type, 'REGISTRY_CHANGE')

        if self._log_fn:
            try:
                self._log_fn(msg, event_type=event_type, severity=severity)
            except Exception as e:
                print(f"[REGISTRY] log_fn error: {e}")

        # Notify GUI
        if self._callback:
            try:
                display_path = f"{full_path}\\{name}"
                self._callback(event_type, display_path, severity)
            except Exception as e:
                print(f"[REGISTRY] callback error: {e}")

        # Generate forensic snapshot + send dual-channel alert for CRITICAL/HIGH
        if severity in ('CRITICAL', 'HIGH'):
            try:
                from core.incident_snapshot import generate_incident_snapshot
                generate_incident_snapshot(
                    event_type=event_type,
                    severity=severity,
                    message=msg,
                    affected_files=[f"{full_path}\\{name}"],
                    additional_data={
                        'registry_path':   full_path,
                        'value_name':      name,
                        'old_data':        str(old_val),
                        'new_data':        str(new_val),
                        'change_type':     change_type,
                        'description':     description,
                    }
                )
            except Exception as e:
                print(f"[REGISTRY] Snapshot error: {e}")
 
            # Email + webhook alert (same dual-channel pipeline as file events)
            try:
                from core.integrity_core import send_webhook_safe
                alert_msg = (
                    f"{msg}\n\n"
                    f"Registry Key: {full_path}\n"
                    f"Value Name:   {name}\n"
                    f"Change Type:  {change_type}\n"
                    f"New Data:     {str(new_val)[:200]}"
                )
                send_webhook_safe(
                    event_type,
                    alert_msg,
                    filepath=f"{full_path}\\{name}",
                    severity=severity
                )
            except Exception as e:
                print(f"[REGISTRY] Alert dispatch error: {e}")


# ── Module-level singleton ────────────────────────────────────────────
_registry_monitor: RegistryMonitor | None = None
_reg_lock = threading.Lock()


def get_registry_monitor() -> RegistryMonitor:
    global _registry_monitor
    with _reg_lock:
        if _registry_monitor is None:
            _registry_monitor = RegistryMonitor()
        return _registry_monitor


def start_registry_monitoring(log_fn=None, alert_callback=None) -> bool:
    """
    Start registry persistence monitoring.
    Call this from FileIntegrityMonitor.start_monitoring().
    Returns True if started, False if pywin32 not available.
    """
    return get_registry_monitor().start(
        log_fn=log_fn,
        alert_callback=alert_callback
    )


def stop_registry_monitoring():
    """Call from FileIntegrityMonitor.stop_monitoring()."""
    get_registry_monitor().stop()