"""
system_paths.py — FMSecure v2.6
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SYSTEM PATH PROTECTION  —  Gap 2 Fix

Expands monitoring beyond user-chosen folders to include Windows
critical paths that attackers abuse.

Industry reference:
  CrowdStrike / SentinelOne monitor the ENTIRE filesystem by default.
  This module gives FMSecure a curated subset of the highest-risk paths,
  keeping resource usage reasonable while catching the most common attacks.

Monitored path categories:
  1. Autostart locations   — Run, RunOnce, Startup folders
  2. System32/SysWOW64     — Core OS binaries (DLL hijack target)
  3. Program Files         — Installed software (supply chain attack)
  4. Temp directories      — Dropper staging ground (malware stage 1)
  5. Browser data dirs     — Credential theft target
  6. Script/task dirs      — Persistence via scheduled tasks/scripts
  7. User Profile roots    — Documents, Desktop, AppData

Usage:
    from core.system_paths import get_system_paths, is_system_critical

    # Get all paths to add to watchdog observer
    paths = get_system_paths(level='balanced')  # 'minimal' | 'balanced' | 'aggressive'

    # Check if a modified file is in a critical system location
    severity = is_system_critical(filepath)  # returns 'CRITICAL' | 'HIGH' | None
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import os
import sys
import platform


def _expand(*parts) -> str:
    """Build and normalise a path, expanding env vars."""
    p = os.path.join(*parts)
    return os.path.normcase(os.path.expandvars(os.path.expanduser(p)))


# ── Path Definitions ──────────────────────────────────────────────────

def _user_home() -> str:
    return os.path.expanduser("~")


def _appdata() -> str:
    return os.environ.get("APPDATA", os.path.join(_user_home(), "AppData", "Roaming"))


def _localappdata() -> str:
    return os.environ.get("LOCALAPPDATA",
                           os.path.join(_user_home(), "AppData", "Local"))


def _programdata() -> str:
    return os.environ.get("PROGRAMDATA", r"C:\ProgramData")


def _windir() -> str:
    return os.environ.get("WINDIR", r"C:\Windows")


# ─────────────────────────────────────────────────────────────────────
# CRITICAL — any modification here is almost certainly malicious
# ─────────────────────────────────────────────────────────────────────
CRITICAL_PATHS = {
    # Windows startup folders (persistence classic)
    "startup_current_user": os.path.join(
        _appdata(),
        r"Microsoft\Windows\Start Menu\Programs\Startup"
    ),
    "startup_all_users": os.path.join(
        _programdata(),
        r"Microsoft\Windows\Start Menu\Programs\Startup"
    ),

    # Core system binary directories (DLL hijack, binary replacement)
    "system32": os.path.join(_windir(), "System32"),
    "syswow64": os.path.join(_windir(), "SysWOW64"),

    # Scheduled tasks (persistence via XML task files)
    "scheduled_tasks": os.path.join(
        _windir(), r"System32\Tasks"
    ),

    # Windows scripting host objects
    "wsh_scripts": os.path.join(_windir(), r"System32\wbem"),

    # Driver store (kernel driver persistence)
    "drivers": os.path.join(_windir(), r"System32\drivers"),
}

# ─────────────────────────────────────────────────────────────────────
# HIGH — suspicious but may have legitimate changes
# ─────────────────────────────────────────────────────────────────────
HIGH_PATHS = {
    # Program Files (supply chain tampering, DLL planting)
    "program_files":     r"C:\Program Files",
    "program_files_x86": r"C:\Program Files (x86)",

    # ProgramData (shared application data, malware staging)
    "programdata": _programdata(),

    # Common temp staging areas (malware dropper stage 1)
    "user_temp":   os.environ.get("TEMP", os.path.join(
                       _localappdata(), "Temp")),
    "windows_temp": os.path.join(_windir(), "Temp"),

    # PowerShell module paths (script-based persistence)
    "ps_modules_system": os.path.join(
        _windir(), r"System32\WindowsPowerShell\v1.0\Modules"
    ),
    "ps_modules_user": os.path.join(
        _user_home(), r"Documents\WindowsPowerShell\Modules"
    ),

    # Hosts file (DNS hijacking)
    "hosts_dir": os.path.join(_windir(), r"System32\drivers\etc"),
}

# ─────────────────────────────────────────────────────────────────────
# MEDIUM — standard monitoring (user-facing attack surface)
# ─────────────────────────────────────────────────────────────────────
MEDIUM_PATHS = {
    # User documents/desktop (ransomware primary target)
    "desktop":   os.path.join(_user_home(), "Desktop"),
    "documents": os.path.join(_user_home(), "Documents"),
    "downloads": os.path.join(_user_home(), "Downloads"),

    # AppData (credential stores, config hijack)
    "appdata_roaming": _appdata(),
    "appdata_local":   _localappdata(),

    # Browser credential stores
    "chrome_creds": os.path.join(
        _localappdata(), r"Google\Chrome\User Data\Default"
    ),
    "edge_creds": os.path.join(
        _localappdata(), r"Microsoft\Edge\User Data\Default"
    ),
    "firefox_creds": os.path.join(
        _appdata(), r"Mozilla\Firefox\Profiles"
    ),
}

# ─────────────────────────────────────────────────────────────────────
# Profile sets: what gets added depending on monitoring level
# ─────────────────────────────────────────────────────────────────────
LEVEL_PROFILES = {
    "minimal": {
        # Just the absolute highest risk — startup + system32
        "startup_current_user", "startup_all_users",
        "scheduled_tasks",
        "hosts_dir",
    },
    "balanced": {
        # Startup folders — highest signal, very low noise
        "startup_current_user",
        "startup_all_users",
        # Scheduled tasks — persistence via XML task files
        "scheduled_tasks",
        # Hosts file — DNS hijacking (single file dir, near-zero noise)
        "hosts_dir",
        # Drivers directory — kernel persistence (low write frequency)
        # "drivers",   # OPTIONAL: comment this out if still laggy
    },
    "aggressive": {
        # Everything — full coverage, higher CPU/IO
        *CRITICAL_PATHS.keys(),
        *HIGH_PATHS.keys(),
        *MEDIUM_PATHS.keys(),
    },
}

# ── Reverse lookup: path → severity ──────────────────────────────────
# Built at module load time for O(1) per-event lookups.

_path_severity_map: dict = {}  # normalised_path → 'CRITICAL' | 'HIGH' | 'MEDIUM'


def _build_severity_map():
    global _path_severity_map
    m = {}
    for path in CRITICAL_PATHS.values():
        m[os.path.normcase(path)] = 'CRITICAL'
    for path in HIGH_PATHS.values():
        m[os.path.normcase(path)] = 'HIGH'
    for path in MEDIUM_PATHS.values():
        if os.path.normcase(path) not in m:
            m[os.path.normcase(path)] = 'MEDIUM'
    _path_severity_map = m


_build_severity_map()


# ── Public API ────────────────────────────────────────────────────────

def get_system_paths(level: str = 'balanced') -> list:
    """
    Returns a list of (path, severity) tuples for the given monitoring level.
    Only includes paths that actually exist on the current machine.

    level: 'minimal' | 'balanced' | 'aggressive'
    """
    all_paths = {**CRITICAL_PATHS, **HIGH_PATHS, **MEDIUM_PATHS}
    key_set   = LEVEL_PROFILES.get(level, LEVEL_PROFILES['balanced'])

    result = []
    for key in key_set:
        path = all_paths.get(key, '')
        if not path:
            continue
        if not os.path.exists(path):
            continue
        # Determine severity
        norm = os.path.normcase(path)
        if key in CRITICAL_PATHS:
            sev = 'CRITICAL'
        elif key in HIGH_PATHS:
            sev = 'HIGH'
        else:
            sev = 'MEDIUM'
        result.append((path, sev))

    return result


def get_paths_only(level: str = 'balanced') -> list:
    """Returns just the path strings (for watchdog observer scheduling)."""
    return [p for p, _ in get_system_paths(level)]


def is_system_critical(filepath: str) -> str | None:
    """
    Check if a file path falls under a system-critical monitored directory.
    Returns severity string ('CRITICAL', 'HIGH', 'MEDIUM') or None.

    Usage in integrity_core.py:
        sys_sev = is_system_critical(path)
        if sys_sev:
            # Escalate severity, add badge to log message
            severity = max(severity, sys_sev)
    """
    norm = os.path.normcase(os.path.abspath(filepath))
    # Check each known critical prefix
    for base_path, sev in _path_severity_map.items():
        try:
            if norm.startswith(base_path):
                return sev
        except Exception:
            continue
    return None


def is_in_temp(filepath: str) -> bool:
    """True if the file is in a temp directory — common dropper staging."""
    norm = os.path.normcase(os.path.abspath(filepath))
    temp_paths = [
        os.path.normcase(os.environ.get("TEMP", "")),
        os.path.normcase(os.path.join(_windir(), "Temp")),
    ]
    return any(norm.startswith(t) for t in temp_paths if t)


def is_executable(filepath: str) -> bool:
    """True if the file is a binary that could be executed."""
    ext = os.path.splitext(filepath)[1].lower()
    return ext in {
        '.exe', '.dll', '.sys', '.drv', '.ocx',
        '.bat', '.cmd', '.ps1', '.vbs', '.js',
        '.hta', '.scr', '.pif', '.com', '.jar',
        '.msi', '.msp', '.reg',
    }


def classify_file_risk(filepath: str) -> dict:
    """
    Full risk classification for a file path.
    Returns:
    {
        'system_severity': 'CRITICAL'|'HIGH'|'MEDIUM'|None,
        'in_temp':         bool,
        'is_executable':   bool,
        'risk_score':      int  (0-10)
    }
    """
    sys_sev = is_system_critical(filepath)
    in_temp = is_in_temp(filepath)
    is_exec = is_executable(filepath)

    score = 0
    if sys_sev == 'CRITICAL':  score += 5
    elif sys_sev == 'HIGH':    score += 3
    elif sys_sev == 'MEDIUM':  score += 1
    if in_temp:                score += 3
    if is_exec:                score += 2

    return {
        'system_severity': sys_sev,
        'in_temp':         in_temp,
        'is_executable':   is_exec,
        'risk_score':      min(score, 10),
    }


def get_system_paths_summary() -> str:
    """Human-readable summary for GUI display."""
    lines = ["System-Critical Paths (FMSecure Protection):"]
    lines.append("\n  [CRITICAL — Autostart & System Binaries]")
    for k, v in CRITICAL_PATHS.items():
        exists = "✓" if os.path.exists(v) else "✗"
        lines.append(f"    {exists} {v}")
    lines.append("\n  [HIGH — Temp, Scripts, ProgramData]")
    for k, v in HIGH_PATHS.items():
        exists = "✓" if os.path.exists(v) else "✗"
        lines.append(f"    {exists} {v}")
    return "\n".join(lines)