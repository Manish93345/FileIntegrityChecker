"""
core/tenant_manager.py — FMSecure v2.5.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MULTI-TENANCY — Desktop Agent Layer

Single source of truth for tenant identity on this machine.
Reads/writes AppData/FMSecure/tenant.json.

Design rules:
  • If tenant.json does not exist → single-user mode (all existing
    features work exactly as before, no behaviour change).
  • If tenant.json exists → tenant mode:
      - Heartbeat adds x-tenant-key header
      - Alerts push to /api/agent/alert in addition to email/webhook
      - Policy config can be pulled from server
  • This module never raises — all methods return safe defaults on error.
  • Import cost is zero — no network calls at import time.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import os
import json
import time
import socket
import threading
from datetime import datetime, timezone
from core.utils import get_app_data_dir

# ── File path ─────────────────────────────────────────────────────────────────
_TENANT_FILE = os.path.join(get_app_data_dir(), "tenant.json")

# ── In-memory cache so we don't hit disk on every heartbeat ──────────────────
_cached: dict | None = None
_cache_lock = threading.Lock()


# ══════════════════════════════════════════════════════════════════════════════
#  READ / WRITE
# ══════════════════════════════════════════════════════════════════════════════

def load() -> dict | None:
    """
    Load tenant config from disk.
    Returns the config dict if enrolled, None if single-user mode.
    Result is cached in memory after first read.
    """
    global _cached
    with _cache_lock:
        if _cached is not None:
            return _cached   # already loaded this session

        if not os.path.exists(_TENANT_FILE):
            return None

        try:
            with open(_TENANT_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not data.get("tenant_key"):
                return None
            _cached = data
            return _cached
        except Exception as e:
            print(f"[TENANT] Could not read tenant.json: {e}")
            return None


def save(tenant_key: str, server: str, tenant_name: str = "") -> bool:
    """
    Persist tenant enrollment to disk.
    Called once during the enrollment wizard.
    Invalidates the in-memory cache so next load() reads fresh data.
    """
    global _cached
    try:
        os.makedirs(os.path.dirname(_TENANT_FILE), exist_ok=True)
        data = {
            "tenant_key":  tenant_key.strip(),
            "server":      server.rstrip("/"),
            "tenant_name": tenant_name.strip(),
            "enrolled_at": datetime.now(timezone.utc).isoformat(),
        }
        with open(_TENANT_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        with _cache_lock:
            _cached = data
        print(f"[TENANT] Enrolled: {tenant_name} ({tenant_key[:18]}…)")
        return True
    except Exception as e:
        print(f"[TENANT] Could not save tenant.json: {e}")
        return False


def clear() -> bool:
    """Remove tenant enrollment (leave single-user mode)."""
    global _cached
    try:
        if os.path.exists(_TENANT_FILE):
            os.remove(_TENANT_FILE)
        with _cache_lock:
            _cached = None
        print("[TENANT] Enrollment cleared — single-user mode restored.")
        return True
    except Exception as e:
        print(f"[TENANT] Could not clear tenant.json: {e}")
        return False


# ══════════════════════════════════════════════════════════════════════════════
#  CONVENIENCE ACCESSORS
# ══════════════════════════════════════════════════════════════════════════════

def is_enrolled() -> bool:
    """True if this machine has a valid tenant key configured."""
    cfg = load()
    return bool(cfg and cfg.get("tenant_key"))


def get_key() -> str:
    """Return the tenant API key, or empty string if not enrolled."""
    cfg = load()
    return (cfg or {}).get("tenant_key", "")


def get_server() -> str:
    """Return the C2 server URL from tenant config, or the default."""
    cfg = load()
    return (cfg or {}).get(
        "server",
        "https://fmsecure-c2-server-production.up.railway.app"
    )


def get_name() -> str:
    """Return the tenant/organisation name, or empty string."""
    cfg = load()
    return (cfg or {}).get("tenant_name", "")


# ══════════════════════════════════════════════════════════════════════════════
#  SERVER VALIDATION
# ══════════════════════════════════════════════════════════════════════════════

def validate_key(tenant_key: str, server: str = "") -> tuple[bool, str]:
    """
    Verify a tenant API key against the server before saving.
    Sends a minimal heartbeat and checks for a valid response.

    Returns (True, tenant_name) on success.
    Returns (False, error_message) on failure.

    Never raises — safe to call from GUI thread (runs sync, use in a Thread).
    """
    import requests as _req

    srv = (server or "https://fmsecure-c2-server-production.up.railway.app").rstrip("/")
    url = f"{srv}/api/heartbeat"

    try:
        payload = {
            "machine_id":    _get_machine_id(),
            "hostname":      socket.gethostname(),
            "username":      "enrollment-check",
            "tier":          "free",
            "is_armed":      False,
            "agent_version": "2.5.0",
        }
        headers = {"x-tenant-key": tenant_key.strip()}
        r = _req.post(url, json=payload, headers=headers, timeout=8)

        if r.status_code == 200:
            data = r.json()
            # Server returns {"status":"ok","tenant":"slug"} for valid keys
            tenant_slug = data.get("tenant", "")
            return True, tenant_slug
        elif r.status_code == 401:
            return False, "Invalid organisation key. Please check and try again."
        else:
            return False, f"Server returned HTTP {r.status_code}. Try again later."

    except _req.exceptions.ConnectionError:
        return False, "Cannot reach the FMSecure server. Check your internet connection."
    except _req.exceptions.Timeout:
        return False, "Server timed out. Please try again."
    except Exception as e:
        return False, f"Unexpected error: {e}"


def push_alert(
    machine_id: str,
    hostname:   str,
    severity:   str,
    event_type: str,
    message:    str,
    file_path:  str = "",
) -> bool:
    """
    Fire-and-forget alert push to the tenant server.
    Called from send_webhook_safe() for CRITICAL/HIGH events.
    Returns True if queued (always — the actual send is async).
    Does nothing and returns False if not enrolled.
    """
    if not is_enrolled():
        return False

    def _send():
        try:
            import requests as _req
            url = f"{get_server()}/api/agent/alert"
            payload = {
                "machine_id": machine_id,
                "hostname":   hostname,
                "severity":   severity.upper(),
                "event_type": event_type,
                "message":    message[:1000],
                "file_path":  file_path[:500],
            }
            headers = {"x-tenant-key": get_key()}
            r = _req.post(url, json=payload, headers=headers, timeout=6)
            if r.status_code == 200:
                print(f"[TENANT] Alert pushed: {severity} / {event_type}")
            else:
                print(f"[TENANT] Alert push returned HTTP {r.status_code}")
        except Exception as e:
            print(f"[TENANT] Alert push failed (non-critical): {e}")

    threading.Thread(target=_send, daemon=True).start()
    return True


# ══════════════════════════════════════════════════════════════════════════════
#  PRIVATE HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _get_machine_id() -> str:
    """Match the same hardware fingerprint used by encryption_manager."""
    try:
        from core.encryption_manager import crypto_manager
        return crypto_manager.get_machine_id()
    except Exception:
        import platform
        import hashlib
        hw = f"{platform.node()}-{platform.machine()}-{platform.processor()}"
        return "FM-" + hashlib.sha256(hw.encode()).hexdigest()[:24].upper()



def pull_config() -> dict:
    """
    Fetch tenant policy config from the server and return it as a dict.
 
    Called on app startup. The caller applies the returned values to
    CONFIG (integrity_core.CONFIG), overriding local config.json.
    This implements Option B — IT admin controls policy centrally.
 
    Returns an empty dict if:
      - Not enrolled (single-user mode — no change to behaviour)
      - Server offline (fail open — keep local config)
      - Tenant config not yet set on server
 
    Never raises — safe to call from any thread.
    """
    if not is_enrolled():
        return {}
 
    try:
        import requests as _req
        url     = f"{get_server()}/agent/config"
        headers = {"x-tenant-key": get_key()}
        r = _req.get(url, headers=headers, timeout=6)
 
        if r.status_code == 200:
            data = r.json()
            cfg  = data.get("config", {})
            name = data.get("tenant_name", "")
            if cfg:
                print(f"[TENANT] Policy pulled from server "
                      f"({name}): {list(cfg.keys())}")
            return cfg
 
        elif r.status_code == 402:
            # Seat limit exceeded — let the GUI know
            print("[TENANT] ⚠️  Seat limit reached. "
                  "This machine cannot enroll. Contact your administrator.")
            return {"_seat_limit_exceeded": True}
 
        else:
            print(f"[TENANT] Config pull returned HTTP {r.status_code}")
            return {}
 
    except Exception as e:
        print(f"[TENANT] Config pull failed (non-critical, using local): {e}")
        return {}