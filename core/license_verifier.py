"""
core/license_verifier.py — FMSecure v2.0 — Device-based licensing
Email is NOT sent to server. Machine ID is used instead.
"""
import os, time, hashlib, threading, requests, platform, uuid
from datetime import datetime
from core.utils import get_app_data_dir
from core.encryption_manager import crypto_manager

LICENSE_SERVER_URL = "https://fmsecure-c2-server-production.up.railway.app"
_CACHE_FILE      = os.path.join(get_app_data_dir(), "logs", "license_cache.dat")
_MACHINE_ID_FILE = os.path.join(get_app_data_dir(), "logs", "machine_id.dat")
_CACHE_TTL       = 86_400
_TIMEOUT         = 8

def _get_machine_id() -> str:
    try:
        if os.path.exists(_MACHINE_ID_FILE):
            d = crypto_manager.decrypt_json(_MACHINE_ID_FILE)
            if d and d.get("machine_id"):
                return d["machine_id"]
    except Exception:
        pass
    try:
        hw  = f"{platform.node()}-{platform.machine()}-{platform.processor()}"
        mid = f"FM-{hashlib.sha256(hw.encode()).hexdigest()[:16].upper()}-{uuid.uuid4().hex[:8].upper()}"
    except Exception:
        mid = f"FM-{uuid.uuid4().hex[:24].upper()}"
    try:
        os.makedirs(os.path.dirname(_MACHINE_ID_FILE), exist_ok=True)
        crypto_manager.encrypt_json({"machine_id": mid}, _MACHINE_ID_FILE)
    except Exception:
        pass
    return mid

def _ck(k, m): return hashlib.sha256(f"{k}:{m}".encode()).hexdigest()[:16]

def _save_cache(k, m, r):
    try:
        os.makedirs(os.path.dirname(_CACHE_FILE), exist_ok=True)
        crypto_manager.encrypt_json({"ck": _ck(k,m), "response": r, "cached_at": time.time()}, _CACHE_FILE)
    except Exception: pass

def _load_cache(k, m, allow_stale=False):
    try:
        if not os.path.exists(_CACHE_FILE): return None
        c = crypto_manager.decrypt_json(_CACHE_FILE)
        if not c or c.get("ck") != _ck(k, m): return None
        if not allow_stale and time.time() - c.get("cached_at", 0) > _CACHE_TTL: return None
        return c.get("response")
    except Exception: return None

def _clear_cache():
    try:
        if os.path.exists(_CACHE_FILE): os.remove(_CACHE_FILE)
    except Exception: pass

def _call_server(key, mid):
    try:
        r = requests.post(f"{LICENSE_SERVER_URL}/api/license/validate",
                          json={"license_key": key, "machine_id": mid}, timeout=_TIMEOUT)
        return r.json() if r.status_code == 200 else {"valid": False, "tier": "free", "reason": f"http_{r.status_code}"}
    except requests.exceptions.ConnectionError:
        return {"valid": False, "tier": "free", "reason": "server_unreachable"}
    except requests.exceptions.Timeout:
        return {"valid": False, "tier": "free", "reason": "server_timeout"}
    except Exception as e:
        return {"valid": False, "tier": "free", "reason": str(e)}

REASON_MESSAGES = {
    "key_not_found":       "Invalid license key. Please check and try again.",
    "subscription_expired":"Your PRO subscription has expired. Please renew.",
    "device_mismatch":     "This key is already activated on a different device.\nContact support to transfer it.",
    "db_error":            "License server error. Please try again later.",
    "server_unreachable":  "Cannot reach license server. Using offline cached status.",
    "server_timeout":      "License server timed out. Using offline cached status.",
}

class LicenseVerifier:
    def verify_license(self, license_key: str, user_email: str = "") -> tuple:
        key = license_key.strip()
        mid = _get_machine_id()
        if not key: return False, "free"
        cached = _load_cache(key, mid)
        if cached is not None:
            return cached.get("valid", False), cached.get("tier", "free")
        resp = _call_server(key, mid)
        if resp.get("reason") in ("server_unreachable", "server_timeout"):
            stale = _load_cache(key, mid, allow_stale=True)
            if stale and stale.get("valid"):
                return True, stale.get("tier", "pro_monthly")
            return False, "free"
        if resp.get("valid"):
            _save_cache(key, mid, resp)
        return resp.get("valid", False), resp.get("tier", "free")

    def get_activation_error(self, license_key: str) -> str:
        resp = _call_server(license_key.strip(), _get_machine_id())
        return REASON_MESSAGES.get(resp.get("reason", ""), f"Activation failed ({resp.get('reason', 'unknown')})")

    def background_revalidate(self, license_key: str, callback=None):
        def _w():
            ok, t = self.verify_license(license_key)
            if callback: callback(ok, t)
        threading.Thread(target=_w, daemon=True).start()

    def get_expiry_display(self, license_key: str, user_email: str = "") -> str:
        k = license_key.strip(); m = _get_machine_id()
        c = _load_cache(k, m) or _load_cache(k, m, allow_stale=True)
        if c and c.get("expires_at"):
            try: return datetime.fromisoformat(c["expires_at"]).strftime("Expires %d %b %Y")
            except Exception: pass
        return "Active"

    def get_machine_id(self) -> str:
        return _get_machine_id()

    def deactivate(self, license_key: str = "", user_email: str = ""):
        _clear_cache()

license_verifier = LicenseVerifier()