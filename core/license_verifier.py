"""
core/license_verifier.py — FMSecure v2.0 — Device-based licensing

ROOT CAUSE FIX (reinstall "already used" bug):
  The old _get_machine_id() appended uuid.uuid4().hex[:8] to the hardware hash.
  After reinstall, that random suffix changed, making the server see a different
  device → "device_mismatch" for a key the user legitimately owns.

  Fix: Pure hardware derivation, identical to encryption_manager.get_machine_id().
  No random component. Deterministic across reinstalls forever.

LICENSE TRANSFER FLOW:
  When a user reinstalls on the SAME hardware but using an OLD license key that
  was activated before this fix (i.e. stored with the old random machine_id):
    1. activate_license() receives "device_mismatch" from the server
    2. auth_manager surfaces a "Transfer License" option
    3. User enters the purchase email → OTP sent
    4. OTP verified → server updates stored machine_id to the new hardware ID
    5. Re-validation succeeds

  Server endpoints required (add to your Railway FastAPI server):
    POST /api/license/request_transfer
      body: {license_key, email}
      → validates key exists, sends 6-digit OTP to email, returns {ok: true}

    POST /api/license/confirm_transfer
      body: {license_key, otp, new_machine_id}
      → verifies OTP, updates machine_id in DB, returns {ok: true, tier}
"""
import os
import time
import hashlib
import platform
import threading
import requests
from datetime import datetime
from core.utils import get_app_data_dir
from core.encryption_manager import crypto_manager

LICENSE_SERVER_URL = "https://fmsecure-c2-server-production.up.railway.app"
_CACHE_FILE      = os.path.join(get_app_data_dir(), "logs", "license_cache.dat")
_CACHE_TTL       = 86_400   # 24 hours
_TIMEOUT         = 8


# ── MACHINE IDENTITY ─────────────────────────────────────────────────────────

def _get_machine_id() -> str:
    """
    Pure hardware derivation — NO random UUID suffix.

    Must stay identical to encryption_manager.get_machine_id() so both
    subsystems use the same device fingerprint. Any divergence causes
    "device_mismatch" errors for users who legitimately own a license.

    Deterministic: same hardware → same ID → survives reinstall forever.
    """
    hw = f"{platform.node()}-{platform.machine()}-{platform.processor()}"
    return "FM-" + hashlib.sha256(hw.encode()).hexdigest()[:24].upper()


# ── CACHE ─────────────────────────────────────────────────────────────────────

def _ck(k, m):
    return hashlib.sha256(f"{k}:{m}".encode()).hexdigest()[:16]


def _save_cache(k, m, r):
    try:
        os.makedirs(os.path.dirname(_CACHE_FILE), exist_ok=True)
        crypto_manager.encrypt_json(
            {"ck": _ck(k, m), "response": r, "cached_at": time.time()},
            _CACHE_FILE
        )
    except Exception:
        pass


def _load_cache(k, m, allow_stale=False):
    try:
        if not os.path.exists(_CACHE_FILE):
            return None
        c = crypto_manager.decrypt_json(_CACHE_FILE)
        if not c or c.get("ck") != _ck(k, m):
            return None
        if not allow_stale and time.time() - c.get("cached_at", 0) > _CACHE_TTL:
            return None
        return c.get("response")
    except Exception:
        return None


def _clear_cache():
    try:
        if os.path.exists(_CACHE_FILE):
            os.remove(_CACHE_FILE)
    except Exception:
        pass


# ── SERVER CALLS ──────────────────────────────────────────────────────────────

def _call_server(key, mid):
    try:
        r = requests.post(
            f"{LICENSE_SERVER_URL}/api/license/validate",
            json={"license_key": key, "machine_id": mid},
            timeout=_TIMEOUT
        )
        return (r.json() if r.status_code == 200
                else {"valid": False, "tier": "free", "reason": f"http_{r.status_code}"})
    except requests.exceptions.ConnectionError:
        return {"valid": False, "tier": "free", "reason": "server_unreachable"}
    except requests.exceptions.Timeout:
        return {"valid": False, "tier": "free", "reason": "server_timeout"}
    except Exception as e:
        return {"valid": False, "tier": "free", "reason": str(e)}


# ── ERROR MESSAGES ────────────────────────────────────────────────────────────

REASON_MESSAGES = {
    "key_not_found":        "Invalid license key. Please check and try again.",
    "subscription_expired": "Your PRO subscription has expired. Please renew.",
    "device_mismatch":      (
        "This key was activated on a different device.\n\n"
        "If you reinstalled FMSecure on the same computer,\n"
        "use 'Transfer License' to reassign it to this device."
    ),
    "db_error":             "License server error. Please try again later.",
    "server_unreachable":   "Cannot reach license server. Using offline cached status.",
    "server_timeout":       "License server timed out. Using offline cached status.",
}


# ── VERIFIER CLASS ────────────────────────────────────────────────────────────

class LicenseVerifier:

    def verify_license(self, license_key: str, user_email: str = "") -> tuple:
        key = license_key.strip()
        mid = _get_machine_id()
        if not key:
            return False, "free"
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
        reason = resp.get("reason", "")
        return REASON_MESSAGES.get(reason, f"Activation failed ({reason})")

    def is_device_mismatch(self, license_key: str) -> bool:
        """True if the key exists but is registered to a different device."""
        resp = _call_server(license_key.strip(), _get_machine_id())
        return resp.get("reason") == "device_mismatch"

    def request_license_transfer(self, license_key: str, email: str) -> tuple[bool, str]:
        """
        Step 1 of the transfer flow.
        Asks the server to send a 6-digit OTP to the purchase email.
        Returns (True, "OTP sent") or (False, error_message).

        Requires server endpoint:
          POST /api/license/request_transfer
          body: {license_key, email}
          → {ok: true} or {ok: false, reason: "..."}
        """
        try:
            r = requests.post(
                f"{LICENSE_SERVER_URL}/api/license/request_transfer",
                json={"license_key": license_key.strip(), "email": email.strip().lower()},
                timeout=_TIMEOUT
            )
            data = r.json() if r.status_code in (200, 400) else {}
            if r.status_code == 200 and data.get("ok"):
                return True, "OTP sent to your purchase email."
            return False, data.get("reason", "Transfer request failed. Check your email address.")
        except requests.exceptions.ConnectionError:
            return False, "Cannot reach license server. Check your internet connection."
        except Exception as e:
            return False, str(e)

    def confirm_license_transfer(self, license_key: str, otp: str) -> tuple[bool, str, str]:
        """
        Step 2 of the transfer flow.
        Submits the OTP + current machine_id to the server.
        On success, the server updates the stored machine_id.
        Returns (True, "Success message", tier) or (False, error_message, "free").

        Requires server endpoint:
          POST /api/license/confirm_transfer
          body: {license_key, otp, new_machine_id}
          → {ok: true, tier: "pro_monthly"} or {ok: false, reason: "..."}
        """
        mid = _get_machine_id()
        try:
            r = requests.post(
                f"{LICENSE_SERVER_URL}/api/license/confirm_transfer",
                json={
                    "license_key":    license_key.strip(),
                    "otp":            otp.strip(),
                    "new_machine_id": mid,
                },
                timeout=_TIMEOUT
            )
            data = r.json() if r.status_code in (200, 400) else {}
            if r.status_code == 200 and data.get("ok"):
                tier = data.get("tier", "pro_monthly")
                # Cache the successful response so the app goes PRO immediately
                _save_cache(license_key.strip(), mid, {
                    "valid": True,
                    "tier":  tier,
                })
                return True, f"License transferred successfully.", tier
            return False, data.get("reason", "OTP incorrect or expired."), "free"
        except requests.exceptions.ConnectionError:
            return False, "Cannot reach license server.", "free"
        except Exception as e:
            return False, str(e), "free"

    def background_revalidate(self, license_key: str, callback=None):
        def _w():
            ok, t = self.verify_license(license_key)
            if callback:
                callback(ok, t)
        threading.Thread(target=_w, daemon=True).start()

    def get_expiry_display(self, license_key: str, user_email: str = "") -> str:
        k = license_key.strip()
        m = _get_machine_id()
        c = _load_cache(k, m) or _load_cache(k, m, allow_stale=True)
        if c and c.get("expires_at"):
            try:
                return datetime.fromisoformat(c["expires_at"]).strftime("Expires %d %b %Y")
            except Exception:
                pass
        return "Active"

    def get_machine_id(self) -> str:
        return _get_machine_id()

    def deactivate(self, license_key: str = "", user_email: str = ""):
        _clear_cache()


license_verifier = LicenseVerifier()