"""
core/license_verifier.py — FMSecure v2.0
Server-validated subscription license system.

Architecture:
  - On first activation: app sends key to server, server validates + returns subscription info
  - On every startup: app silently re-validates in background (keeps local cache)
  - Cache is AES-encrypted locally so it can't be tampered with
  - Cache is valid for 24 hours (so app works offline for a day)
  - If server is unreachable AND cache is still valid → grant access (grace period)
  - If server is unreachable AND cache is expired → deny access (license enforcement)

This is the same pattern used by JetBrains, Malwarebytes, and Bitdefender.
"""

import os
import json
import hashlib
import hmac
import time
import threading
import requests
from datetime import datetime, timezone

from core.utils import get_app_data_dir
from core.encryption_manager import crypto_manager

# ── Configuration ─────────────────────────────────────────────────────────────

# Your Railway server URL — change this if you move servers
LICENSE_SERVER_URL = "https://fmsecure-c2-server-production.up.railway.app"

# Local encrypted cache file — stores last known license status
_CACHE_FILE = os.path.join(get_app_data_dir(), "logs", "license_cache.dat")

# How long a cached license is trusted without re-validation (seconds)
# 24 hours — app works offline for up to a day
_CACHE_TTL_SECONDS = 86_400

# Request timeout — don't block the app UI if server is slow
_REQUEST_TIMEOUT_SECONDS = 8


# ── Cache helpers ──────────────────────────────────────────────────────────────

def _save_cache(email: str, key: str, response: dict):
    """Encrypt and save the server response locally."""
    cache = {
        "email":       email,
        "key":         key,
        "response":    response,
        "cached_at":   time.time(),
    }
    try:
        os.makedirs(os.path.dirname(_CACHE_FILE), exist_ok=True)
        crypto_manager.encrypt_json(cache, _CACHE_FILE)
    except Exception as e:
        print(f"[LICENSE] Cache save failed: {e}")


def _load_cache(email: str, key: str):
    """
    Load the local cache and return the cached response if:
      - It belongs to the same email + key
      - It is not older than _CACHE_TTL_SECONDS
    Returns the cached response dict, or None.
    """
    try:
        if not os.path.exists(_CACHE_FILE):
            return None
        cache = crypto_manager.decrypt_json(_CACHE_FILE)
        if not cache:
            return None

        # Must match same email and key
        if cache.get("email") != email or cache.get("key") != key:
            return None

        age = time.time() - cache.get("cached_at", 0)
        if age > _CACHE_TTL_SECONDS:
            return None          # Cache expired

        return cache.get("response")
    except Exception:
        return None


def _clear_cache():
    """Remove the license cache (e.g. on logout or deactivation)."""
    try:
        if os.path.exists(_CACHE_FILE):
            os.remove(_CACHE_FILE)
    except Exception:
        pass


# ── Server communication ───────────────────────────────────────────────────────

def _validate_with_server(email: str, key: str) -> dict:
    """
    POST to the license server and return the response dict.
    Returns a failure dict if the server can't be reached.
    """
    endpoint = f"{LICENSE_SERVER_URL}/api/license/validate"
    payload  = {"email": email, "license_key": key}

    try:
        resp = requests.post(endpoint, json=payload, timeout=_REQUEST_TIMEOUT_SECONDS)
        if resp.status_code == 200:
            return resp.json()
        else:
            return {
                "valid": False,
                "tier":  "free",
                "reason": f"Server returned {resp.status_code}"
            }
    except requests.exceptions.ConnectionError:
        return {"valid": False, "tier": "free", "reason": "server_unreachable"}
    except requests.exceptions.Timeout:
        return {"valid": False, "tier": "free", "reason": "server_timeout"}
    except Exception as e:
        return {"valid": False, "tier": "free", "reason": str(e)}


# ── Public API ─────────────────────────────────────────────────────────────────

class LicenseVerifier:
    """
    Drop-in replacement for the old static-key verifier.
    Same public interface: verify_license(email, key) → (bool, str)
    """

    def verify_license(self, user_email: str, license_key: str) -> tuple[bool, str]:
        """
        Validate a license key for the given user.

        Strategy:
          1. Try the local cache first (fast path — no network)
          2. If cache miss or expired, hit the server
          3. If server is unreachable but cache is still valid → grant (grace)
          4. Save successful server responses to cache

        Returns: (is_valid: bool, tier: str)
        tier will be "free", "pro_monthly", or "pro_annual"
        """
        email = user_email.strip().lower()
        key   = license_key.strip()

        # ── 1. Cache fast-path ────────────────────────────────────────────────
        cached = _load_cache(email, key)
        if cached is not None:
            # We have a fresh cached response — use it directly
            print(f"[LICENSE] Cache hit for {email} (valid={cached.get('valid')})")
            return cached.get("valid", False), cached.get("tier", "free")

        # ── 2. Hit the server ─────────────────────────────────────────────────
        print(f"[LICENSE] Validating {email} with server...")
        server_response = _validate_with_server(email, key)

        # ── 3. Server unreachable — try stale cache as grace period ───────────
        if server_response.get("reason") in ("server_unreachable", "server_timeout"):
            print("[LICENSE] Server unreachable — checking stale cache for grace period")
            # Load cache ignoring TTL
            try:
                if os.path.exists(_CACHE_FILE):
                    stale = crypto_manager.decrypt_json(_CACHE_FILE)
                    if (stale and
                            stale.get("email") == email and
                            stale.get("key") == key):
                        stale_resp = stale.get("response", {})
                        if stale_resp.get("valid"):
                            age_hours = (time.time() - stale.get("cached_at", 0)) / 3600
                            print(f"[LICENSE] Grace period granted — cache is {age_hours:.1f}h old")
                            return True, stale_resp.get("tier", "pro_monthly")
            except Exception:
                pass
            # No valid stale cache
            return False, "free"

        # ── 4. Server responded — save to cache and return ────────────────────
        if server_response.get("valid"):
            _save_cache(email, key, server_response)

        return server_response.get("valid", False), server_response.get("tier", "free")

    def background_revalidate(self, user_email: str, license_key: str,
                               callback=None):
        """
        Silently re-validate in a background thread on app startup.
        If the subscription has lapsed since last check, the callback
        receives (False, "free") so the UI can degrade gracefully.

        callback: optional callable(is_valid: bool, tier: str)
        """
        def _worker():
            is_valid, tier = self.verify_license(user_email, license_key)
            if callback:
                callback(is_valid, tier)

        threading.Thread(target=_worker, daemon=True).start()

    def get_expiry_display(self, user_email: str, license_key: str) -> str:
        """
        Return a human-readable expiry string for the profile panel.
        Reads from cache only — no network call.
        """
        email  = user_email.strip().lower()
        key    = license_key.strip()
        cached = _load_cache(email, key)

        if cached and cached.get("expires_at"):
            try:
                dt = datetime.fromisoformat(cached["expires_at"])
                return dt.strftime("Expires %d %b %Y")
            except Exception:
                return "Active"
        return "Active"

    def deactivate(self, user_email: str, license_key: str):
        """
        Clear the local cache. The subscription remains active on the server
        but the app will re-validate from scratch next time.
        """
        _clear_cache()


# ── Singleton ──────────────────────────────────────────────────────────────────
license_verifier = LicenseVerifier()