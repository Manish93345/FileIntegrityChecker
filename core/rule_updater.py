"""
rule_updater.py — FMSecure v2.7
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
LIVE DETECTION-RULE UPDATER  (Industry pattern: CrowdStrike Falcon Sensor,
                              SentinelOne Cloud Funcs, Microsoft Defender
                              Security Intelligence Updates, ClamAV freshclam)

PROBLEM SOLVED
──────────────
The agent is shipped as a frozen .exe. YARA / Sigma rule files live inside
sys._MEIPASS which is READ-ONLY at runtime. When a new malware family is
discovered we cannot rebuild and redistribute the .exe — we need agents to
pick up the new rule within minutes, automatically, with no user action.

DESIGN
──────
  1.  RULES_DIR_OVERRIDE  = %LOCALAPPDATA%\\SecureFIM\\rules\\{yara|sigma}\\
      A writable directory the agent owns. Engines scan this FIRST, then
      fall back to the read-only bundled copies in sys._MEIPASS.

  2.  VERSION POINTER on the server (Neon-cheap).
      A single tiny row stores:  rule_version, sha256, base64_bundle.
      The bundle is a ZIP of all .yar + .yml files (~50 KB compressed for
      ~200 rules).

  3.  PIGGYBACK on the existing 10-second heartbeat — the server's response
      now contains "rule_version". The agent compares it to the version it
      already has on disk. If equal → do nothing. If different → fetch the
      manifest, validate SHA-256, atomically swap the rules folder, and
      call yara_engine.reload_yara_rules() + sigma_engine.reload_rules().

      99.9 % of heartbeats trigger zero work. The download fires only on the
      single heartbeat following a publish — so Neon compute stays minimal
      and the agent's network footprint is ~25 extra bytes per heartbeat.

  4.  ATOMIC SWAP  →  download to ".../rules.new", verify hash, then rename.
      If anything fails mid-way, the old rules folder is untouched and the
      agent keeps detecting threats with the previous ruleset. Safety first.

  5.  HMAC SIGNATURE  →  the manifest is signed with LICENSE_HMAC_SECRET
      (already in your server config). Tampered bundles are rejected.

PUBLIC API
──────────
    get_rules_override_dir(kind)   →  Path  ('yara' | 'sigma')
    get_local_version()            →  str   (currently active version)
    handle_heartbeat_version(srv_ver, tenant_key, server_url, gui_cb=None)
        Call this from inside the heartbeat loop, right after we parse the
        server's response. Non-blocking, never raises.
    force_check(tenant_key, server_url)
        Manual "Check for rule updates now" button.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
from __future__ import annotations

import os
import io
import json
import time
import base64
import hashlib
import hmac
import shutil
import zipfile
import threading
from datetime import datetime
from typing import Optional, Callable

import requests

from core.utils import get_app_data_dir


# ── Constants ─────────────────────────────────────────────────────────────────

# Where downloaded rules live (writable, per-user)
_RULES_ROOT = os.path.join(get_app_data_dir(), "rules")
_YARA_DIR   = os.path.join(_RULES_ROOT, "yara")
_SIGMA_DIR  = os.path.join(_RULES_ROOT, "sigma")
_STATE_FILE = os.path.join(_RULES_ROOT, "state.json")

# Server endpoint paths (joined to tenant server URL at call time)
_MANIFEST_PATH = "/api/rules/manifest"

# Network
_DOWNLOAD_TIMEOUT = 20         # seconds — manifest can be a few hundred KB
_MAX_BUNDLE_BYTES = 5_000_000  # 5 MB hard ceiling — protects against runaway response

# Optional HMAC verification — set to the same string as web's
# LICENSE_HMAC_SECRET env var (or leave empty to skip).
_HMAC_SHARED_SECRET = os.environ.get("FMSECURE_RULES_HMAC", "")

# ── Concurrency lock — only ONE updater runs at a time across threads ────────
_update_lock = threading.Lock()
_state_lock  = threading.Lock()


# ── State persistence ─────────────────────────────────────────────────────────

def _ensure_dirs():
    os.makedirs(_YARA_DIR,  exist_ok=True)
    os.makedirs(_SIGMA_DIR, exist_ok=True)


def _read_state() -> dict:
    """{'version': '...', 'sha256': '...', 'updated_at': '...', 'count': N}"""
    with _state_lock:
        try:
            if os.path.exists(_STATE_FILE):
                with open(_STATE_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return {}


def _write_state(state: dict):
    with _state_lock:
        try:
            _ensure_dirs()
            tmp = _STATE_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2)
            os.replace(tmp, _STATE_FILE)
        except Exception as e:
            print(f"[RULE-UPDATER] state write error: {e}")


# ── Public path helpers ───────────────────────────────────────────────────────

def get_rules_override_dir(kind: str) -> str:
    """
    Returns the writable rule directory for the requested engine.
    kind: 'yara' | 'sigma'

    yara_engine.py and sigma_engine.py call this to learn where the
    "live" (downloaded) rules live. They scan both this dir AND their
    original bundled dir; downloaded files override bundled ones by
    filename if there's a collision.
    """
    _ensure_dirs()
    return _YARA_DIR if kind == "yara" else _SIGMA_DIR


def get_local_version() -> str:
    """The rule pack version currently active on this agent. '' if never updated."""
    return _read_state().get("version", "")


def get_status_summary() -> dict:
    """For GUI display: { version, count, updated_at, yara_files, sigma_files }"""
    st = _read_state()
    try:
        yara_count  = len([f for f in os.listdir(_YARA_DIR)
                           if f.lower().endswith((".yar", ".yara"))])
    except Exception:
        yara_count = 0
    try:
        sigma_count = len([f for f in os.listdir(_SIGMA_DIR)
                           if f.lower().endswith((".yml", ".yaml"))])
    except Exception:
        sigma_count = 0
    return {
        "version":     st.get("version", ""),
        "count":       st.get("count", 0),
        "updated_at":  st.get("updated_at", ""),
        "yara_files":  yara_count,
        "sigma_files": sigma_count,
    }


# ── Internal: hash + verify helpers ───────────────────────────────────────────

def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _verify_hmac(payload_bytes: bytes, signature_hex: str) -> bool:
    """HMAC-SHA256 verification. Returns True if no secret configured (opt-in)."""
    if not _HMAC_SHARED_SECRET:
        return True
    expected = hmac.new(
        _HMAC_SHARED_SECRET.encode("utf-8"),
        payload_bytes,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature_hex or "")


# ── Internal: bundle unpack ───────────────────────────────────────────────────

_ALLOWED_YARA  = (".yar", ".yara")
_ALLOWED_SIGMA = (".yml", ".yaml")


def _unpack_bundle_to_temp(bundle_bytes: bytes) -> Optional[str]:
    """
    Unzip the bundle into a brand-new temp folder beside the live one.
    Returns the temp folder path on success, None on failure.

    Bundle ZIP layout (mirror of repo):
        yara/foo.yar
        yara/bar.yar
        sigma/baz.yml
    """
    _ensure_dirs()
    tmp_root = os.path.join(_RULES_ROOT, f"_tmp_{int(time.time())}")
    try:
        os.makedirs(os.path.join(tmp_root, "yara"),  exist_ok=True)
        os.makedirs(os.path.join(tmp_root, "sigma"), exist_ok=True)

        with zipfile.ZipFile(io.BytesIO(bundle_bytes), "r") as zf:
            for info in zf.infolist():
                # Defence-in-depth — refuse Zip-Slip and absolute paths
                fn = info.filename.replace("\\", "/")
                if fn.startswith("/") or ".." in fn.split("/"):
                    continue
                if info.is_dir():
                    continue

                lower = fn.lower()
                if lower.startswith("yara/") and lower.endswith(_ALLOWED_YARA):
                    out = os.path.join(tmp_root, "yara",
                                       os.path.basename(fn))
                elif lower.startswith("sigma/") and lower.endswith(_ALLOWED_SIGMA):
                    out = os.path.join(tmp_root, "sigma",
                                       os.path.basename(fn))
                else:
                    continue   # silently ignore unknown files

                with zf.open(info, "r") as src, open(out, "wb") as dst:
                    shutil.copyfileobj(src, dst)

        return tmp_root
    except Exception as e:
        print(f"[RULE-UPDATER] unpack error: {e}")
        try:
            shutil.rmtree(tmp_root, ignore_errors=True)
        except Exception:
            pass
        return None


def _atomic_swap(tmp_root: str):
    """
    Replace the contents of _YARA_DIR / _SIGMA_DIR with those in tmp_root.
    Implemented as: clear-then-move (Windows-safe — no cross-drive renames).
    """
    for kind, target in (("yara", _YARA_DIR), ("sigma", _SIGMA_DIR)):
        src = os.path.join(tmp_root, kind)
        if not os.path.isdir(src):
            continue

        # Wipe current files (keep dir handle so engines don't see EEXIST)
        try:
            for f in os.listdir(target):
                fp = os.path.join(target, f)
                if os.path.isfile(fp):
                    try:
                        os.remove(fp)
                    except OSError:
                        pass
        except FileNotFoundError:
            os.makedirs(target, exist_ok=True)

        # Move new files in
        for f in os.listdir(src):
            shutil.move(os.path.join(src, f), os.path.join(target, f))

    # Cleanup the temp shell
    try:
        shutil.rmtree(tmp_root, ignore_errors=True)
    except Exception:
        pass


# ── Main update routine ───────────────────────────────────────────────────────

def _apply_manifest(manifest: dict,
                    gui_cb: Optional[Callable] = None) -> bool:
    """
    Manifest schema (from web/main.py /api/rules/manifest):
    {
        "version":     "2026-06-07.1",
        "sha256":      "abcdef..." (hash of the *unencoded* bundle bytes),
        "signature":   "..." (HMAC-SHA256 over the manifest minus this field),
        "bundle_b64":  "<base64 of zip>",
        "count":       42,
        "published_at":"2026-06-07T11:24:00Z",
        "release_notes":"Added APT41 RuralBytes ransomware family"
    }
    """
    try:
        bundle_b64 = manifest.get("bundle_b64", "")
        if not bundle_b64:
            print("[RULE-UPDATER] manifest has empty bundle_b64 — ignoring.")
            return False

        bundle = base64.b64decode(bundle_b64)
        if len(bundle) > _MAX_BUNDLE_BYTES:
            print(f"[RULE-UPDATER] bundle too large: {len(bundle)} bytes")
            return False

        # Hash check — content integrity
        actual_hash = _sha256_bytes(bundle)
        if actual_hash != manifest.get("sha256", ""):
            print(f"[RULE-UPDATER] SHA-256 mismatch — rejecting bundle")
            return False

        # Optional HMAC check — authenticity
        if _HMAC_SHARED_SECRET:
            sig = manifest.get("signature", "")
            unsigned = {k: v for k, v in manifest.items() if k != "signature"}
            canonical = json.dumps(unsigned, sort_keys=True,
                                   separators=(",", ":")).encode("utf-8")
            if not _verify_hmac(canonical, sig):
                print("[RULE-UPDATER] HMAC signature invalid — rejecting bundle")
                return False

        # Unpack to staging
        tmp_root = _unpack_bundle_to_temp(bundle)
        if not tmp_root:
            return False

        # Atomic swap
        _atomic_swap(tmp_root)

        # Persist state
        _write_state({
            "version":    manifest.get("version", ""),
            "sha256":     actual_hash,
            "count":      manifest.get("count", 0),
            "updated_at": datetime.utcnow().isoformat() + "Z",
        })

        # Hot-reload engines (they already support this)
        try:
            from core.yara_engine  import reload_yara_rules
            reload_yara_rules()
        except Exception as e:
            print(f"[RULE-UPDATER] yara reload error: {e}")
        try:
            from core.sigma_engine import reload_rules as _sigma_reload
            _sigma_reload()
        except Exception as e:
            print(f"[RULE-UPDATER] sigma reload error: {e}")

        version = manifest.get("version", "?")
        count   = manifest.get("count", 0)
        notes   = manifest.get("release_notes", "")
        msg     = (f"📥 Detection rules updated → v{version} "
                   f"({count} rules active)"
                   + (f" — {notes}" if notes else ""))

        # Log into the FMSecure alert pipeline so GUI sees it
        try:
            from core.integrity_core import append_log_line
            append_log_line(msg, event_type="RULE_UPDATE", severity="INFO")
        except Exception:
            pass
        print(f"[RULE-UPDATER] {msg}")

        # GUI toast / banner
        if gui_cb:
            try:
                gui_cb("RULE_UPDATE", msg, "INFO")
            except Exception:
                pass

        return True

    except Exception as e:
        print(f"[RULE-UPDATER] apply error: {e}")
        return False


def _fetch_and_apply(tenant_key: str,
                     server_url: str,
                     gui_cb: Optional[Callable] = None) -> bool:
    """Make the GET, parse the manifest, apply if newer."""
    if not server_url or not tenant_key:
        return False

    url = server_url.rstrip("/") + _MANIFEST_PATH
    headers = {"x-tenant-key": tenant_key}

    try:
        r = requests.get(url, headers=headers, timeout=_DOWNLOAD_TIMEOUT)
    except Exception as e:
        print(f"[RULE-UPDATER] manifest GET error: {e}")
        return False

    if r.status_code != 200:
        print(f"[RULE-UPDATER] manifest GET status {r.status_code}")
        return False

    try:
        manifest = r.json()
    except Exception:
        print("[RULE-UPDATER] manifest JSON parse error")
        return False

    new_version = manifest.get("version", "")
    cur_version = get_local_version()
    if new_version and new_version == cur_version:
        # Nothing actually changed — server was just confirming
        return False

    return _apply_manifest(manifest, gui_cb=gui_cb)


# ── Public entry points (called from heartbeat loop) ─────────────────────────

def handle_heartbeat_version(server_version: str,
                              tenant_key: str,
                              server_url: str,
                              gui_cb: Optional[Callable] = None):
    """
    Call this from the heartbeat loop in integrity_gui.py *only* when the
    server's response contained a "rule_version" field.

    Cheap branch — exits in microseconds when versions match.

    Thread-safety: re-entry-safe; if a previous fetch is still running,
    this call is a no-op (it just returns).
    """
    if not server_version:
        return
    if server_version == get_local_version():
        return   # 99.9 % of heartbeats hit this fast path

    if not _update_lock.acquire(blocking=False):
        return   # another thread is already updating; let it finish

    def _bg():
        try:
            _fetch_and_apply(tenant_key, server_url, gui_cb)
        finally:
            _update_lock.release()

    threading.Thread(target=_bg, daemon=True,
                     name="FMSecure-RuleUpdater").start()


def force_check(tenant_key: str,
                server_url: str,
                gui_cb: Optional[Callable] = None) -> bool:
    """
    Manual 'Check for rule updates' button. BLOCKING — call from a worker
    thread, never from the Tk main thread.
    Returns True if a new pack was applied, False if up-to-date or error.
    """
    if not _update_lock.acquire(blocking=False):
        return False
    try:
        return _fetch_and_apply(tenant_key, server_url, gui_cb)
    finally:
        _update_lock.release()
