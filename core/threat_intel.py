"""
threat_intel.py — FMSecure v2.6
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
THREAT INTELLIGENCE ENGINE  —  Gap 4 Fix

Compares every newly detected or modified file's SHA-256 hash against
known malware signatures from three sources:

  Source 1 — MalwareBazaar (abuse.ch)
    Free API, no key required.
    Endpoint: POST https://mb-api.abuse.ch/api/v1/
    Covers: ransomware, RATs, stealers, loaders — 300k+ samples.

  Source 2 — Local SQLite cache
    Results from Source 1 are cached for 7 days.
    Zero network calls for repeat encounters (same malware re-deployed).
    Database: AppData/FMSecure/threat_db.sqlite

  Source 3 — VirusTotal (optional, requires API key in config.json)
    Falls back to VT if MalwareBazaar returns no result.
    Free tier: 4 lookups/minute, 500/day.
    Config key: "virustotal_api_key"

WORKFLOW (per file event)
  1. Generate SHA-256 content hash
  2. Check local cache → instant result if seen recently
  3. If not cached, query MalwareBazaar (async, non-blocking)
  4. If MB returns a hit: CRITICAL alert + quarantine (move to vault)
  5. If MB returns no hit AND VT key configured: query VT
  6. Cache the combined result
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import os
import json
import sqlite3
import hashlib
import threading
import time
import requests
from datetime import datetime, timedelta

from core.utils import get_app_data_dir

# ── Database path ─────────────────────────────────────────────────────
_DB_PATH = os.path.join(get_app_data_dir(), "logs", "threat_db.sqlite")

# ── API endpoints ─────────────────────────────────────────────────────
_MB_URL = "https://mb-api.abuse.ch/api/v1/"
_VT_URL = "https://www.virustotal.com/api/v3/files/{}"

# ── Cache TTL: 7 days for clean files, 30 days for malicious ─────────
_TTL_CLEAN     = 7   * 24 * 3600
_TTL_MALICIOUS = 30  * 24 * 3600

# ── Request timeout ────────────────────────────────────────────────────
_TIMEOUT = 8  # seconds

# ── In-memory hit cache (avoids repeated DB reads in burst events) ────
_mem_cache: dict = {}
_mem_lock = threading.Lock()


# ── Database setup ────────────────────────────────────────────────────

def _get_db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(_DB_PATH, timeout=10, check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS threat_cache (
            sha256       TEXT PRIMARY KEY,
            is_malicious INTEGER NOT NULL DEFAULT 0,
            malware_name TEXT,
            malware_family TEXT,
            threat_type  TEXT,
            source       TEXT,
            vt_positives INTEGER DEFAULT 0,
            vt_total     INTEGER DEFAULT 0,
            mb_url       TEXT,
            checked_at   REAL NOT NULL,
            expires_at   REAL NOT NULL
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_sha256 ON threat_cache(sha256)
    """)
    conn.commit()
    return conn


def _cache_lookup(sha256: str) -> dict | None:
    """Return cached result if not expired, else None."""
    sha256 = sha256.lower()

    # Check memory cache first
    with _mem_lock:
        if sha256 in _mem_cache:
            entry = _mem_cache[sha256]
            if time.time() < entry['expires_at']:
                return entry

    # Check SQLite
    try:
        conn = _get_db()
        row = conn.execute(
            "SELECT * FROM threat_cache WHERE sha256=? AND expires_at > ?",
            (sha256, time.time())
        ).fetchone()
        conn.close()
        if row:
            result = {
                'sha256':          row[0],
                'is_malicious':    bool(row[1]),
                'malware_name':    row[2] or '',
                'malware_family':  row[3] or '',
                'threat_type':     row[4] or '',
                'source':          row[5] or '',
                'vt_positives':    row[6] or 0,
                'vt_total':        row[7] or 0,
                'mb_url':          row[8] or '',
                'checked_at':      row[9],
                'expires_at':      row[10],
            }
            with _mem_lock:
                _mem_cache[sha256] = result
            return result
    except Exception as e:
        print(f"[THREAT] DB lookup error: {e}")
    return None


def _cache_store(result: dict):
    """Store a lookup result in DB + memory cache."""
    sha256 = result['sha256'].lower()
    ttl    = _TTL_MALICIOUS if result['is_malicious'] else _TTL_CLEAN
    result['expires_at'] = time.time() + ttl
    result['checked_at'] = time.time()

    with _mem_lock:
        _mem_cache[sha256] = result

    try:
        conn = _get_db()
        conn.execute("""
            INSERT OR REPLACE INTO threat_cache
            (sha256, is_malicious, malware_name, malware_family, threat_type,
             source, vt_positives, vt_total, mb_url, checked_at, expires_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (
            sha256,
            1 if result['is_malicious'] else 0,
            result.get('malware_name', ''),
            result.get('malware_family', ''),
            result.get('threat_type', ''),
            result.get('source', ''),
            result.get('vt_positives', 0),
            result.get('vt_total', 0),
            result.get('mb_url', ''),
            result['checked_at'],
            result['expires_at'],
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[THREAT] DB store error: {e}")


# ── Source 1: MalwareBazaar ───────────────────────────────────────────

def _query_malwarebazaar(sha256: str) -> dict | None:
    """
    Query MalwareBazaar hash lookup.
    Returns result dict or None on network/API error.
    """
    try:
        r = requests.post(
            _MB_URL,
            data={"query": "get_info", "hash": sha256},
            timeout=_TIMEOUT,
            headers={"User-Agent": "FMSecure-EDR/2.6"}
        )
        if r.status_code != 200:
            return None
        data = r.json()
        if data.get("query_status") == "hash_not_found":
            return {
                'sha256':         sha256,
                'is_malicious':   False,
                'malware_name':   '',
                'malware_family': '',
                'threat_type':    '',
                'source':         'malwarebazaar',
                'vt_positives':   0,
                'vt_total':       0,
                'mb_url':         '',
            }
        if data.get("query_status") == "ok":
            info = data.get("data", [{}])[0]
            return {
                'sha256':         sha256,
                'is_malicious':   True,
                'malware_name':   info.get("file_name", ""),
                'malware_family': info.get("tags", [""])[0] if info.get("tags") else "",
                'threat_type':    info.get("file_type", ""),
                'source':         'malwarebazaar',
                'vt_positives':   0,
                'vt_total':       0,
                'mb_url':         f"https://bazaar.abuse.ch/sample/{sha256}/",
            }
    except Exception as e:
        print(f"[THREAT] MalwareBazaar query error: {e}")
    return None


# ── Source 2: VirusTotal ──────────────────────────────────────────────

def _query_virustotal(sha256: str, api_key: str) -> dict | None:
    """
    Query VirusTotal v3 for a file hash.
    Requires api_key. Free tier: 4 req/min, 500/day.
    """
    if not api_key:
        return None
    try:
        url = _VT_URL.format(sha256)
        r   = requests.get(
            url,
            headers={"x-apikey": api_key},
            timeout=_TIMEOUT
        )
        if r.status_code == 404:
            return {
                'sha256':         sha256,
                'is_malicious':   False,
                'malware_name':   '',
                'malware_family': '',
                'threat_type':    '',
                'source':         'virustotal',
                'vt_positives':   0,
                'vt_total':       0,
                'mb_url':         '',
            }
        if r.status_code == 200:
            attrs      = r.json().get("data", {}).get("attributes", {})
            stats      = attrs.get("last_analysis_stats", {})
            positives  = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total      = sum(stats.values())
            names      = attrs.get("meaningful_name", "")
            is_bad     = positives >= 3  # threshold: 3+ engines

            # Get the most-common detection name
            results    = attrs.get("last_analysis_results", {})
            detections = [v.get("result", "") for v in results.values()
                          if v.get("category") == "malicious" and v.get("result")]
            from collections import Counter
            name = Counter(detections).most_common(1)[0][0] if detections else names

            return {
                'sha256':         sha256,
                'is_malicious':   is_bad,
                'malware_name':   name,
                'malware_family': attrs.get("popular_threat_classification",
                                            {}).get("suggested_threat_label", ""),
                'threat_type':    attrs.get("type_description", ""),
                'source':         'virustotal',
                'vt_positives':   positives,
                'vt_total':       total,
                'mb_url':         f"https://www.virustotal.com/gui/file/{sha256}",
            }
    except Exception as e:
        print(f"[THREAT] VirusTotal query error: {e}")
    return None


# ── Main lookup function ──────────────────────────────────────────────

def check_file_hash(sha256: str, vt_api_key: str = '') -> dict:
    """
    Full lookup pipeline: cache → MalwareBazaar → VirusTotal.
    Always returns a dict. Never raises.

    Returns:
    {
        'sha256':         str,
        'is_malicious':   bool,
        'malware_name':   str,
        'malware_family': str,
        'threat_type':    str,
        'source':         str,   # 'cache' | 'malwarebazaar' | 'virustotal'
        'vt_positives':   int,
        'vt_total':       int,
        'mb_url':         str,
        'checked_at':     float,
        'expires_at':     float,
        'error':          str,   # present only on failure
    }
    """
    sha256 = sha256.lower()
    EMPTY  = {
        'sha256': sha256, 'is_malicious': False,
        'malware_name': '', 'malware_family': '', 'threat_type': '',
        'source': '', 'vt_positives': 0, 'vt_total': 0, 'mb_url': '',
        'checked_at': time.time(), 'expires_at': time.time() + _TTL_CLEAN,
    }

    # 1. Cache check
    cached = _cache_lookup(sha256)
    if cached:
        cached['source'] = 'cache'
        return cached

    # 2. MalwareBazaar
    result = _query_malwarebazaar(sha256)

    # 3. VirusTotal fallback (only if MB gave no result or clean, and key present)
    if result is None or (not result['is_malicious'] and vt_api_key):
        vt = _query_virustotal(sha256, vt_api_key)
        if vt and vt['is_malicious']:
            result = vt  # VT found something MB missed

    if result is None:
        EMPTY['error'] = 'network_failure'
        return EMPTY

    _cache_store(result)
    return result


def format_threat_result(result: dict) -> str:
    """
    Format a threat lookup result for log insertion.
    Returns empty string for clean files.
    """
    if not result.get('is_malicious'):
        return ''
    name   = result.get('malware_name', 'Unknown Malware')
    family = result.get('malware_family', '')
    src    = result.get('source', '')
    pos    = result.get('vt_positives', 0)
    total  = result.get('vt_total', 0)
    url    = result.get('mb_url', '')

    parts = [f"⚠ KNOWN MALWARE: {name}"]
    if family:
        parts.append(f"Family: {family}")
    if pos:
        parts.append(f"VT: {pos}/{total}")
    if src != 'cache':
        parts.append(f"[{src}]")
    if url:
        parts.append(f"Ref: {url}")
    return ' | '.join(parts)


# ── Async check (non-blocking, fires callback when done) ─────────────

class ThreatIntelEngine:
    """
    Async wrapper around check_file_hash.
    Queues checks into a thread pool so file events are never blocked.
    """

    def __init__(self, max_workers: int = 3):
        self._queue   = []
        self._lock    = threading.Lock()
        self._semaphore = threading.Semaphore(max_workers)
        self._vt_key  = ''

    def configure(self, config: dict):
        self._vt_key = config.get('virustotal_api_key', '')

    def check_async(self, filepath: str, sha256: str,
                    on_malicious=None, log_fn=None, alert_callback=None):
        """
        Kicks off an async hash check.
        on_malicious(filepath, result) called if malware is found.
        """
        def _run():
            self._semaphore.acquire()
            try:
                result = check_file_hash(sha256, vt_api_key=self._vt_key)
                if result.get('is_malicious'):
                    self._handle_malicious(
                        filepath, result, on_malicious, log_fn, alert_callback)
            finally:
                self._semaphore.release()

        t = threading.Thread(target=_run, daemon=True,
                              name=f"FMSecure-ThreatCheck")
        t.start()

    def _handle_malicious(self, filepath: str, result: dict,
                           on_malicious, log_fn, alert_callback):
        name    = result.get('malware_name', 'Unknown Malware')
        family  = result.get('malware_family', '')
        src     = result.get('source', '')
        url     = result.get('mb_url', '')

        family_str = f" ({family})" if family else ""
        msg = (f"MALWARE DETECTED: {name}{family_str} in file:\n"
               f"  {filepath}\n"
               f"  Source: {src} | Ref: {url or 'N/A'}")

        print(f"[THREAT] 🚨 {msg}")

        if log_fn:
            try:
                log_fn(msg, event_type="MALWARE_DETECTED", severity="CRITICAL")
            except Exception:
                pass

        if alert_callback:
            try:
                alert_callback("MALWARE_DETECTED", filepath, "CRITICAL")
            except Exception:
                pass

        # Generate forensic snapshot
        try:
            from core.incident_snapshot import generate_incident_snapshot
            generate_incident_snapshot(
                event_type="MALWARE_DETECTED",
                severity="CRITICAL",
                message=msg,
                affected_files=[filepath],
                additional_data={
                    'sha256':         result['sha256'],
                    'malware_name':   result.get('malware_name', ''),
                    'malware_family': result.get('malware_family', ''),
                    'vt_positives':   result.get('vt_positives', 0),
                    'source':         src,
                    'reference_url':  url,
                }
            )
        except Exception:
            pass

        if on_malicious:
            try:
                on_malicious(filepath, result)
            except Exception:
                pass


# ── Module-level singleton ────────────────────────────────────────────
_engine: ThreatIntelEngine | None = None
_engine_lock = threading.Lock()


def get_engine() -> ThreatIntelEngine:
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = ThreatIntelEngine()
        return _engine


def check_file_threat(filepath: str, content_hash: str,
                       log_fn=None, alert_callback=None):
    """
    Convenience: async threat check for a file.
    content_hash is the plain SHA-256 of file contents
    (integrity_core stores this as details['content']).

    Usage in integrity_core.py on_created / on_modified:
        from core.threat_intel import check_file_threat
        check_file_threat(path, details['content'],
                          log_fn=append_log_line,
                          alert_callback=self._notify_gui)
    """
    if not content_hash or len(content_hash) != 64:
        return
    get_engine().check_async(
        filepath, content_hash,
        log_fn=log_fn,
        alert_callback=alert_callback
    )


def get_db_stats() -> dict:
    """Return database statistics for GUI display."""
    try:
        conn  = _get_db()
        total = conn.execute("SELECT COUNT(*) FROM threat_cache").fetchone()[0]
        bad   = conn.execute(
            "SELECT COUNT(*) FROM threat_cache WHERE is_malicious=1"
        ).fetchone()[0]
        conn.close()
        return {'total_cached': total, 'known_malicious': bad}
    except Exception:
        return {'total_cached': 0, 'known_malicious': 0}