"""
yara_engine.py — FMSecure v2.6
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
YARA malware signature scanning engine.

Scans file content against compiled YARA rules on every
file creation and modification event.

Rules are compiled once at startup into a single
yara.Rules object — subsequent scans are microseconds.

All scanning is async (daemon thread) — never blocks
the watchdog event hot path.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import os
import glob
import threading
import queue
from typing import Optional, Dict, Any, List

_yara_available = False
try:
    import yara
    _yara_available = True
except ImportError:
    print("[YARA] yara-python not installed — YARA scanning disabled.")
    print("[YARA] Install with: pip install yara-python")


# ── Engine ────────────────────────────────────────────────────────────────────

class YaraEngine:
    """
    Loads all .yar / .yara files from rules_dir, compiles them into
    a single yara.Rules object, and exposes scan_file().

    Thread-safe — multiple watchdog threads can call scan_file() concurrently.
    """

    MAX_FILE_SIZE_MB = 20   # skip files larger than this (performance guard)

    def __init__(self, rules_dir: str):
        self.rules_dir    = rules_dir
        self._compiled:   Optional[Any] = None   # yara.Rules object
        self._lock        = threading.RLock()
        self._load_and_compile()

    # ── Loading ───────────────────────────────────────────────────────────────

    def _load_and_compile(self):
        """
        Compile all rule files into one yara.Rules object.
        yara.compile() with filepaths dict is the correct way to
        combine multiple rule files without namespace collisions.
        """
        if not _yara_available:
            return

        rule_files = {}
        for ext in ("*.yar", "*.yara"):
            for path in glob.glob(os.path.join(self.rules_dir, ext)):
                namespace = os.path.splitext(os.path.basename(path))[0]
                rule_files[namespace] = path

        if not rule_files:
            print(f"[YARA] No rule files found in {self.rules_dir}")
            return

        try:
            compiled = yara.compile(filepaths=rule_files)
            with self._lock:
                self._compiled = compiled
            total_rules = sum(1 for _ in compiled)
            print(f"[YARA] Compiled {len(rule_files)} rule files "
                  f"({total_rules} rules) from {self.rules_dir}")
        except yara.SyntaxError as e:
            print(f"[YARA] Rule syntax error: {e}")
        except Exception as e:
            print(f"[YARA] Compile error: {e}")

    def reload(self):
        """Hot-reload rules. Call after adding new rule files."""
        self._load_and_compile()

    @property
    def is_ready(self) -> bool:
        return _yara_available and self._compiled is not None

    # ── Scanning ──────────────────────────────────────────────────────────────

    def scan_file(self, filepath: str) -> Optional[Dict]:
        """
        Scan a single file against all compiled YARA rules.

        Returns a result dict on match:
        {
            "matched":      True,
            "rule_name":    "WannaCry_Ransomware",
            "family":       "WannaCry",
            "description":  "Detects WannaCry ransomware",
            "severity":     "CRITICAL",
            "mitre":        "T1486",
            "strings_hit":  ["$a", "$b"],
            "filepath":     "/path/to/file",
        }

        Returns None if no match or file cannot be scanned.
        Never raises.
        """
        if not self.is_ready:
            return None

        if not os.path.isfile(filepath):
            return None

        # Size guard — skip large files for performance
        try:
            size_mb = os.path.getsize(filepath) / (1024 * 1024)
            if size_mb > self.MAX_FILE_SIZE_MB:
                return None
        except OSError:
            return None

        try:
            with self._lock:
                compiled = self._compiled
            if not compiled:
                return None

            matches = compiled.match(filepath, timeout=10)

            if not matches:
                return None

            # Take the first (highest priority) match
            match        = matches[0]
            meta         = match.meta if hasattr(match, 'meta') else {}
            strings_hit  = [s.identifier for s in match.strings] \
                           if hasattr(match, 'strings') else []

            return {
                "matched":     True,
                "rule_name":   match.rule,
                "namespace":   match.namespace,
                "family":      meta.get("family", match.rule),
                "description": meta.get("description", ""),
                "severity":    meta.get("severity", "HIGH").upper(),
                "mitre":       meta.get("mitre", ""),
                "strings_hit": strings_hit,
                "filepath":    filepath,
                "all_matches": [m.rule for m in matches],
            }

        except yara.TimeoutError:
            print(f"[YARA] Scan timeout: {filepath}")
            return None
        except Exception as e:
            # File locked, permission denied, etc. — non-critical
            return None


# ── Async scanner queue ────────────────────────────────────────────────────────

class AsyncYaraScanner:
    """
    Receives scan jobs via a queue and runs them in a dedicated
    worker thread — completely off the watchdog event thread.

    on_match(filepath, result) is called when a rule matches.
    """

    def __init__(self, engine: YaraEngine, on_match=None):
        self._engine    = engine
        self._on_match  = on_match
        self._queue:    queue.Queue = queue.Queue(maxsize=500)
        self._running   = False
        self._thread:   Optional[threading.Thread] = None

    def start(self):
        self._running = True
        self._thread  = threading.Thread(
            target=self._worker,
            daemon=True,
            name="FMSecure-YaraScanner"
        )
        self._thread.start()

    def stop(self):
        self._running = False

    def submit(self, filepath: str):
        """Non-blocking — drop the job if queue is full."""
        try:
            self._queue.put_nowait(filepath)
        except queue.Full:
            pass   # Under heavy load, drop scan — never block watchdog thread

    def _worker(self):
        while self._running:
            try:
                filepath = self._queue.get(timeout=1.0)
                result   = self._engine.scan_file(filepath)
                if result and self._on_match:
                    try:
                        self._on_match(filepath, result)
                    except Exception as e:
                        print(f"[YARA] on_match callback error: {e}")
                self._queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[YARA] Worker error: {e}")


# ── Module-level singletons ───────────────────────────────────────────────────

_engine:  Optional[YaraEngine]       = None
_scanner: Optional[AsyncYaraScanner] = None


def start_yara_scanning(rules_dir: str, on_match=None) -> bool:
    """
    Initialize and start the YARA scanner.
    Called from FileIntegrityMonitor.start_monitoring().
    """
    global _engine, _scanner

    if not _yara_available:
        print("[YARA] Skipping — yara-python not installed.")
        return False

    if not os.path.isdir(rules_dir):
        print(f"[YARA] Rules directory not found: {rules_dir}")
        return False

    _engine  = YaraEngine(rules_dir=rules_dir)
    if not _engine.is_ready:
        return False

    _scanner = AsyncYaraScanner(engine=_engine, on_match=on_match)
    _scanner.start()
    return True


def stop_yara_scanning():
    """Called from FileIntegrityMonitor.stop_monitoring()."""
    global _scanner
    if _scanner:
        _scanner.stop()


def submit_file_for_scan(filepath: str):
    """
    Called from on_created() and on_modified() in integrity_core.py.
    Non-blocking — returns immediately.
    """
    if _scanner:
        _scanner.submit(filepath)


def reload_yara_rules():
    """Hot-reload rules without restarting monitoring."""
    if _engine:
        _engine.reload()


def get_yara_status() -> Dict:
    """For GUI / dashboard display."""
    return {
        "available":   _yara_available,
        "engine_ready": _engine.is_ready if _engine else False,
        "rules_dir":   _engine.rules_dir if _engine else "",
    }