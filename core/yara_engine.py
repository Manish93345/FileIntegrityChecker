"""
yara_engine.py — FMSecure v2.7
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
YARA malware signature scanning engine.

CHANGED IN v2.7
───────────────
The engine now compiles rules from TWO directories at the same time:

  1. Bundled (read-only)   — sys._MEIPASS / project's core/yara_rules/
                             Shipped inside the .exe. Cannot be changed
                             without rebuilding the binary.
  2. Override (writable)   — %LOCALAPPDATA%\\SecureFIM\\rules\\yara\\
                             Populated by core.rule_updater after a
                             successful pull from the C2 server.

If both directories contain a file with the same name, the OVERRIDE wins —
this is how live updates supersede shipped defaults without ever touching
the read-only bundle.

Hot-reload (`reload_yara_rules()`) still works exactly as before — it
re-scans both dirs in lock-step.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
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
    Loads all .yar / .yara files from BOTH rules_dir (bundled) and the
    optional override_dir (writable, populated by rule_updater).

    Thread-safe — multiple watchdog threads can call scan_file() concurrently.
    """

    MAX_FILE_SIZE_MB = 20   # skip files larger than this (performance guard)

    def __init__(self, rules_dir: str, override_dir: Optional[str] = None):
        self.rules_dir    = rules_dir
        self.override_dir = override_dir
        self._compiled:   Optional[Any] = None   # yara.Rules object
        self._lock        = threading.RLock()
        self._load_and_compile()

    # ── Loading ───────────────────────────────────────────────────────────────

    def _collect_rule_files(self) -> Dict[str, str]:
        """
        Return {namespace: absolute_path}, with override files SHADOWING
        bundled files of the same basename.
        """
        files: Dict[str, str] = {}

        # 1) Bundled first
        for ext in ("*.yar", "*.yara"):
            for path in glob.glob(os.path.join(self.rules_dir, ext)):
                namespace = os.path.splitext(os.path.basename(path))[0]
                files[namespace] = path

        # 2) Override on top — same basename ⇒ overwrite
        if self.override_dir and os.path.isdir(self.override_dir):
            for ext in ("*.yar", "*.yara"):
                for path in glob.glob(os.path.join(self.override_dir, ext)):
                    namespace = os.path.splitext(os.path.basename(path))[0]
                    files[namespace] = path   # override wins

        return files

    def _load_and_compile(self):
        """Compile all rule files into one yara.Rules object."""
        if not _yara_available:
            return

        rule_files = self._collect_rule_files()
        if not rule_files:
            print(f"[YARA] No rule files found in {self.rules_dir} "
                  f"(override={self.override_dir})")
            return

        try:
            compiled = yara.compile(filepaths=rule_files)
            with self._lock:
                self._compiled = compiled
            total_rules = sum(1 for _ in compiled)
            print(f"[YARA] Compiled {len(rule_files)} rule files "
                  f"({total_rules} rules) — "
                  f"bundled={self.rules_dir}, override={self.override_dir}")
        except yara.SyntaxError as e:
            print(f"[YARA] Rule syntax error: {e}")
        except Exception as e:
            print(f"[YARA] Compile error: {e}")

    def reload(self):
        """Hot-reload rules. Called by rule_updater after a successful pull."""
        self._load_and_compile()

    @property
    def is_ready(self) -> bool:
        return _yara_available and self._compiled is not None

    # ── Scanning ──────────────────────────────────────────────────────────────

    def scan_file(self, filepath: str) -> Optional[Dict]:
        """
        Scan a single file against all compiled YARA rules.
        Returns a result dict on match (see original docstring), or None.
        Never raises.
        """
        if not self.is_ready:
            return None

        if not os.path.isfile(filepath):
            return None

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
        except Exception:
            return None


# ── Async scanner queue ────────────────────────────────────────────────────────

class AsyncYaraScanner:
    def __init__(self, engine: YaraEngine, on_match=None):
        self._engine    = engine
        self._on_match  = on_match
        self._queue:    queue.Queue = queue.Queue(maxsize=500)
        self._running   = False
        self._thread:   Optional[threading.Thread] = None

    def start(self):
        self._running = True
        self._thread  = threading.Thread(
            target=self._worker, daemon=True, name="FMSecure-YaraScanner")
        self._thread.start()

    def stop(self):
        self._running = False

    def submit(self, filepath: str):
        try:
            self._queue.put_nowait(filepath)
        except queue.Full:
            pass

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
    Now also discovers the writable override directory from rule_updater.
    """
    global _engine, _scanner

    if not _yara_available:
        print("[YARA] Skipping — yara-python not installed.")
        return False

    if not os.path.isdir(rules_dir):
        print(f"[YARA] Rules directory not found: {rules_dir}")
        return False

    # NEW: writable override directory for live-updated rules
    override_dir: Optional[str] = None
    try:
        from core.rule_updater import get_rules_override_dir
        override_dir = get_rules_override_dir("yara")
    except Exception as e:
        print(f"[YARA] No override dir available: {e}")

    _engine  = YaraEngine(rules_dir=rules_dir, override_dir=override_dir)
    if not _engine.is_ready:
        return False

    _scanner = AsyncYaraScanner(engine=_engine, on_match=on_match)
    _scanner.start()
    return True


def stop_yara_scanning():
    global _scanner
    if _scanner:
        _scanner.stop()


def submit_file_for_scan(filepath: str):
    if _scanner:
        _scanner.submit(filepath)


def reload_yara_rules():
    """Hot-reload rules without restarting monitoring. Called by rule_updater."""
    if _engine:
        _engine.reload()


def get_yara_status() -> Dict:
    """For GUI / dashboard display."""
    return {
        "available":    _yara_available,
        "engine_ready": _engine.is_ready if _engine else False,
        "rules_dir":    _engine.rules_dir    if _engine else "",
        "override_dir": _engine.override_dir if _engine else "",
    }
