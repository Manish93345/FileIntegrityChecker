"""
sigma_engine.py — FMSecure v2.7
Sigma rule evaluation engine.

CHANGED IN v2.7
───────────────
SimpleSigmaEngine now loads rules from BOTH:
  1. Bundled (read-only)   — core/sigma_rules/
  2. Override (writable)   — %LOCALAPPDATA%\\SecureFIM\\rules\\sigma\\

Override files with the same filename SHADOW their bundled counterparts —
enabling live rule updates without rebuilding the .exe.
Hot-reload (`reload_rules()`) re-scans both directories.
"""

import os
import json
import time
import threading
import glob
import yaml
from typing import List, Dict, Any, Optional
from datetime import datetime


class SimpleSigmaEngine:
    """
    Lightweight Sigma evaluator that works directly on FMSecure's ECS JSON events.
    """

    def __init__(self, rules_dir: str, override_dir: Optional[str] = None):
        self.rules_dir    = rules_dir
        self.override_dir = override_dir
        self.rules: List[Dict] = []
        self._lock        = threading.Lock()
        self._load_rules()

    # ── Rule loading ──────────────────────────────────────────────────────────

    def _gather_paths(self) -> List[str]:
        """
        Build the final ordered list of .yml paths to load.
        Override directory wins on basename collision.
        """
        by_name: Dict[str, str] = {}

        # 1) Bundled first
        for path in glob.glob(os.path.join(self.rules_dir, "*.yml")):
            by_name[os.path.basename(path)] = path
        for path in glob.glob(os.path.join(self.rules_dir, "*.yaml")):
            by_name[os.path.basename(path)] = path

        # 2) Override on top — same basename ⇒ overwrite path
        if self.override_dir and os.path.isdir(self.override_dir):
            for path in glob.glob(os.path.join(self.override_dir, "*.yml")):
                by_name[os.path.basename(path)] = path
            for path in glob.glob(os.path.join(self.override_dir, "*.yaml")):
                by_name[os.path.basename(path)] = path

        return list(by_name.values())

    def _load_rules(self):
        """Load and parse all .yml files from bundled + override dirs."""
        loaded = []
        for path in self._gather_paths():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    rule = yaml.safe_load(f)
                if self._validate_rule(rule):
                    rule["_path"] = path
                    loaded.append(rule)
            except Exception as e:
                print(f"[SIGMA] Failed to load {path}: {e}")

        with self._lock:
            self.rules = loaded
        print(f"[SIGMA] Loaded {len(loaded)} detection rules "
              f"(bundled={self.rules_dir}, override={self.override_dir})")

    def reload_rules(self):
        """Hot-reload rules without restarting monitoring. Called by rule_updater."""
        self._load_rules()

    def _validate_rule(self, rule: dict) -> bool:
        return (
            isinstance(rule, dict)
            and "title" in rule
            and "detection" in rule
            and "level" in rule
        )

    # ── Matching logic (unchanged) ────────────────────────────────────────────

    def evaluate(self, event: Dict[str, Any]) -> Optional[Dict]:
        with self._lock:
            rules_snapshot = list(self.rules)

        for rule in rules_snapshot:
            try:
                if self._match_rule(rule, event):
                    return rule
            except Exception:
                continue
        return None

    def _match_rule(self, rule: dict, event: dict) -> bool:
        detection = rule.get("detection", {})
        condition  = detection.get("condition", "selection")
        if condition.strip() != "selection":
            return False

        selection = detection.get("selection", {})
        if not selection:
            return False

        for field_expr, expected in selection.items():
            if not self._match_field(event, field_expr, expected):
                return False
        return True

    def _match_field(self, event: dict, field_expr: str, expected) -> bool:
        modifier = None
        field_path = field_expr
        if "|" in field_expr:
            field_path, modifier = field_expr.split("|", 1)

        actual = self._get_nested(event, field_path)
        if actual is None:
            return False

        actual_str = str(actual).lower()

        if not isinstance(expected, list):
            expected = [expected]

        for exp_val in expected:
            exp_str = str(exp_val).lower()
            if modifier == "contains":
                if exp_str in actual_str:
                    return True
            elif modifier == "startswith":
                if actual_str.startswith(exp_str):
                    return True
            elif modifier == "endswith":
                if actual_str.endswith(exp_str):
                    return True
            else:
                if actual_str == exp_str:
                    return True
        return False

    def _get_nested(self, d: dict, dotted_path: str):
        parts = dotted_path.split(".")
        cur = d
        for part in parts:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(part)
        return cur


# ── Tail + evaluate loop (unchanged) ──────────────────────────────────────────

class SigmaMonitor:
    def __init__(self, telemetry_path: str, engine: SimpleSigmaEngine, gui_callback=None):
        self.telemetry_path = telemetry_path
        self.engine         = engine
        self._running       = False
        self._thread: Optional[threading.Thread] = None
        self._gui_callback = gui_callback

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread  = threading.Thread(
            target=self._tail_loop, daemon=True, name="FMSecure-SigmaMonitor")
        self._thread.start()
        print("[SIGMA] Monitor thread started.")

    def stop(self):
        self._running = False

    def _tail_loop(self):
        fh = None
        while self._running:
            try:
                if fh is None:
                    if os.path.exists(self.telemetry_path):
                        fh = open(self.telemetry_path, "r", encoding="utf-8")
                        fh.seek(0, 2)
                    else:
                        time.sleep(1.0)
                        continue

                line = fh.readline()
                if not line:
                    try:
                        if not os.path.exists(self.telemetry_path):
                            fh.close(); fh = None
                    except Exception:
                        pass
                    time.sleep(0.5)
                    continue

                line = line.strip()
                if not line:
                    continue

                try:
                    event = json.loads(line)
                    self._handle_event(event)
                except json.JSONDecodeError:
                    pass

            except Exception as e:
                print(f"[SIGMA] Tail error (non-critical): {e}")
                if fh:
                    try:
                        fh.close()
                    except Exception:
                        pass
                    fh = None
                time.sleep(2.0)

        if fh:
            try:
                fh.close()
            except Exception:
                pass

    def _handle_event(self, event: dict):
        matched_rule = self.engine.evaluate(event)
        if not matched_rule:
            return

        rule_title   = matched_rule.get("title", "Unknown Rule")
        rule_level   = matched_rule.get("level", "medium").upper()
        rule_id      = matched_rule.get("id", "")
        tags         = matched_rule.get("tags", [])

        severity_map = {
            "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
            "LOW":      "INFO",     "INFO": "INFO",
        }
        severity = severity_map.get(rule_level, "HIGH")

        mitre_id = ""
        for tag in tags:
            tag_lower = tag.lower()
            if tag_lower.startswith("attack.t"):
                mitre_id = tag_lower.replace("attack.", "").upper()
                break

        original_msg = event.get("message", "")
        file_path    = event.get("file", {}).get("path", "")

        alert_msg = (
            f"[SIGMA RULE MATCH] {rule_title}"
            + (f" [{mitre_id}]" if mitre_id else "")
            + f" — {original_msg}"
        )

        try:
            from core.integrity_core import append_log_line, send_webhook_safe
            append_log_line(
                alert_msg, event_type=f"SIGMA_{rule_level}",
                severity=severity, file_path=file_path or None)
            if self._gui_callback:
                try:
                    self._gui_callback(f"SIGMA_{rule_level}", alert_msg, severity)
                except Exception:
                    pass
            if severity in ("HIGH", "CRITICAL"):
                send_webhook_safe(
                    f"SIGMA_RULE_{rule_level}", alert_msg,
                    filepath=file_path or None, severity=severity)
        except Exception as e:
            print(f"[SIGMA] Alert dispatch error: {e}")


# ── Module-level singleton ────────────────────────────────────────────────────

_monitor: Optional[SigmaMonitor] = None
_engine:  Optional[SimpleSigmaEngine] = None


def start_sigma_monitoring(telemetry_path: str, rules_dir: str, gui_callback=None) -> bool:
    """
    Start the Sigma rule monitor.
    Now also discovers the writable override directory from rule_updater.
    """
    global _monitor, _engine

    if not os.path.isdir(rules_dir):
        print(f"[SIGMA] Rules directory not found: {rules_dir}")
        return False

    # NEW: writable override directory for live-updated rules
    override_dir: Optional[str] = None
    try:
        from core.rule_updater import get_rules_override_dir
        override_dir = get_rules_override_dir("sigma")
    except Exception as e:
        print(f"[SIGMA] No override dir available: {e}")

    _engine  = SimpleSigmaEngine(rules_dir=rules_dir, override_dir=override_dir)
    if not _engine.rules:
        print("[SIGMA] No rules loaded — monitor not started.")
        return False

    _monitor = SigmaMonitor(telemetry_path=telemetry_path,
                            engine=_engine, gui_callback=gui_callback)
    _monitor.start()
    return True


def stop_sigma_monitoring():
    global _monitor
    if _monitor:
        _monitor.stop()


def reload_rules():
    """Hot-reload rules. Called by rule_updater."""
    if _engine:
        _engine.reload_rules()


def get_loaded_rules() -> List[Dict]:
    """Return list of loaded rule metadata for GUI display."""
    if _engine:
        with _engine._lock:
            return [
                {
                    "title": r.get("title", "?"),
                    "level": r.get("level", "?"),
                    "id":    r.get("id", "?"),
                    "tags":  r.get("tags", []),
                }
                for r in _engine.rules
            ]
    return []
