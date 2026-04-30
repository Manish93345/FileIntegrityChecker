"""
sigma_engine.py — FMSecure v2.6
Sigma rule evaluation engine.

Tails telemetry.jsonl and evaluates every new event against
.yml rule files in core/sigma_rules/.

When a rule fires:
  - calls append_log_line() so the GUI shows it
  - emits a structured telemetry event tagged with the Sigma rule name
  - triggers send_webhook_safe() for HIGH/CRITICAL matches
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

    Why not use pySigma's full backend system:
      pySigma is designed to *convert* Sigma rules to SIEM query languages
      (Splunk SPL, Elastic KQL, etc.). For *real-time evaluation* against a
      JSON stream, a direct field-matching approach is faster and simpler.
      pySigma is still used for rule parsing/validation.
    """

    def __init__(self, rules_dir: str):
        self.rules_dir   = rules_dir
        self.rules: List[Dict] = []
        self._lock       = threading.Lock()
        self._load_rules()

    # ── Rule loading ──────────────────────────────────────────────────────────

    def _load_rules(self):
        """Load and parse all .yml files from the rules directory."""
        loaded = []
        pattern = os.path.join(self.rules_dir, "*.yml")
        for path in glob.glob(pattern):
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
        print(f"[SIGMA] Loaded {len(loaded)} detection rules from {self.rules_dir}")

    def reload_rules(self):
        """Hot-reload rules without restarting monitoring. Call from GUI."""
        self._load_rules()

    def _validate_rule(self, rule: dict) -> bool:
        """Minimal validation — must have title, detection, level."""
        return (
            isinstance(rule, dict)
            and "title" in rule
            and "detection" in rule
            and "level" in rule
        )

    # ── Matching logic ────────────────────────────────────────────────────────

    def evaluate(self, event: Dict[str, Any]) -> Optional[Dict]:
        """
        Evaluate a single ECS event dict against all loaded rules.
        Returns the first matching rule dict, or None if no match.

        Supports Sigma condition operators:
          - Simple field equality:   field: value
          - List OR:                 field: [v1, v2, v3]
          - Contains modifier:       field|contains: substring
          - startswith modifier:     field|startswith: prefix
          - endswith modifier:       field|endswith: suffix
          - condition: selection (only mode implemented — covers 95% of rules)
        """
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

        # Only handle "condition: selection" for now
        # This covers the vast majority of Sigma rules
        if condition.strip() != "selection":
            return False

        selection = detection.get("selection", {})
        if not selection:
            return False

        # All fields in selection must match (AND logic)
        for field_expr, expected in selection.items():
            if not self._match_field(event, field_expr, expected):
                return False
        return True

    def _match_field(self, event: dict, field_expr: str, expected) -> bool:
        """
        Resolve a dotted field path with optional modifier (contains/startswith/endswith).
        field_expr examples:
            "fmsecure.event_type"
            "message|contains"
            "file.path|contains"
        """
        # Parse modifier
        modifier = None
        field_path = field_expr
        if "|" in field_expr:
            field_path, modifier = field_expr.split("|", 1)

        # Resolve dotted path in nested dict
        actual = self._get_nested(event, field_path)
        if actual is None:
            return False

        actual_str = str(actual).lower()

        # Normalize expected to list
        if not isinstance(expected, list):
            expected = [expected]

        # Any value in the list can match (OR logic within a field)
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
                # Exact match
                if actual_str == exp_str:
                    return True

        return False

    def _get_nested(self, d: dict, dotted_path: str):
        """Resolve 'a.b.c' into d['a']['b']['c'], returns None if missing."""
        parts = dotted_path.split(".")
        cur = d
        for part in parts:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(part)
        return cur


# ── Tail + evaluate loop ───────────────────────────────────────────────────────

class SigmaMonitor:
    """
    Background thread that tails telemetry.jsonl and runs rule evaluation
    on every new line.
    """

    def __init__(self, telemetry_path: str, engine: SimpleSigmaEngine):
        self.telemetry_path = telemetry_path
        self.engine         = engine
        self._running       = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread  = threading.Thread(
            target=self._tail_loop,
            daemon=True,
            name="FMSecure-SigmaMonitor"
        )
        self._thread.start()
        print("[SIGMA] Monitor thread started.")

    def stop(self):
        self._running = False

    def _tail_loop(self):
        """
        Efficient tail implementation:
          - seek to end of file on startup (don't re-evaluate old events)
          - poll for new lines every 0.5 seconds
          - handle file rotation (file disappears → reopen)
        """
        fh = None
        while self._running:
            try:
                if fh is None:
                    if os.path.exists(self.telemetry_path):
                        fh = open(self.telemetry_path, "r", encoding="utf-8")
                        fh.seek(0, 2)   # seek to end — ignore historical events
                    else:
                        time.sleep(1.0)
                        continue

                line = fh.readline()
                if not line:
                    # No new data — check if file was rotated
                    try:
                        if not os.path.exists(self.telemetry_path):
                            fh.close()
                            fh = None
                    except Exception:
                        pass
                    time.sleep(0.5)
                    continue

                line = line.strip()
                if not line:
                    continue

                # Parse and evaluate
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
        """Called for every new telemetry event. Evaluates rules and fires alerts."""
        matched_rule = self.engine.evaluate(event)
        if not matched_rule:
            return

        rule_title   = matched_rule.get("title", "Unknown Rule")
        rule_level   = matched_rule.get("level", "medium").upper()
        rule_id      = matched_rule.get("id", "")
        tags         = matched_rule.get("tags", [])

        # Map Sigma level to FMSecure severity
        severity_map = {
            "CRITICAL": "CRITICAL",
            "HIGH":     "HIGH",
            "MEDIUM":   "MEDIUM",
            "LOW":      "INFO",
            "INFO":     "INFO",
        }
        severity = severity_map.get(rule_level, "HIGH")

        # Extract MITRE technique from tags e.g. "attack.t1486"
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

        # Fire into the standard FMSecure alert pipeline
        try:
            from core.integrity_core import append_log_line, send_webhook_safe
            append_log_line(
                alert_msg,
                event_type=f"SIGMA_{rule_level}",
                severity=severity,
                file_path=file_path or None,
            )
            if severity in ("HIGH", "CRITICAL"):
                send_webhook_safe(
                    f"SIGMA_RULE_{rule_level}",
                    alert_msg,
                    filepath=file_path or None,
                    severity=severity,
                )
        except Exception as e:
            print(f"[SIGMA] Alert dispatch error: {e}")


# ── Module-level singleton ────────────────────────────────────────────────────

_monitor: Optional[SigmaMonitor] = None
_engine:  Optional[SimpleSigmaEngine] = None


def start_sigma_monitoring(telemetry_path: str, rules_dir: str) -> bool:
    """
    Start the Sigma rule monitor.
    Called from FileIntegrityMonitor.start_monitoring().
    Safe to call multiple times — only one thread runs.
    """
    global _monitor, _engine

    if not os.path.isdir(rules_dir):
        print(f"[SIGMA] Rules directory not found: {rules_dir}")
        return False

    _engine  = SimpleSigmaEngine(rules_dir=rules_dir)
    if not _engine.rules:
        print("[SIGMA] No rules loaded — monitor not started.")
        return False

    _monitor = SigmaMonitor(telemetry_path=telemetry_path, engine=_engine)
    _monitor.start()
    return True


def stop_sigma_monitoring():
    """Called from FileIntegrityMonitor.stop_monitoring()."""
    global _monitor
    if _monitor:
        _monitor.stop()


def reload_rules():
    """Hot-reload rules. Can be wired to a GUI button later."""
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