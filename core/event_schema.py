"""
event_schema.py — FMSecure v2.6
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ECS (Elastic Common Schema) Structured Event Builder
MITRE ATT&CK Technique Mapping

PURPOSE
────────
Every security event in FMSecure now emits TWO records:
  1. The existing AES-encrypted human-readable log (integrity_log.dat)
     — used by the GUI, forensics vault, audit viewer (unchanged)
  2. A new structured JSONL telemetry log (telemetry.jsonl)
     — one JSON object per line, ECS-compliant
     — can be directly ingested by: Splunk, Elastic SIEM, Microsoft Sentinel,
       IBM QRadar, Wazuh, or any tool that accepts JSON/Syslog/CEF

SCHEMA REFERENCE
─────────────────
  ECS: https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html
  OSSEM: https://github.com/OTRF/OSSEM

MITRE ATT&CK FIELDS
────────────────────
  threat.technique.id    — e.g. "T1059.001"
  threat.technique.name  — e.g. "PowerShell"
  threat.tactic.id       — e.g. "TA0002"
  threat.tactic.name     — e.g. "Execution"

USAGE
──────
  from core.event_schema import build_ecs_event, emit_telemetry_event

  # Called automatically from integrity_core.append_log_line()
  # Can also be called directly for richer events (process, network)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import os
import json
import socket
import platform
import threading
from datetime import datetime, timezone
from typing import Optional, Dict, Any

# ── MITRE ATT&CK Mapping ──────────────────────────────────────────────────────
# Maps FMSecure event types to MITRE ATT&CK techniques.
# Reference: https://attack.mitre.org/
#
# Format per entry:
#   "EVENT_TYPE": {
#       "technique_id":   str  — e.g. "T1565.001"
#       "technique_name": str
#       "tactic_id":      str  — e.g. "TA0040"
#       "tactic_name":    str
#       "sub_technique":  bool — True if technique_id contains a dot
#   }
#
# When an event has no specific ATT&CK mapping (e.g. routine INFO events)
# the fields are omitted from the ECS event to keep the schema clean.

MITRE_MAPPING: Dict[str, Dict[str, str]] = {

    # ── File Integrity ────────────────────────────────────────────────────
    "MODIFIED": {
        "technique_id":   "T1565.001",
        "technique_name": "Stored Data Manipulation",
        "tactic_id":      "TA0040",
        "tactic_name":    "Impact",
    },
    "TAMPERED_RECORDS": {
        "technique_id":   "T1565.001",
        "technique_name": "Stored Data Manipulation",
        "tactic_id":      "TA0040",
        "tactic_name":    "Impact",
    },
    "TAMPERED_LOGS": {
        "technique_id":   "T1070.002",
        "technique_name": "Clear Linux or Mac System Logs",
        "tactic_id":      "TA0005",
        "tactic_name":    "Defense Evasion",
    },
    "LOG_INTEGRITY_FAIL": {
        "technique_id":   "T1070.002",
        "technique_name": "Clear Linux or Mac System Logs",
        "tactic_id":      "TA0005",
        "tactic_name":    "Defense Evasion",
    },
    "INTEGRITY_FAIL": {
        "technique_id":   "T1565.001",
        "technique_name": "Stored Data Manipulation",
        "tactic_id":      "TA0040",
        "tactic_name":    "Impact",
    },
    "SIGNATURE_MISMATCH": {
        "technique_id":   "T1565.001",
        "technique_name": "Stored Data Manipulation",
        "tactic_id":      "TA0040",
        "tactic_name":    "Impact",
    },

    # ── Ransomware / Destruction ──────────────────────────────────────────
    "BURST_OPERATION": {
        "technique_id":   "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic_id":      "TA0040",
        "tactic_name":    "Impact",
    },
    "MULTIPLE_DELETES": {
        "technique_id":   "T1485",
        "technique_name": "Data Destruction",
        "tactic_id":      "TA0040",
        "tactic_name":    "Impact",
    },
    "RANSOMWARE_BURST": {
        "technique_id":   "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic_id":      "TA0040",
        "tactic_name":    "Impact",
    },
    "MASS_DELETION_BURST": {
        "technique_id":   "T1485",
        "technique_name": "Data Destruction",
        "tactic_id":      "TA0040",
        "tactic_name":    "Impact",
    },

    # ── Persistence / Registry ───────────────────────────────────────────
    "REGISTRY_PERSISTENCE_NEW": {
        "technique_id":   "T1547.001",
        "technique_name": "Registry Run Keys / Startup Folder",
        "tactic_id":      "TA0003",
        "tactic_name":    "Persistence",
    },
    "REGISTRY_VALUE_CHANGED": {
        "technique_id":   "T1112",
        "technique_name": "Modify Registry",
        "tactic_id":      "TA0005",
        "tactic_name":    "Defense Evasion",
    },
    "REGISTRY_VALUE_DELETED": {
        "technique_id":   "T1112",
        "technique_name": "Modify Registry",
        "tactic_id":      "TA0005",
        "tactic_name":    "Defense Evasion",
    },

    # ── System Path Events ────────────────────────────────────────────────
    "SYSTEM_PATH_MODIFIED": {
        "technique_id":   "T1543",
        "technique_name": "Create or Modify System Process",
        "tactic_id":      "TA0003",
        "tactic_name":    "Persistence",
    },
    "HONEYPOT_BREACH": {
        "technique_id":   "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic_id":      "TA0007",
        "tactic_name":    "Discovery",
    },

    # ── Malware Detection ────────────────────────────────────────────────
    "MALWARE_DETECTED": {
        "technique_id":   "T1204",
        "technique_name": "User Execution",
        "tactic_id":      "TA0002",
        "tactic_name":    "Execution",
    },

    # ── Process Attribution LOLBin ───────────────────────────────────────
    "PROCESS_ATTRIBUTION": {
        "technique_id":   "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic_id":      "TA0002",
        "tactic_name":    "Execution",
    },

    # ── Configuration / Settings ─────────────────────────────────────────
    "CONFIG_CHANGED": {
        "technique_id":   "T1562.001",
        "technique_name": "Disable or Modify Tools",
        "tactic_id":      "TA0005",
        "tactic_name":    "Defense Evasion",
    },

    # ── Safe Mode (Incident Response) ────────────────────────────────────
    "SAFE_MODE_ACTIVATED": {
        "technique_id":   "T1562",
        "technique_name": "Impair Defenses",
        "tactic_id":      "TA0005",
        "tactic_name":    "Defense Evasion",
    },
}

# ── ECS event.category mapping ───────────────────────────────────────────────
# Maps event_type → ECS event.category + event.type arrays

ECS_CATEGORY_MAP: Dict[str, Dict] = {
    "CREATED":                  {"category": ["file"], "type": ["creation"]},
    "MODIFIED":                 {"category": ["file"], "type": ["change"]},
    "DELETED":                  {"category": ["file"], "type": ["deletion"]},
    "DELETED_UNTRACKED":        {"category": ["file"], "type": ["deletion"]},
    "CREATED_ON_MODIFY":        {"category": ["file"], "type": ["creation"]},
    "RENAMED":                  {"category": ["file"], "type": ["change"]},
    "RESTORED":                 {"category": ["file"], "type": ["creation"]},
    "TAMPERED_RECORDS":         {"category": ["file", "intrusion_detection"], "type": ["change"]},
    "TAMPERED_LOGS":            {"category": ["file", "intrusion_detection"], "type": ["change"]},
    "LOG_INTEGRITY_FAIL":       {"category": ["intrusion_detection"], "type": ["info"]},
    "INTEGRITY_FAIL":           {"category": ["intrusion_detection"], "type": ["info"]},
    "SIGNATURE_MISMATCH":       {"category": ["intrusion_detection"], "type": ["info"]},
    "BURST_OPERATION":          {"category": ["intrusion_detection", "malware"], "type": ["info"]},
    "RANSOMWARE_BURST":         {"category": ["intrusion_detection", "malware"], "type": ["info"]},
    "MULTIPLE_DELETES":         {"category": ["intrusion_detection"], "type": ["info"]},
    "MASS_DELETION_BURST":      {"category": ["intrusion_detection"], "type": ["info"]},
    "REGISTRY_PERSISTENCE_NEW": {"category": ["registry"], "type": ["creation"]},
    "REGISTRY_VALUE_CHANGED":   {"category": ["registry"], "type": ["change"]},
    "REGISTRY_VALUE_DELETED":   {"category": ["registry"], "type": ["deletion"]},
    "HONEYPOT_BREACH":          {"category": ["intrusion_detection"], "type": ["info"]},
    "MALWARE_DETECTED":         {"category": ["malware", "intrusion_detection"], "type": ["info"]},
    "PROCESS_ATTRIBUTION":      {"category": ["process"], "type": ["info"]},
    "CONFIG_CHANGED":           {"category": ["configuration"], "type": ["change"]},
    "MONITOR_STARTED":          {"category": ["process"], "type": ["start"]},
    "MONITOR_STOPPED":          {"category": ["process"], "type": ["end"]},
    "SAFE_MODE_ACTIVATED":      {"category": ["intrusion_detection"], "type": ["info"]},
    "WATCHED_FOLDER_DELETED":   {"category": ["file", "intrusion_detection"], "type": ["deletion"]},
    "SYSTEM_MONITORING_ADDED":  {"category": ["process"], "type": ["info"]},
}

# ── ECS severity → numeric mapping ───────────────────────────────────────────
SEVERITY_NUMERIC = {"INFO": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# ── Module-level cached host info (read once, reused) ────────────────────────
_HOST_INFO: Optional[Dict] = None
_HOST_LOCK = threading.Lock()


def _get_host_info() -> Dict:
    global _HOST_INFO
    if _HOST_INFO:
        return _HOST_INFO
    with _HOST_LOCK:
        if _HOST_INFO:
            return _HOST_INFO
        try:
            from core.encryption_manager import crypto_manager
            machine_id = crypto_manager.get_machine_id()
        except Exception:
            hw = f"{platform.node()}-{platform.machine()}-{platform.processor()}"
            import hashlib
            machine_id = "FM-" + hashlib.sha256(hw.encode()).hexdigest()[:24].upper()

        try:
            from version import APP_VERSION
        except ImportError:
            APP_VERSION = "2.6.0"

        _HOST_INFO = {
            "hostname":    platform.node(),
            "machine_id":  machine_id,
            "os_name":     platform.system(),
            "os_version":  platform.version()[:64],
            "agent_version": APP_VERSION,
        }
    return _HOST_INFO


# ── Core builder ──────────────────────────────────────────────────────────────

def build_ecs_event(
    message:    str,
    event_type: str,
    severity:   str,
    file_path:  Optional[str]  = None,
    file_hash:  Optional[str]  = None,
    process_pid:   Optional[int]  = None,
    process_name:  Optional[str]  = None,
    process_parent: Optional[str] = None,
    extra:      Optional[Dict]  = None,
) -> Dict[str, Any]:
    """
    Build a fully ECS-compliant event dict.

    Required:
        message     — human-readable description
        event_type  — FMSecure event type string (e.g. "MODIFIED", "RANSOMWARE_BURST")
        severity    — "INFO" | "MEDIUM" | "HIGH" | "CRITICAL"

    Optional enrichment:
        file_path, file_hash, process_pid, process_name, process_parent, extra

    Returns a flat dict ready for json.dumps().
    Raises nothing — all errors are swallowed to never block the calling thread.
    """
    try:
        now_utc = datetime.now(timezone.utc)
        host    = _get_host_info()
        cats    = ECS_CATEGORY_MAP.get(event_type, {"category": ["process"], "type": ["info"]})
        mitre   = MITRE_MAPPING.get(event_type, {})

        # ── Base structure ────────────────────────────────────────────────
        event: Dict[str, Any] = {
            "@timestamp": now_utc.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",

            # ECS: event
            "event": {
                "kind":     "alert" if severity in ("HIGH", "CRITICAL") else "event",
                "category": cats["category"],
                "type":     cats["type"],
                "action":   event_type,
                "severity": SEVERITY_NUMERIC.get(severity, 1),
                "outcome":  "unknown",
                "timezone": "UTC",
            },

            # ECS: message (top-level, required by ECS)
            "message": message,

            # ECS: host
            "host": {
                "hostname": host["hostname"],
                "id":       host["machine_id"],
                "os": {
                    "name":    host["os_name"],
                    "version": host["os_version"],
                },
            },

            # ECS: agent (the FMSecure sensor)
            "agent": {
                "name":    "FMSecure",
                "version": host["agent_version"],
                "type":    "endpoint",
            },

            # Custom FMSecure namespace (ECS allows custom fields under product namespace)
            "fmsecure": {
                "severity_label": severity,
                "event_type":     event_type,
            },
        }

        # ── File fields ───────────────────────────────────────────────────
        if file_path:
            file_field: Dict[str, Any] = {
                "path": file_path,
                "name": os.path.basename(file_path),
            }
            if file_hash:
                file_field["hash"] = {"sha256": file_hash}
            try:
                file_field["directory"] = os.path.dirname(file_path)
                _, ext = os.path.splitext(file_path)
                if ext:
                    file_field["extension"] = ext.lstrip(".")
            except Exception:
                pass
            event["file"] = file_field

        # ── Process fields ────────────────────────────────────────────────
        if process_name or process_pid:
            proc: Dict[str, Any] = {}
            if process_pid:
                proc["pid"] = process_pid
            if process_name:
                proc["name"] = process_name
                proc["executable"] = process_name
            if process_parent:
                proc["parent"] = {"name": process_parent}
            event["process"] = proc

        # ── MITRE ATT&CK fields ───────────────────────────────────────────
        if mitre:
            event["threat"] = {
                "framework": "MITRE ATT&CK",
                "technique": {
                    "id":   mitre["technique_id"],
                    "name": mitre["technique_name"],
                },
                "tactic": {
                    "id":   mitre.get("tactic_id", ""),
                    "name": mitre.get("tactic_name", ""),
                },
            }

        # ── Rule field (maps to Sigma rule name pattern) ──────────────────
        event["rule"] = {
            "name":     event_type,
            "category": "FMSecure Detection",
        }

        # ── Extra / arbitrary fields under fmsecure namespace ────────────
        if extra and isinstance(extra, dict):
            event["fmsecure"].update(extra)

        return event

    except Exception as exc:
        # Fallback: minimal valid event so we never drop an event entirely
        return {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "message":    message,
            "event": {
                "kind": "event",
                "action": event_type,
                "severity": SEVERITY_NUMERIC.get(severity, 1),
            },
            "fmsecure": {
                "severity_label": severity,
                "event_type":     event_type,
                "schema_error":   str(exc),
            },
        }


# ── Telemetry log writer ───────────────────────────────────────────────────────

# Thread lock so concurrent log writes don't interleave partial JSON lines
_TELEMETRY_LOCK = threading.Lock()


def emit_telemetry_event(
    message:       str,
    event_type:    str,
    severity:      str,
    file_path:     Optional[str] = None,
    file_hash:     Optional[str] = None,
    process_pid:   Optional[int] = None,
    process_name:  Optional[str] = None,
    process_parent: Optional[str] = None,
    extra:         Optional[Dict] = None,
) -> None:
    """
    Build an ECS event and append it as a single JSON line to telemetry.jsonl.

    telemetry.jsonl is:
      • NOT encrypted — it contains only metadata, no raw file content
      • One JSON object per line (JSONL / NDJSON format)
      • Directly ingestable by Splunk (HEC file monitor), Elastic Filebeat,
        Fluentd, Logstash, Microsoft Sentinel, or any syslog forwarder
      • Rotated at the same time as integrity_log.dat (handled separately)

    This function NEVER raises — it is called inside integrity_core hot paths.
    """
    try:
        event = build_ecs_event(
            message=message,
            event_type=event_type,
            severity=severity,
            file_path=file_path,
            file_hash=file_hash,
            process_pid=process_pid,
            process_name=process_name,
            process_parent=process_parent,
            extra=extra,
        )
        line = json.dumps(event, separators=(",", ":"), ensure_ascii=False)

        # Resolve telemetry log path from the same data root as integrity_log.dat
        try:
            from core.utils import get_app_data_dir
            _log_dir = os.path.join(get_app_data_dir(), "logs")
        except Exception:
            _log_dir = os.path.join(
                os.getenv("APPDATA", os.path.expanduser("~")),
                "FMSecure", "logs"
            )

        telemetry_path = os.path.join(_log_dir, "telemetry.jsonl")
        os.makedirs(_log_dir, exist_ok=True)

        with _TELEMETRY_LOCK:
            with open(telemetry_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    except Exception:
        pass   # Never block the calling thread — telemetry is best-effort


# ── Syslog / CEF emitter (SIEM integration) ───────────────────────────────────

def emit_syslog_cef(
    message:    str,
    event_type: str,
    severity:   str,
    file_path:  Optional[str] = None,
) -> None:
    """
    Emit a CEF (Common Event Format) syslog message to a configured syslog server.

    CEF is the universal SIEM input format — accepted by Splunk, QRadar, Sentinel,
    ArcSight, and Wazuh without any custom parsing.

    CEF format:
        CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension

    Configured via config.json:
        "syslog_host": "192.168.1.100"   (your SIEM collector IP)
        "syslog_port": 514               (UDP syslog standard port)
        "syslog_enabled": true

    If syslog_host is not configured this function is a no-op.
    """
    try:
        from core.integrity_core import CONFIG
        if not CONFIG.get("syslog_enabled", False):
            return
        syslog_host = CONFIG.get("syslog_host", "")
        syslog_port = int(CONFIG.get("syslog_port", 514))
        if not syslog_host:
            return

        host      = _get_host_info()
        sev_cef   = {"INFO": 3, "MEDIUM": 5, "HIGH": 8, "CRITICAL": 10}.get(severity, 3)
        sig_id    = event_type.replace(" ", "_").upper()
        name      = event_type.replace("_", " ").title()
        extension = (
            f"src={host['hostname']} "
            f"msg={message.replace('|', '%7C')[:200]} "
            f"fname={file_path or 'N/A'} "
            f"cs1={severity} "
            f"cs1Label=FMSecureSeverity "
            f"cs2={host['machine_id']} "
            f"cs2Label=MachineID"
        )
        cef_line  = (
            f"CEF:0|FMSecure|FMSecure EDR|{host['agent_version']}|"
            f"{sig_id}|{name}|{sev_cef}|{extension}"
        )

        # RFC 5424 syslog header
        priority  = (1 * 8) + 6  # facility=user(1), severity=informational(6)
        ts        = datetime.now().strftime("%b %d %H:%M:%S")
        syslog_msg = f"<{priority}>{ts} {host['hostname']} FMSecure: {cef_line}"

        import socket as _socket
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.sendto(syslog_msg.encode("utf-8"), (syslog_host, syslog_port))
        sock.close()

    except Exception:
        pass   # Never block calling thread


# ── Convenience: build and return raw dict (for REST API / tenant push) ────────

def get_structured_event(
    message:    str,
    event_type: str,
    severity:   str,
    **kwargs,
) -> Dict:
    """
    Return a fully built ECS event dict without writing to any file.
    Used by the C2 server push (tenant_manager.push_alert) and REST API.
    """
    return build_ecs_event(
        message=message,
        event_type=event_type,
        severity=severity,
        **kwargs,
    )


# ── Telemetry log rotation ────────────────────────────────────────────────────

def rotate_telemetry_if_needed(max_mb: float = 50.0) -> None:
    """
    Rotate telemetry.jsonl when it exceeds max_mb.
    Called from integrity_core.rotate_logs_if_needed().
    Keeps the last 3 rotated files.
    """
    try:
        from core.utils import get_app_data_dir
        _log_dir = os.path.join(get_app_data_dir(), "logs")
        path = os.path.join(_log_dir, "telemetry.jsonl")
        if not os.path.exists(path):
            return
        if os.path.getsize(path) < max_mb * 1024 * 1024:
            return
        ts   = datetime.now().strftime("%Y%m%d%H%M%S")
        dest = os.path.join(_log_dir, f"telemetry_{ts}.jsonl")
        os.replace(path, dest)
        # Keep only last 3 rotated files
        archives = sorted([
            f for f in os.listdir(_log_dir)
            if f.startswith("telemetry_") and f.endswith(".jsonl")
        ])
        for old in archives[:-3]:
            try:
                os.remove(os.path.join(_log_dir, old))
            except Exception:
                pass
    except Exception:
        pass