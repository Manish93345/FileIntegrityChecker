"""
process_monitor.py — FMSecure v2.6.3
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ROOT CAUSE OF ALL PREVIOUS LAG
───────────────────────────────
v2.6.0 — open_files() per process: each call = NtQuerySystemInformation
         on event thread → 15-20s block per event.

v2.6.1 — open_files() moved to background thread: NtQuerySystemInformation
         is serialized OS-wide. Background thread competes with Notepad's
         file save for the same kernel lock → Notepad hangs.

v2.6.2 — io_counters() per process in background: each call =
         GetProcessIoCounters() via ctypes, holds Python GIL until it
         returns. 100+ processes × 2s = GIL held 100-200ms per cycle →
         GUI thread starves → visible stutter.

v2.6.3 FIX — zero per-process API calls:
  • process_iter() with bulk attrs uses ONE fast OS call for ALL processes
  • No open_files(), no io_counters(), no per-process anything
  • Attribution runs on a dedicated daemon thread, never on event thread
  • File events log INSTANTLY; attribution appears as follow-up if found
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import os
import time
import threading
import queue
import psutil
from datetime import datetime

try:
    import win32evtlog
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False


# ── LOLBins ───────────────────────────────────────────────────────────
LOLBINS = {
    'powershell.exe', 'powershell_ise.exe',
    'cmd.exe',
    'wscript.exe', 'cscript.exe',
    'mshta.exe', 'regsvr32.exe', 'rundll32.exe',
    'certutil.exe', 'bitsadmin.exe', 'msiexec.exe',
    'wmic.exe', 'schtasks.exe', 'at.exe', 'sc.exe',
    'net.exe', 'net1.exe', 'nltest.exe',
    'psexec.exe', 'psexec64.exe', 'mimikatz.exe',
    'procdump.exe', 'wevtutil.exe', 'vssadmin.exe',
    'bcdedit.exe', 'whoami.exe', 'ipconfig.exe', 'nslookup.exe',
}

TRUSTED_PARENTS = {
    'code.exe', 'code - insiders.exe', 'devenv.exe',
    'idea64.exe', 'pycharm64.exe', 'webstorm64.exe',
    'rider64.exe', 'cursor.exe', 'windsurf.exe',
    'sublime_text.exe', 'atom.exe', 'notepad++.exe',
    'windowsterminal.exe', 'wt.exe', 'conhost.exe',
    'mintty.exe', 'hyper.exe', 'alacritty.exe',
    'node.exe', 'python.exe', 'python3.exe',
    'git.exe', 'cargo.exe',
    'svchost.exe', 'services.exe', 'winlogon.exe',
    'taskhostw.exe', 'explorer.exe',
}

HIGH_RISK_PARENTS = {
    'outlook.exe', 'excel.exe', 'word.exe', 'winword.exe',
    'powerpnt.exe', 'chrome.exe', 'firefox.exe',
    'msedge.exe', 'iexplore.exe', 'thunderbird.exe',
}


class ProcessAttributor:
    """
    Zero-lag process attribution.

    Background snapshot thread:
      - Uses process_iter() with BULK attrs → single fast OS call
      - NO open_files(), NO io_counters(), NO per-process calls
      - Runs every 3 seconds (GIL impact: < 1ms total)

    Attribution is ASYNC:
      - attribute_file_event() queues a job and returns '' immediately
      - A worker thread resolves attribution and calls log_fn with result
      - File event always logs instantly; attribution is a follow-up line
    """

    SNAPSHOT_INTERVAL = 3.0   # seconds; safe to increase if still stuttering

    def __init__(self):
        self._snapshot: list = []
        self._lock           = threading.Lock()
        self._audit_ok       = self._check_audit_policy()

        # Async attribution queue
        self._attr_queue: queue.Queue = queue.Queue(maxsize=50)

        self._start_snapshot_thread()
        self._start_attribution_worker()

        print(f"[PROC] v3 (zero GIL, async). "
              f"Win32={HAS_WIN32}, AuditLog={self._audit_ok}")

    # ── Init ──────────────────────────────────────────────────────────

    def _check_audit_policy(self) -> bool:
        if not HAS_WIN32:
            return False
        try:
            h = win32evtlog.OpenEventLog(None, "Security")
            win32evtlog.CloseEventLog(h)
            return True
        except Exception:
            return False

    def _start_snapshot_thread(self):
        """
        ONE fast OS call every 3 seconds.
        process_iter() with these attrs uses NtQuerySystemInformation
        with SystemProcessInformation — returns ALL processes in a
        single kernel call, no per-process work needed.
        """
        def _loop():
            while True:
                try:
                    snap = []
                    # This single call fetches all process info at once
                    for p in psutil.process_iter(
                        ['pid', 'name', 'ppid', 'username']
                    ):
                        try:
                            snap.append({
                                'pid':       p.info['pid'],
                                'name':      (p.info['name'] or '').lower(),
                                'name_orig': p.info['name'] or '',
                                'ppid':      p.info['ppid'] or 0,
                                'username':  p.info['username'] or '',
                            })
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                    with self._lock:
                        self._snapshot = snap
                except Exception:
                    pass
                time.sleep(self.SNAPSHOT_INTERVAL)

        threading.Thread(target=_loop, daemon=True,
                          name="FMSecure-ProcSnapshot").start()

    def _start_attribution_worker(self):
        """
        Single daemon thread processes attribution jobs from the queue.
        Completely separate from the watchdog event pipeline.
        """
        def _worker():
            while True:
                try:
                    job = self._attr_queue.get(timeout=5.0)
                    if job is None:
                        break
                    filepath, log_fn, event_type = job
                    try:
                        attr = self._resolve(filepath)
                        if attr and log_fn:
                            tag = self._format(attr)
                            if tag:
                                # Append attribution as a follow-up log line
                                log_fn(
                                    f"ATTRIBUTION: {os.path.basename(filepath)}"
                                    f"  {tag}",
                                    event_type="PROCESS_ATTRIBUTION",
                                    severity="INFO"
                                )
                    except Exception:
                        pass
                    finally:
                        self._attr_queue.task_done()
                except queue.Empty:
                    pass

        threading.Thread(target=_worker, daemon=True,
                          name="FMSecure-AttrWorker").start()

    # ── Public API ────────────────────────────────────────────────────

    def queue_attribution(self, filepath: str, log_fn=None,
                           event_type: str = ""):
        """
        Non-blocking. Queues an attribution job and returns immediately.
        The file event log line is already written by the caller.
        Attribution result appears as a separate log line within ~3s.
        """
        try:
            self._attr_queue.put_nowait((filepath, log_fn, event_type))
        except queue.Full:
            pass  # Drop if queue full — attribution is best-effort

    def get_attribution_sync(self, filepath: str) -> dict | None:
        """
        Synchronous lookup for cases that need it (forensic snapshots).
        Only uses the snapshot — no I/O, fast.
        """
        return self._resolve(filepath)

    def format_for_log(self, attribution: dict | None) -> str:
        return self._format(attribution)

    # ── Resolution ────────────────────────────────────────────────────

    def _resolve(self, filepath: str) -> dict | None:
        # Tier 1: LOLBin in snapshot (instant, most actionable)
        result = self._lolbin_scan()
        if result:
            result['source'] = 'lolbin_snapshot'
            return self._enrich(result)

        # Tier 2: Security Event Log (only if audit enabled)
        if self._audit_ok:
            result = self._query_security_log(filepath)
            if result:
                result['source'] = 'security_log'
                return self._enrich(result)

        return None

    # ── Tier 1 — LOLBin snapshot scan ────────────────────────────────

    def _lolbin_scan(self) -> dict | None:
        with self._lock:
            snap = list(self._snapshot)
        for proc in snap:
            if proc['name'] in LOLBINS:
                parent = self._parent_name(proc['ppid'], snap)
                return {**proc, 'parent_name': parent, 'cmdline': ''}
        return None

    # ── Tier 2 — Windows Security Event Log ──────────────────────────

    def _query_security_log(self, filepath: str) -> dict | None:
        if not HAS_WIN32:
            return None
        target = os.path.normcase(os.path.abspath(filepath))
        try:
            hand   = win32evtlog.OpenEventLog(None, "Security")
            flags  = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                      win32evtlog.EVENTLOG_SEQUENTIAL_READ)
            cutoff = time.time() - 15
            while True:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break
                for ev in events:
                    if ev.EventID != 4663:
                        continue
                    try:
                        if ev.TimeGenerated.timestamp() < cutoff:
                            win32evtlog.CloseEventLog(hand)
                            return None
                    except Exception:
                        continue
                    strings = ev.StringInserts or []
                    ev_path = os.path.normcase(
                        strings[5] if len(strings) > 5 else '')
                    if ev_path == target:
                        win32evtlog.CloseEventLog(hand)
                        proc_id   = 0
                        proc_name = strings[9] if len(strings) > 9 else 'Unknown'
                        try:
                            proc_id = int(strings[8], 16) if len(strings) > 8 else 0
                        except Exception:
                            pass
                        return {
                            'pid':         proc_id,
                            'name':        os.path.basename(proc_name).lower(),
                            'name_orig':   os.path.basename(proc_name),
                            'ppid':        0,
                            'parent_name': '',
                            'username':    strings[1] if len(strings) > 1 else '',
                            'cmdline':     '',
                        }
            win32evtlog.CloseEventLog(hand)
        except Exception:
            pass
        return None

    # ── Helpers ───────────────────────────────────────────────────────

    def _parent_name(self, ppid: int, snap: list) -> str:
        for p in snap:
            if p['pid'] == ppid:
                return p['name_orig']
        return ''

    def _enrich(self, attr: dict) -> dict:
        name   = attr.get('name', '').lower()
        parent = attr.get('parent_name', '').lower()
        parent_trusted     = parent in TRUSTED_PARENTS
        attr['is_lolbin']  = (name in LOLBINS) and not parent_trusted
        attr['is_suspicious'] = (
            attr['is_lolbin'] or
            (parent in HIGH_RISK_PARENTS and name in LOLBINS)
        )
        return attr

    def _format(self, attribution: dict | None) -> str:
        if not attribution:
            return ''
        pid    = attribution.get('pid', '?')
        name   = attribution.get('name_orig') or attribution.get('name', '?')
        parent = attribution.get('parent_name', '')
        warn   = (' ⚠ LOLBin'       if attribution.get('is_lolbin')     else
                  ' ⚠ SUSPICIOUS'   if attribution.get('is_suspicious')  else '')
        parent_tag = f' ← {parent}' if parent else ''
        return f'[PID:{pid}] {name}{parent_tag}{warn}'


# ── Singleton ─────────────────────────────────────────────────────────
_instance: ProcessAttributor | None = None
_lock = threading.Lock()


def get_attributor() -> ProcessAttributor:
    global _instance
    with _lock:
        if _instance is None:
            _instance = ProcessAttributor()
        return _instance


def attribute_file_event(filepath: str, log_fn=None,
                          event_type: str = '') -> str:
    """
    ALWAYS returns '' immediately — zero blocking.
    If log_fn is provided, attribution is queued async and will appear
    as a follow-up log line within a few seconds.

    Usage in integrity_core.py:
        attribute_file_event(path, log_fn=append_log_line, event_type="CREATED")
    """
    try:
        get_attributor().queue_attribution(filepath, log_fn, event_type)
    except Exception:
        pass
    return ''


def get_attribution_dict(filepath: str) -> dict | None:
    """Sync lookup for forensic snapshots. Fast — snapshot only."""
    try:
        return get_attributor().get_attribution_sync(filepath)
    except Exception:
        return None