#!/usr/bin/env python3
"""
integrity_cli.py
Command Line Interface for Secure File Integrity Monitor
- Uses integrity_core for all backend logic
- Handles CLI arguments and user interaction
"""

import os
import sys
import argparse
import time
sys.path.append('core')
from core.integrity_core import (
    load_config, FileIntegrityMonitor, 
    verify_all_files_and_update, get_summary,
    CONFIG, now_pretty, atomic_write_text,
    LOG_FILE, LOG_SIG_FILE
)


def main():
    parser = argparse.ArgumentParser(description="Secure File Integrity Monitor CLI")
    parser.add_argument("--config", type=str, help="Path to config.json (optional)")
    parser.add_argument("--watch", type=str, help="Folder to watch (overrides config)")
    parser.add_argument("--verify", action="store_true", help="Run full verification once and exit")
    parser.add_argument("--summary-only", action="store_true", help="Print last summary and exit")
    parser.add_argument("--webhook", type=str, help="Enable webhook URL for this run")
    parser.add_argument("--interval", type=int, help="Periodic verify interval seconds")
    args = parser.parse_args()

    # Load configuration
    config_path = args.config or os.path.join("config", "config.json")
    if not load_config(args.config):
        sys.exit(1)
    
    # Apply CLI overrides
    if args.watch:
        CONFIG["watch_folder"] = os.path.abspath(args.watch)
    if args.webhook:
        CONFIG["webhook_url"] = args.webhook
    if args.interval:
        CONFIG["verify_interval"] = int(args.interval)

    wf = CONFIG["watch_folder"]
    if not os.path.exists(wf):
        print(f"[ERROR] Watch folder does not exist: {wf}")
        sys.exit(1)

    # Startup info
    print("========================================")
    print("Secure File Integrity Monitor CLI")
    print(f"Watch folder: {wf}")
    print(f"Verify interval: {CONFIG['verify_interval']}s")
    print(f"Webhook: {'enabled' if CONFIG.get('webhook_url') else 'disabled'}")
    print("========================================")

    # Ensure log files exist via proper logging method
    from core.integrity_core import append_log_line
    
    if not os.path.exists(LOG_FILE):
        # This will create the file AND the signature correctly
        append_log_line("CLI Monitor started", severity="INFO")

    if args.summary_only:
        monitor = FileIntegrityMonitor()
        print(monitor.get_summary())
        return

    monitor = FileIntegrityMonitor()

    if args.verify:
        print("Running one-shot full verification...")
        summary = monitor.run_verification()
        print("One-shot verification completed.")
        return

    # Start continuous monitoring
    if not monitor.start_monitoring():
        print("Failed to start monitoring")
        sys.exit(1)

    print("Monitor running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping monitor...")
        monitor.stop_monitoring()

if __name__ == "__main__":
    main()