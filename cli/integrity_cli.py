#!/usr/bin/env python3
"""
integrity_cli.py
Command Line Interface for Secure File Integrity Monitor
"""

import os
import sys
import argparse
import time

# Get the absolute path of the 'cli' folder
current_dir = os.path.dirname(os.path.abspath(__file__))
# Get the parent directory (the root of LISA_PROJECT)
root_dir = os.path.abspath(os.path.join(current_dir, ".."))
# Safely append the core directory to path
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'core'))

# Add the root directory to sys.path so it can find the 'core' folder
if root_dir not in sys.path:
    sys.path.append(root_dir)

from core.integrity_core import (
    load_config, FileIntegrityMonitor, append_log_line,
    CONFIG, LOG_FILE
)

def cli_callback(event_type, path, severity):
    """Real-time terminal feedback for file events."""
    # Color coding for terminal output
    colors = {
        "INFO": "\033[94m",     # Blue
        "MEDIUM": "\033[93m",   # Yellow
        "HIGH": "\033[91m",     # Red
        "CRITICAL": "\033[1;91m" # Bold Red
    }
    reset = "\033[0m"
    color = colors.get(severity, reset)
    print(f"{color}[{severity}] {event_type} - {path}{reset}")

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
    if not load_config(args.config):
        print("[ERROR] Failed to load configuration.")
        sys.exit(1)

    # Apply CLI overrides
    if args.watch:
        abs_watch = os.path.abspath(args.watch)
        CONFIG["watch_folders"] = [abs_watch]  # v2.0 Array Logic
        CONFIG["watch_folder"] = abs_watch     # Legacy Fallback

    if args.webhook:
        CONFIG["webhook_url"] = args.webhook
    if args.interval:
        CONFIG["verify_interval"] = int(args.interval)

    # Check if watch folders exist
    watch_folders = CONFIG.get("watch_folders", [])
    if not watch_folders and CONFIG.get("watch_folder"):
        watch_folders = [CONFIG["watch_folder"]]

    if not watch_folders or not all(os.path.exists(f) for f in watch_folders):
        print(f"[ERROR] One or more watch folders do not exist: {watch_folders}")
        sys.exit(1)

    # Startup info
    print("========================================")
    print("Secure File Integrity Monitor CLI")
    print(f"Watch folders: {watch_folders}")
    print(f"Verify interval: {CONFIG.get('verify_interval', 60)}s")
    print(f"Webhook: {'enabled' if CONFIG.get('webhook_url') else 'disabled'}")
    print("========================================")

    # Ensure log files exist via proper logging method
    if not os.path.exists(LOG_FILE):
        append_log_line("CLI Monitor started", severity="INFO")

    monitor = FileIntegrityMonitor()

    if args.summary_only:
        print(monitor.get_summary())
        return

    if args.verify:
        print("Running one-shot full verification...")
        summary = monitor.run_verification(watch_folders=watch_folders)
        print("One-shot verification completed.")
        return

    # Start continuous monitoring with real-time callback
    if not monitor.start_monitoring(watch_folders=watch_folders, event_callback=cli_callback):
        print("[ERROR] Failed to start monitoring")
        sys.exit(1)

    print("🟢 Monitor running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Stopping monitor...")
        monitor.stop_monitoring()

if __name__ == "__main__":
    main()