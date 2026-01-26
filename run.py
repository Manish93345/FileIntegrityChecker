#!/usr/bin/env python3
"""
run.py - Main entry point for File Integrity Security Monitor
Usage:
    python run.py              # Launch GUI
    python run.py --cli        # Launch CLI
    python run.py --verify     # Run one-time verification
"""

import os
import sys
import argparse
from pathlib import Path

# Add the core directory to Python path
CORE_DIR = Path(__file__).parent / "core"
sys.path.append(str(CORE_DIR))

def main():
    parser = argparse.ArgumentParser(description="File Integrity Security Monitor")
    parser.add_argument("--cli", action="store_true", help="Run in CLI mode")
    parser.add_argument("--verify", action="store_true", help="Run one-time verification")
    parser.add_argument("--watch", type=str, help="Folder to watch (overrides config)")
    parser.add_argument("--init", action="store_true", help="Initialize severity system")
    parser.add_argument("--gui", action="store_true", help="Launch GUI (default)")
    
    args = parser.parse_args()
    
    if args.init:
        # Initialize severity system
        from core.severity_init import init_severity_counters, create_event_mapping
        init_severity_counters()
        create_event_mapping()
        print("✅ Severity system initialized!")
        return
    
    if args.cli or args.verify:
        # Run CLI mode
        from integrity_cli import main as cli_main
        sys.argv = [sys.argv[0]]
        if args.verify:
            sys.argv.append("--verify")
        if args.watch:
            sys.argv.extend(["--watch", args.watch])
        cli_main()
    else:
        # Run GUI mode (default)
        from gui.login_gui import LoginWindow
        app = LoginWindow()
        app.run()

if __name__ == "__main__":
    main()