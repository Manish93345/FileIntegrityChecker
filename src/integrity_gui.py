#!/usr/bin/env python3
"""
integrity_gui.py — Upgraded GUI for FileIntegrityChecker
Features:
- Dashboard: total files, created/modified/deleted counts (approx)
- Tamper indicators: records & logs (green/red)
- Start / Stop monitor, Run verification, Verify signatures
- Settings dialog to edit config.json (watch_folder, interval, webhook, secret_key)
- Test webhook button (if webhook configured and send function available)
- Live tail of integrity_log.txt
- Dark/Light theme toggle
- Icons on buttons
- PDF report export with signatures and charts
- Real-time report generation on file changes
- Slide-in alert panel for security events
- Color-coded alerts for different event types
- Professional security-oriented UI
- Report Data Normalization
- Bar Chart Generator (matplotlib)
- Export logs as PDF option
"""

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox, simpledialog
import threading
import time
import os
import json
import traceback
from datetime import datetime
import tempfile
import subprocess
import sys

# Import Auth for password changing
try:
    from auth_manager import auth
except ImportError:
    auth = None

from pathlib import Path
import re

# Severity mapping for GUI
SEVERITY_COLORS = {
    "INFO": "#0dcaf0",      # Blue/Cyan
    "MEDIUM": "#ffc107",    # Yellow
    "HIGH": "#fd7e14",      # Orange
    "CRITICAL": "#dc3545",  # Red
}

SEVERITY_EMOJIS = {
    "INFO": "🟢",
    "MEDIUM": "🟡",
    "HIGH": "🟠",
    "CRITICAL": "🔴",
}



# Mock backend classes if import fails
class MockFileIntegrityMonitor:
    def __init__(self):
        self.records = {}
        self.running = False
        
    def start_monitoring(self, watch_folder=None):
        print(f"Mock: Starting monitoring for {watch_folder}")
        self.running = True
        return True
        
    def stop_monitoring(self):
        print("Mock: Stopping monitoring")
        self.running = False
        
    def run_verification(self, watch_folder=None):
        print(f"Mock: Running verification for {watch_folder}")
        return {
            'total_monitored': 42,
            'created': ['file1.txt', 'file2.pdf'],
            'modified': ['config.json'],
            'deleted': ['temp.txt'],
            'skipped': [],
            'tampered_records': False,
            'tampered_logs': False
        }

# Try import from your backend
try:
    from integrity_core import (
        load_config,
        FileIntegrityMonitor,
        CONFIG,
        LOG_FILE,
        REPORT_SUMMARY_FILE,
        HASH_RECORD_FILE,
        HASH_SIGNATURE_FILE,
        LOG_SIG_FILE,
        verify_records_signature_on_disk,
        verify_log_signatures,
        send_webhook_safe,
    )
    BACKEND_AVAILABLE = True
    print("Backend imported successfully")
except Exception as e:
    # graceful fallback if import fails
    print("Failed to import integrity_core:", e)
    print("Using mock backend for demonstration")
    
    # Create mock objects
    FileIntegrityMonitor = MockFileIntegrityMonitor
    CONFIG = {
        "watch_folder": "",
        "verify_interval": 1800,
        "webhook_url": None
    }
    LOG_FILE = "integrity_log.txt"
    REPORT_SUMMARY_FILE = "report_summary.txt"
    REPORT_DATA_JSON = "report_data.json"
    HASH_RECORD_FILE = "hash_records.json"
    HASH_SIGNATURE_FILE = "hash_records.sig"
    LOG_SIG_FILE = "integrity_log.sig"
    
    # Mock functions
    def load_config(config_file=None):
        print(f"Mock: Loading config from {config_file}")
        return CONFIG
        
    def verify_records_signature_on_disk():
        print("Mock: Verifying records signature")
        return True
        
    def verify_log_signatures():
        print("Mock: Verifying log signatures")
        return True, "Log verification successful"
        
    def send_webhook_safe(event_type, message, data):
        print(f"Mock: Sending webhook - {event_type}: {message}")
        return True
        
    BACKEND_AVAILABLE = False

# Try to import charting libraries
try:
    import matplotlib
    matplotlib.use('Agg')  # Use non-interactive backend
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("Matplotlib not available - charts disabled")

# Try to import PDF libraries
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.pdfgen import canvas
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False
    print("ReportLab not available - PDF export disabled")

# Import Pillow for image handling
try:
    from PIL import Image as PILImage
    HAS_PIL = True
except ImportError:
    HAS_PIL = False
    print("Pillow not available - image handling disabled")


class ProIntegrityGUI:
    def __init__(self, root, user_role='admin', username='admin'):
        self.root = root
        self.user_role = user_role  # Store the role
        self.username = username    # Store the username
        # Update title to show who is logged in
        self.root.title(f"🛡️ File Integrity Monitor — [{username.upper()} MODE]")

        self.root.title("🛡️ File Integrity Checker — Professional Security Monitor")
        self.root.geometry("1200x850")
        self.root.minsize(1000, 700)

        # Theme management
        self.dark_mode = False
        
        # Professional security color schemes
        self.light_theme = {
            'bg': '#f8f9fa',
            'fg': '#212529',
            'accent': '#0d6efd',
            'secondary_bg': '#ffffff',
            'frame_bg': '#e9ecef',
            'text_bg': '#ffffff',
            'text_fg': '#212529',
            'button_bg': '#e9ecef',
            'button_fg': '#212529',
            'button_active': '#0d6efd',
            'hover_bg': '#dee2e6',
            'entry_bg': '#ffffff',
            'entry_fg': '#212529',
            'entry_border': '#ced4da',
            'indicator_ok': '#198754',
            'indicator_tamper': '#dc3545',
            'indicator_unknown': '#6c757d',
            'log_bg': '#ffffff',
            'log_fg': '#212529',
            'tab_bg': '#ffffff',
            'tab_fg': '#212529',
            'tab_selected': '#0d6efd',
            'panel_bg': '#ffffff',
            'panel_fg': '#212529',
            'border': '#dee2e6',
            'success': '#198754',
            'warning': '#ffc107',
            'danger': '#dc3545',
            'info': '#0dcaf0',
            'chart_bg': '#ffffff',
            'chart_grid': '#e0e0e0',
            'chart_text': '#212529'
        }
        
        self.dark_theme = {
            'bg': '#121212',
            'fg': '#e9ecef',
            'accent': '#0d6efd',
            'secondary_bg': '#1e1e1e',
            'frame_bg': '#2d2d2d',
            'text_bg': '#1e1e1e',
            'text_fg': '#e9ecef',
            'button_bg': '#2d2d2d',
            'button_fg': '#e9ecef',
            'button_active': '#0d6efd',
            'hover_bg': '#3d3d3d',
            'entry_bg': '#2d2d2d',
            'entry_fg': '#e9ecef',
            'entry_border': '#495057',
            'indicator_ok': '#198754',
            'indicator_tamper': '#dc3545',
            'indicator_unknown': '#6c757d',
            'log_bg': '#1e1e1e',
            'log_fg': '#e9ecef',
            'tab_bg': '#2d2d2d',
            'tab_fg': '#e9ecef',
            'tab_selected': '#0d6efd',
            'panel_bg': '#1e1e1e',
            'panel_fg': '#e9ecef',
            'border': '#495057',
            'success': '#198754',
            'warning': '#ffc107',
            'danger': '#dc3545',
            'info': '#0dcaf0',
            'chart_bg': '#1e1e1e',
            'chart_grid': '#404040',
            'chart_text': '#e9ecef'
        }
        
        self.colors = self.light_theme
        
        # Alert panel configuration
        self.ALERT_PANEL_WIDTH = 400
        self.ALERT_ANIM_STEP = 25
        self.ALERT_ANIM_DELAY = 10
        self.ALERT_SHOW_MS = 4500
        self.alert_visible = False
        self.alert_current_x = 0
        self.alert_hide_after_id = None
        
        # Report tracking
        self.report_data = {
            'total': 0,
            'created': [],
            'modified': [],
            'deleted': [],
            'skipped': [],
            'tampered_records': False,
            'tampered_logs': False,
            'last_update': None
        }
        
        # Chart configuration
        self.chart_colors = {
            'created': '#28a745',  # Green
            'modified': '#ffc107',  # Yellow
            'deleted': '#dc3545',   # Red
            'total': '#0d6efd'      # Blue
        }

        # Configure styles
        self.style = ttk.Style()
        self._configure_styles()

        # Load icons
        self.icons = self._load_icons()


        # Severity counters
        self.severity_counters = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'INFO': 0
        }

         # UI variables for severity counters
        self.critical_var = tk.StringVar(value="0")
        self.high_var = tk.StringVar(value="0")
        self.medium_var = tk.StringVar(value="0")
        self.info_var = tk.StringVar(value="0")

        # Ensure config is loaded
        cfg_ok = True
        try:
            if load_config:
                load_config(None)  # load default config.json if present
            else:
                cfg_ok = False
        except Exception as e:
            print(f"Config load warning: {e}")
            cfg_ok = False

        if not cfg_ok:
            messagebox.showwarning("Config", "Failed to load config.json — defaults will be used.")

        # Backend monitor
        self.monitor = FileIntegrityMonitor() if FileIntegrityMonitor else None
        self.monitor_thread = None
        self.monitor_running = False

        # UI variables
        self.watch_folder_var = tk.StringVar(value=os.path.abspath(CONFIG.get("watch_folder", os.getcwd())))
        self.status_var = tk.StringVar(value="🔴 Stopped")
        self.total_files_var = tk.StringVar(value="0")
        self.created_var = tk.StringVar(value="0")
        self.modified_var = tk.StringVar(value="0")
        self.deleted_var = tk.StringVar(value="0")
        self.tamper_records_var = tk.StringVar(value="UNKNOWN")
        self.tamper_logs_var = tk.StringVar(value="UNKNOWN")
        self.webhook_var = tk.StringVar(value=str(CONFIG.get("webhook_url", "")))

        # Initialize file tracking
        self.file_tracking = {
            'last_total': 0,
            'session_created': 0,
            'session_modified': 0,
            'session_deleted': 0,
            'current_files': set()
        }

        # Build UI
        self._build_widgets()
        self._apply_permissions()
        
        # Create alert panel (initially hidden)
        self._create_alert_panel()

        # Start background update loops
        self._update_dashboard()
        self._update_severity_counters()
        self._tail_log_loop()


    def _update_severity_counters(self):
        """Update severity counters from file"""
        try:
            counter_file = "severity_counters.json"
            if os.path.exists(counter_file):
                with open(counter_file, "r", encoding="utf-8") as f:
                    self.severity_counters = json.load(f)
                    
                # Update UI variables
                self.critical_var.set(str(self.severity_counters.get('CRITICAL', 0)))
                self.high_var.set(str(self.severity_counters.get('HIGH', 0)))
                self.medium_var.set(str(self.severity_counters.get('MEDIUM', 0)))
                self.info_var.set(str(self.severity_counters.get('INFO', 0)))
                
        except Exception as e:
            print(f"Error updating severity counters: {e}")
        
        # Schedule next update
        self.root.after(5000, self._update_severity_counters)


    def _configure_styles(self):
        """Configure ttk styles for the current theme"""
        try:
            self.style.theme_use('clam')
        except:
            pass
        
        # Configure base styles
        self.style.configure('.', 
                           background=self.colors['bg'],
                           foreground=self.colors['fg'],
                           font=('Segoe UI', 10))
        
        self.style.configure('TFrame', background=self.colors['bg'])
        self.style.configure('TLabel', 
                           background=self.colors['bg'],
                           foreground=self.colors['fg'],
                           font=('Segoe UI', 10))
        
        self.style.configure('TButton',
                           background=self.colors['button_bg'],
                           foreground=self.colors['button_fg'],
                           borderwidth=1,
                           relief='raised',
                           font=('Segoe UI', 10, 'normal'),
                           padding=8)
        
        self.style.map('TButton',
                      background=[('active', self.colors['hover_bg']),
                                 ('pressed', self.colors['button_active'])],
                      foreground=[('active', self.colors['button_fg']),
                                 ('pressed', '#ffffff')])
        
        self.style.configure('TEntry',
                           fieldbackground=self.colors['entry_bg'],
                           foreground=self.colors['entry_fg'],
                           borderwidth=1,
                           insertcolor=self.colors['entry_fg'])
        
        self.style.configure('TLabelframe',
                           background=self.colors['bg'],
                           foreground=self.colors['fg'],
                           bordercolor=self.colors['border'],
                           relief='solid',
                           borderwidth=1)
        
        self.style.configure('TLabelframe.Label',
                           background=self.colors['bg'],
                           foreground=self.colors['fg'],
                           font=('Segoe UI', 10, 'bold'))

    def _load_icons(self):
        """Load icons from assets folder"""
        icons = {}
        # Create simple colored icons using text symbols
        icon_symbols = {
            'start': '▶️',
            'stop': '⏹️',
            'verify': '🔍',
            'settings': '⚙️',
            'log': '📋',
            'report': '📊',
            'folder': '📁',
            'theme': '🌙',
            'alert': '🔔',
            'security': '🛡️',
            'chart': '📈',
            'export': '📤',
            'logout': '🚪'
        }
        for key, symbol in icon_symbols.items():
            icons[key] = symbol
        return icons

    def toggle_theme(self):
        """Toggle between light and dark themes"""
        self.dark_mode = not self.dark_mode
        self.colors = self.dark_theme if self.dark_mode else self.light_theme
        self._apply_theme()

    def _apply_permissions(self):
        """Disable controls based on user role"""
        if self.user_role == 'admin':
            return # Full access
            
        # Role is 'user' (Read-Only)
        self._append_log(f"Logged in as restricted viewer: {self.username}")
        self.status_var.set("🔒 Read-Only Mode")
        
        # 1. Disable Folder Entry
        self.folder_entry.configure(state='disabled')
        
        # 2. Define Restricted Actions (Text that appears on buttons)
        # Added "Open Folder" and "Browse" to this list
        restricted_actions = [
            "Start Monitor", 
            "Stop Monitor", 
            "Settings", 
            "Verify Now",
            "Open Folder",  # <--- Specifically requested
            "Browse"        # <--- Prevent changing folder via browse
        ]
        
        # 3. Recursively find and disable buttons
        self._disable_recursive(self.root, restricted_actions)

    def _disable_recursive(self, widget, restricted_list):
        """Helper to find buttons recursively"""
        for child in widget.winfo_children():
            # If it's a button (tk or ttk), check its text
            if isinstance(child, (tk.Button, ttk.Button)):
                try:
                    btn_text = child.cget('text')
                    # Check if any restricted keyword is in the button text
                    for action in restricted_list:
                        if action in btn_text:
                            child.configure(state='disabled')
                except:
                    pass
            
            # Recurse into children (Frames, LabelFrames, etc.)
            self._disable_recursive(child, restricted_list)
        
    def _check_and_disable(self, btn, restricted_list):
        """Helper to check button text and disable if restricted"""
        try:
            btn_text = btn.cget('text')
            for action in restricted_list:
                if action in btn_text:
                    btn.configure(state='disabled')
        except:
            pass

    def _apply_theme(self):
        """Apply current theme to all widgets"""
        try:
            # Reconfigure styles with new colors
            self._configure_styles()
            
            # Apply to root window
            self.root.configure(bg=self.colors['bg'])
            
            # Apply to specific widgets
            self._update_specific_widgets()
            
            # Update theme button text
            if hasattr(self, 'theme_btn'):
                self.theme_btn.configure(text="☀️" if self.dark_mode else "🌙",
                                       bg=self.colors['button_bg'],
                                       fg=self.colors['button_fg'])
            
        except Exception as e:
            print(f"Error applying theme (non-critical): {e}")

    def _update_specific_widgets(self):
        """Update specific widgets that support theme changes"""
        # Update log box
        if hasattr(self, 'log_box'):
            try:
                self.log_box.configure(bg=self.colors['log_bg'], fg=self.colors['log_fg'],
                                     insertbackground=self.colors['log_fg'])
            except:
                pass

    def _build_widgets(self):
        """Build the main UI with professional security layout"""
        # Configure root window
        self.root.configure(bg=self.colors['bg'])
        
        # Main container with padding
        main_container = ttk.Frame(self.root, padding="10")
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Header Section
        header_frame = ttk.Frame(main_container)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Title with security icon
        title_frame = ttk.Frame(header_frame)
        title_frame.pack(side=tk.LEFT)
        
        security_icon = self.icons.get('security', '🛡️')
        self.title_label = tk.Label(title_frame, text=f"{security_icon} FILE INTEGRITY SECURITY MONITOR", 
                             font=('Segoe UI', 16, 'bold'), 
                             bg=self.colors['bg'], fg=self.colors['accent'])
        self.title_label.pack(side=tk.LEFT)
        
        self.subtitle_label = tk.Label(title_frame, text="Professional File Integrity & Tamper Detection System", 
                                font=('Segoe UI', 10), 
                                bg=self.colors['bg'], fg=self.colors['fg'])
        self.subtitle_label.pack(side=tk.LEFT, padx=(10, 0))


        
        # --- NEW: HEADER BUTTONS (Theme + Change Pass) ---
        right_header_frame = ttk.Frame(header_frame)
        right_header_frame.pack(side=tk.RIGHT)
        
        # Only show "Change Password" button if user is Admin
        if self.user_role == 'admin':
            self.pass_btn = tk.Button(right_header_frame, text="🔑 Change Password", 
                                    command=self.change_admin_password,
                                    font=('Segoe UI', 9), bg=self.colors['accent'], 
                                    fg='white', bd=0, padx=10, pady=2)
            self.pass_btn.pack(side=tk.LEFT, padx=(0, 10))

        # Logout Button
            self.logout_btn = tk.Button(right_header_frame, text="🚪 Logout", 
                                    command=self.logout,
                                    font=('Segoe UI', 9), bg='#dc3545', # Red Color
                                    fg='white', bd=0, padx=10, pady=2)
            self.logout_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.theme_btn = tk.Button(right_header_frame, text="🌙", command=self.toggle_theme, 
                                 font=('Segoe UI', 12), bg=self.colors['button_bg'], 
                                 fg=self.colors['button_fg'], bd=0, padx=10)
        self.theme_btn.pack(side=tk.LEFT)


        
        # Control Panel Section
        control_frame = ttk.LabelFrame(main_container, text="CONTROL PANEL", padding="15")
        control_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Folder selection row
        folder_frame = ttk.Frame(control_frame)
        folder_frame.pack(fill=tk.X, pady=(0, 10))
        
        folder_label = ttk.Label(folder_frame, text="🔒 Monitor Folder:", font=('Segoe UI', 10, 'bold'))
        folder_label.pack(side=tk.LEFT, padx=(0, 10))
        
        self.folder_entry = ttk.Entry(folder_frame, width=70, font=('Segoe UI', 10))
        self.folder_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.folder_entry.insert(0, self.watch_folder_var.get())
        
        browse_icon = self.icons.get('folder', '📁')
        browse_btn = ttk.Button(folder_frame, text=f"{browse_icon} Browse", 
                               command=self._browse, width=12)
        browse_btn.pack(side=tk.LEFT)
        
        # Status bar
        status_frame = ttk.Frame(control_frame)
        status_frame.pack(fill=tk.X, pady=(5, 10))
        
        status_label = ttk.Label(status_frame, text="System Status:", font=('Segoe UI', 10, 'bold'))
        status_label.pack(side=tk.LEFT)
        
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var, 
                                     font=('Segoe UI', 10, 'bold'), foreground=self.colors['accent'])
        self.status_label.pack(side=tk.LEFT, padx=(10, 20))
        
        # Action Buttons Row
        action_frame = ttk.Frame(control_frame)
        action_frame.pack(fill=tk.X)
        
        # Create button grid with icons
        buttons_config = [
            ("▶️ Start Monitor", self.start_monitor, ""),
            ("⏹️ Stop Monitor", self.stop_monitor, ""),
            ("🔍 Verify Now", self.run_verification, ""),
            ("🔒 Check Signatures", self.verify_signatures, ""),
            ("⚙️ Settings", self.open_settings, ""),
            ("🔄 Reset Counters", self.reset_severity_counters, ""),
        ]
        
        for i, (text, command, icon_key) in enumerate(buttons_config):
            icon = self.icons.get(icon_key, '')
            btn = ttk.Button(action_frame, text=f"{icon} {text}", command=command, width=18)
            btn.grid(row=0, column=i, padx=5, pady=5)
        
        # Report Buttons Row
        report_frame = ttk.Frame(control_frame)
        report_frame.pack(fill=tk.X, pady=(5, 0))
        
        report_buttons = []
        if HAS_REPORTLAB:
            report_buttons.append(("📄 Export Report PDF", self.export_report_pdf, ""))
            report_buttons.append(("📋 Export Logs PDF", self.export_logs_pdf, ""))
        
        if HAS_MATPLOTLIB:
            report_buttons.append(("📈 Generate Chart", self.generate_chart, ""))
        
        report_buttons.append(("📊 View Reports", self.view_report, ""))
        report_buttons.append(("📁 Open Folder", self.open_reports_folder, ""))

        if hasattr(self, 'action_frame'):
            reset_btn = ttk.Button(self.action_frame, text="🔄 Reset Counters", 
                                 command=self.reset_severity_counters, width=18)
            reset_btn.grid(row=0, column=5, padx=5, pady=5)  # Adjust column as needed
        
        for i, (text, command, icon_key) in enumerate(report_buttons):
            icon = self.icons.get(icon_key, '')
            btn = ttk.Button(report_frame, text=f"{icon} {text}", command=command, width=18)
            btn.grid(row=0, column=i, padx=5, pady=5)
        
        # Dashboard Section
        dashboard_frame = ttk.LabelFrame(main_container, text="SECURITY DASHBOARD", padding="15")
        dashboard_frame.pack(fill=tk.X, pady=(0, 15))

        # Create three columns for dashboard instead of two
        left_dashboard = ttk.Frame(dashboard_frame)
        left_dashboard.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 20))
        
        center_dashboard = ttk.Frame(dashboard_frame)
        center_dashboard.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 20))
        
        right_dashboard = ttk.Frame(dashboard_frame)
        right_dashboard.pack(side=tk.RIGHT, fill=tk.BOTH)
        
        # File Statistics (in left_dashboard - unchanged)
        stats_frame = ttk.LabelFrame(left_dashboard, text="📊 FILE STATISTICS", padding="10")
        stats_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create two columns for dashboard
        left_dashboard = ttk.Frame(dashboard_frame)
        left_dashboard.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 20))
        
        right_dashboard = ttk.Frame(dashboard_frame)
        right_dashboard.pack(side=tk.RIGHT, fill=tk.BOTH)
        
        # File Statistics
        stats_frame = ttk.LabelFrame(left_dashboard, text="📊 FILE STATISTICS", padding="10")
        stats_frame.pack(fill=tk.BOTH, expand=True)
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill=tk.BOTH, expand=True)
        
        # Configure grid
        for i in range(4):
            stats_grid.rowconfigure(i, weight=1)
        stats_grid.columnconfigure(0, weight=1)
        stats_grid.columnconfigure(1, weight=2)


        # NEW: Severity Dashboard (in center_dashboard)
        severity_frame = ttk.LabelFrame(center_dashboard, text="🚨 SECURITY ALERT COUNTERS", padding="10")
        severity_frame.pack(fill=tk.BOTH, expand=True)
        
        severity_grid = ttk.Frame(severity_frame)
        severity_grid.pack(fill=tk.BOTH, expand=True)
        
        # Configure grid for severity
        for i in range(4):
            severity_grid.rowconfigure(i, weight=1)
        severity_grid.columnconfigure(0, weight=1)
        severity_grid.columnconfigure(1, weight=2)
        
        severity_data = [
            ("🔴 CRITICAL Alerts:", self.critical_var, SEVERITY_COLORS["CRITICAL"]),
            ("🟠 HIGH Alerts:", self.high_var, SEVERITY_COLORS["HIGH"]),
            ("🟡 MEDIUM Alerts:", self.medium_var, SEVERITY_COLORS["MEDIUM"]),
            ("🟢 INFO Alerts:", self.info_var, SEVERITY_COLORS["INFO"])
        ]
        
        for row, (label, var, color) in enumerate(severity_data):
            label_widget = ttk.Label(severity_grid, text=label, font=('Segoe UI', 10, 'bold'))
            label_widget.grid(row=row, column=0, sticky="w", pady=8, padx=(0, 20))
            
            value_widget = tk.Label(severity_grid, textvariable=var, font=('Segoe UI', 14, 'bold'),
                                  bg=self.colors['secondary_bg'], fg='white',
                                  relief="solid", borderwidth=1, width=12, anchor="center")
            value_widget.configure(bg=color)
            value_widget.grid(row=row, column=1, sticky="ew", pady=8)
            
            # Store reference for theme updates
            setattr(self, f'severity_label_{row}', value_widget)
        
        # Security Status (in right_dashboard - unchanged)
        security_frame = ttk.LabelFrame(right_dashboard, text="🛡️ SECURITY STATUS", padding="10")
        security_frame.pack(fill=tk.BOTH, expand=True)
        
        stats_data = [
            ("Total Monitored Files:", self.total_files_var, "#0d6efd"),
            ("🟢 Created (Session):", self.created_var, "#198754"),
            ("🟡 Modified (Session):", self.modified_var, "#ffc107"),
            ("🔴 Deleted (Session):", self.deleted_var, "#dc3545")
        ]
        
        for row, (label, var, color) in enumerate(stats_data):
            label_widget = ttk.Label(stats_grid, text=label, font=('Segoe UI', 10))
            label_widget.grid(row=row, column=0, sticky="w", pady=8, padx=(0, 20))
            
            value_widget = tk.Label(stats_grid, textvariable=var, font=('Segoe UI', 12, 'bold'),
                                  bg=self.colors['secondary_bg'], fg=color,
                                  relief="solid", borderwidth=1, width=15, anchor="center")
            value_widget.grid(row=row, column=1, sticky="ew", pady=8)
            setattr(self, f'value_label_{row}', value_widget)
        
        # Security Status
        security_frame = ttk.LabelFrame(right_dashboard, text="🛡️ SECURITY STATUS", padding="10")
        security_frame.pack(fill=tk.BOTH, expand=True)
        
        security_grid = ttk.Frame(security_frame)
        security_grid.pack(fill=tk.BOTH, expand=True)
        
        # Security indicators
        security_data = [
            ("Hash Records Integrity:", self.tamper_records_var, "Hash database signature verification"),
            ("Log Files Integrity:", self.tamper_logs_var, "Audit log cryptographic integrity")
        ]
        
        for row, (label, var, tooltip) in enumerate(security_data):
            label_frame = tk.Frame(security_grid, bg=self.colors['bg'])
            label_frame.grid(row=row, column=0, sticky="w", pady=12)
            
            tk.Label(label_frame, text=label, font=('Segoe UI', 10), 
                    bg=self.colors['bg'], fg=self.colors['fg']).pack(side=tk.LEFT)
            
            # Indicator with colored background
            indicator = tk.Label(label_frame, textvariable=var, font=('Segoe UI', 10, 'bold'),
                               relief="solid", borderwidth=1, width=15, anchor="center")
            indicator.pack(side=tk.LEFT, padx=(10, 5))
            
            # Store reference for theme updates
            if row == 0:
                self._rec_indicator = indicator
            else:
                self._log_indicator = indicator
        
        # Live Monitoring Section
        monitor_frame = ttk.LabelFrame(main_container, text="📈 LIVE MONITORING & ALERTS", padding="10")
        monitor_frame.pack(fill=tk.BOTH, expand=True)
        
        # Log display
        log_label = ttk.Label(monitor_frame, text="🔍 Live Security Log:", font=('Segoe UI', 10, 'bold'))
        log_label.pack(anchor="w", pady=(0, 5))
        
        self.log_box = scrolledtext.ScrolledText(monitor_frame, wrap=tk.WORD, height=12,
                                               font=("Consolas", 9),
                                               bg=self.colors['log_bg'], 
                                               fg=self.colors['log_fg'],
                                               insertbackground=self.colors['log_fg'])
        self.log_box.pack(fill=tk.BOTH, expand=True)
        self.log_box.configure(state="disabled")
        
        # Footer
        footer_frame = ttk.Frame(main_container)
        footer_frame.pack(fill=tk.X, pady=(10, 0))
        
        footer_text = "🔐 Secure File Integrity Monitor v2.0 | Real-time Tamper Detection | Cryptographic Verification"
        footer_label = ttk.Label(footer_frame, text=footer_text, font=('Segoe UI', 9),
                               foreground=self.colors['indicator_unknown'])
        footer_label.pack()
        
        # Apply initial theme
        self._apply_theme()

    

    def logout(self):
        """Logout and restart application"""
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            # Stop monitor if running
            if self.monitor_running:
                try:
                    self.monitor.stop_monitoring()
                except: pass
            
            # Destroy current window
            self.root.destroy()
            
            # Restart login_gui.py
            try:
                # We restart the python process pointing to login_gui.py
                # This assumes login_gui.py is in the current directory
                subprocess.Popen([sys.executable, "login_gui.py"])
            except Exception as e:
                print(f"Failed to restart login: {e}")

    # ---------- Report Data Normalization (FIXED) ----------
    def normalize_report_data(self, summary=None):
        """
        Convert summary data to structured dictionary with JSON persistence
        """
        # 1. If summary is provided (e.g., from immediate verification run), use it
        if summary:
            pass # continue to normalization
        
        # 2. If no summary provided, check if we have data in memory
        elif self.report_data.get('total', 0) > 0:
            return self.report_data
            
        # 3. If memory is empty, try to load from the JSON cache (Most Reliable)
        else:
            if os.path.exists(REPORT_DATA_JSON):
                try:
                    with open(REPORT_DATA_JSON, 'r') as f:
                        self.report_data = json.load(f)
                    return self.report_data
                except Exception as e:
                    print(f"Error loading report cache: {e}")

            # 4. Last resort: Try to parse the text file
            summary = self._parse_summary_from_file()
        
        # Normalize the data structure
        normalized = {
            'total': summary.get('total_monitored', 0),
            'created': summary.get('created', []),
            'modified': summary.get('modified', []),
            'deleted': summary.get('deleted', []),
            'skipped': summary.get('skipped', []),
            'tampered_records': summary.get('tampered_records', False),
            'tampered_logs': summary.get('tampered_logs', False),
            'last_update': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Save to JSON cache for future chart generation
        try:
            with open(REPORT_DATA_JSON, 'w') as f:
                json.dump(normalized, f, indent=4)
        except Exception as e:
            print(f"Failed to save report cache: {e}")

        # Update internal report data
        self.report_data = normalized
        return normalized
    
    def _parse_summary_from_file(self):
        """Fallback text parser if JSON is missing"""
        if not os.path.exists(REPORT_SUMMARY_FILE):
            return {}
        
        try:
            with open(REPORT_SUMMARY_FILE, 'r', encoding='utf-8') as f:
                content = f.read()
            
            summary = {}
            lines = content.split('\n')
            
            # Helper to extract lists from text lines
            def extract_files(prefix):
                files = []
                for line in lines:
                    if line.strip().startswith(prefix):
                        parts = line.split(':', 1)
                        if len(parts) > 1:
                            # Handle comma separated
                            raw_files = parts[1].split(',')
                            files = [f.strip() for f in raw_files if f.strip()]
                return files

            summary['created'] = extract_files('Created:')
            summary['modified'] = extract_files('Modified:')
            summary['deleted'] = extract_files('Deleted:')
            
            # Extract total count
            import re
            total_match = re.search(r'Total files monitored:\s*(\d+)', content)
            if total_match:
                summary['total_monitored'] = int(total_match.group(1))
            
            return summary
        except Exception as e:
            print(f"Error parsing summary file: {e}")
            return {}

    # ---------- Bar Chart Generator ----------
    def generate_bar_chart(self, data=None, save_path=None, show_chart=True):
        """
        Generate bar chart for created/modified/deleted counts
        
        Args:
            data: Normalized report data dictionary
            save_path: Path to save chart image (PNG)
            show_chart: Whether to display chart in GUI
        
        Returns:
            Path to saved image or None
        """
        if not HAS_MATPLOTLIB:
            messagebox.showwarning("Chart Generation", 
                                 "Matplotlib not installed. Install with: pip install matplotlib")
            return None
        
        if data is None:
            data = self.report_data
        
        # Prepare data for chart
        categories = ['Created', 'Modified', 'Deleted']
        counts = [
            len(data.get('created', [])),
            len(data.get('modified', [])),
            len(data.get('deleted', []))
        ]
        
        # Set up the figure with theme compatibility
        plt.style.use('dark_background' if self.dark_mode else 'default')
        fig, ax = plt.subplots(figsize=(8, 5))
        
        # Set colors based on theme
        bg_color = self.colors['chart_bg']
        text_color = self.colors['chart_text']
        grid_color = self.colors['chart_grid']
        
        fig.patch.set_facecolor(bg_color)
        ax.set_facecolor(bg_color)
        
        # Create bar chart
        bars = ax.bar(categories, counts, color=[
            self.chart_colors['created'],
            self.chart_colors['modified'],
            self.chart_colors['deleted']
        ], edgecolor='white', linewidth=1.5)
        
        # Add value labels on top of bars
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                   f'{int(height)}', ha='center', va='bottom',
                   color=text_color, fontweight='bold')
        
        # Customize chart
        ax.set_title('File Integrity Changes', fontsize=14, fontweight='bold', color=text_color, pad=20)
        ax.set_xlabel('Change Type', fontsize=12, color=text_color)
        ax.set_ylabel('Number of Files', fontsize=12, color=text_color)
        ax.grid(True, alpha=0.3, color=grid_color, linestyle='--')
        ax.set_axisbelow(True)
        
        # Set tick colors
        ax.tick_params(colors=text_color, which='both')
        
        # Add total files info
        total_files = data.get('total', 0)
        ax.text(0.02, 0.98, f'Total Monitored Files: {total_files}',
                transform=ax.transAxes, fontsize=10, color=text_color,
                verticalalignment='top', bbox=dict(boxstyle='round', facecolor=bg_color, alpha=0.8))
        
        plt.tight_layout()
        
        # Save chart if requested
        if save_path:
            try:
                plt.savefig(save_path, dpi=300, bbox_inches='tight', facecolor=bg_color)
                print(f"Chart saved to: {save_path}")
            except Exception as e:
                print(f"Error saving chart: {e}")
                save_path = None
        
        # Show chart in GUI if requested
        if show_chart:
            self._show_chart_in_gui(fig)
        
        if not show_chart:
            plt.close(fig)
            #return save_path
    
    def _show_chart_in_gui(self, fig):
        """Display chart in a separate window"""
        chart_window = tk.Toplevel(self.root)
        chart_window.title("📈 File Integrity Chart")
        chart_window.geometry("800x600")
        
        # Embed matplotlib figure in Tkinter window
        canvas = FigureCanvasTkAgg(fig, master=chart_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Add save button
        save_btn = ttk.Button(chart_window, text="💾 Save Chart",
                             command=lambda: self._save_chart_dialog(fig))
        save_btn.pack(pady=10)
        
        # Add close button
        close_btn = ttk.Button(chart_window, text="Close", command=chart_window.destroy)
        close_btn.pack(pady=5)

        
    
    def _save_chart_dialog(self, fig):
        """Save chart to file dialog"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG files", "*.png"), ("PDF files", "*.pdf"), ("All files", "*.*")],
            initialfile=f"integrity_chart_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        )
        if filename:
            try:
                fig.savefig(filename, dpi=300, bbox_inches='tight',
                          facecolor=self.colors['chart_bg'])
                messagebox.showinfo("Save Successful", f"Chart saved to:\n{filename}")
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save chart: {e}")

    def generate_chart(self):
        """Generate and display chart from current data"""
        if not HAS_MATPLOTLIB:
            messagebox.showwarning("Chart Generation", 
                                 "Matplotlib not installed. Install with: pip install matplotlib")
            return
        
        # FIX: Ensure we fetch data intelligently
        # If we have valid data in memory, use it. Otherwise load from disk.
        if self.report_data.get('total', 0) > 0:
            data = self.report_data
        else:
            data = self.normalize_report_data() # Will try to load JSON cache
        
        # Check if we actually have data to show
        has_data = (len(data.get('created', [])) > 0 or 
                   len(data.get('modified', [])) > 0 or 
                   len(data.get('deleted', [])) > 0)
        
        if not has_data and data.get('total', 0) == 0:
            messagebox.showinfo("No Data", "No report data found to chart.\nPlease run 'Verify Now' first.")
            return

        # Generate chart
        self.generate_bar_chart(data, show_chart=True)

    # ---------- PDF Report Generator ----------
    def export_report_pdf(self):
        """Export comprehensive PDF report with chart"""
        if not HAS_REPORTLAB:
            messagebox.showwarning("PDF Export", 
                                 "ReportLab not installed. Install with: pip install reportlab")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")],
            initialfile=f"integrity_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        )
        
        if not filename:
            return
        
        def _generate_report():
            try:
                self._append_log("Generating comprehensive PDF report...")
                
                # Normalize data
                data = self.normalize_report_data()

                # Get severity counters
                severity_summary = self.severity_counters
                
                # Generate chart image
                chart_path = None
                if HAS_MATPLOTLIB:
                    temp_dir = tempfile.gettempdir()
                    chart_path = os.path.join(temp_dir, f"chart_{datetime.now().strftime('%Y%m%d%H%M%S')}.png")
                    self.generate_bar_chart(data, save_path=chart_path, show_chart=False)
                
                # Create PDF document
                doc = SimpleDocTemplate(filename, pagesize=A4, topMargin=0.5*inch)
                styles = getSampleStyleSheet()
                
                # Custom styles
                title_style = ParagraphStyle(
                    'CustomTitle',
                    parent=styles['Heading1'],
                    fontSize=18,
                    spaceAfter=20,
                    textColor=colors.HexColor('#0d6efd')
                )
                
                heading_style = ParagraphStyle(
                    'CustomHeading',
                    parent=styles['Heading2'],
                    fontSize=14,
                    spaceAfter=12,
                    textColor=colors.HexColor('#0d6efd')
                )
                
                subheading_style = ParagraphStyle(
                    'CustomSubHeading',
                    parent=styles['Heading3'],
                    fontSize=12,
                    spaceAfter=8,
                    textColor=colors.HexColor('#495057')
                )
                
                normal_style = ParagraphStyle(
                    'CustomNormal',
                    parent=styles['Normal'],
                    fontSize=10,
                    spaceAfter=6
                )
                
                # Content collection
                story = []
                
                # Title Section
                story.append(Paragraph("SECURITY INTEGRITY MONITOR REPORT", title_style))
                story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
                story.append(Spacer(1, 20))

                # NEW: Security Severity Summary
                story.append(Paragraph("🚨 SECURITY SEVERITY SUMMARY", heading_style))

                severity_data = [
                    ["Severity Level", "Count", "Description"],
                    ["🔴 CRITICAL", str(severity_summary.get('CRITICAL', 0)), "Hash/Log tampering, major breaches"],
                    ["🟠 HIGH", str(severity_summary.get('HIGH', 0)), "Config changes, multiple deletes"],
                    ["🟡 MEDIUM", str(severity_summary.get('MEDIUM', 0)), "File modifications, deletions"],
                    ["🟢 INFO", str(severity_summary.get('INFO', 0)), "Normal file operations, system events"]
                ]

                severity_table = Table(severity_data, colWidths=[1.5*inch, 1*inch, 3*inch])
                severity_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0d6efd')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dee2e6')),
                    ('PADDING', (0, 0), (-1, -1), 8),
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BACKGROUND', (0, 1), (0, 1), colors.HexColor('#dc3545')),  # CRITICAL
                    ('BACKGROUND', (0, 2), (0, 2), colors.HexColor('#fd7e14')),  # HIGH
                    ('BACKGROUND', (0, 3), (0, 3), colors.HexColor('#ffc107')),  # MEDIUM
                    ('BACKGROUND', (0, 4), (0, 4), colors.HexColor('#0dcaf0')),  # INFO
                    ('TEXTCOLOR', (0, 1), (0, 4), colors.white),
                ]))
                story.append(severity_table)
                story.append(Spacer(1, 20))
                
                # Executive Summary
                story.append(Paragraph("EXECUTIVE SUMMARY", heading_style))
                
                summary_data = [
                    ["Total Files Monitored:", str(data['total'])],
                    ["New Files Created:", str(len(data['created']))],
                    ["Files Modified:", str(len(data['modified']))],
                    ["Files Deleted:", str(len(data['deleted']))],
                    ["Files Skipped:", str(len(data['skipped']))],
                    ["Records Integrity:", "✓ VERIFIED" if not data['tampered_records'] else "✗ COMPROMISED"],
                    ["Logs Integrity:", "✓ VERIFIED" if not data['tampered_logs'] else "✗ COMPROMISED"]
                ]
                
                summary_table = Table(summary_data, colWidths=[2.5*inch, 1.5*inch])
                summary_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e9ecef')),
                    ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dee2e6')),
                    ('PADDING', (0, 0), (-1, -1), 8),
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                ]))
                story.append(summary_table)
                story.append(Spacer(1, 30))
                
                # Chart Section
                if chart_path and os.path.exists(chart_path):
                    story.append(Paragraph("FILE ACTIVITY CHART", heading_style))
                    try:
                        chart_img = Image(chart_path, width=6*inch, height=3*inch)
                        story.append(chart_img)
                        story.append(Spacer(1, 20))
                    except Exception as e:
                        print(f"Error adding chart to PDF: {e}")
                        story.append(Paragraph("Chart generation failed", normal_style))
                
                # File Lists Section
                story.append(Paragraph("DETAILED FILE CHANGES", heading_style))
                
                # Created Files
                if data['created']:
                    story.append(Paragraph("Newly Created Files:", subheading_style))
                    created_list = data['created'][:20]  # Top 20
                    for file in created_list:
                        story.append(Paragraph(f"• {file}", normal_style))
                    if len(data['created']) > 20:
                        story.append(Paragraph(f"... and {len(data['created']) - 20} more files", normal_style))
                    story.append(Spacer(1, 10))
                
                # Modified Files
                if data['modified']:
                    story.append(Paragraph("Modified Files:", subheading_style))
                    modified_list = data['modified'][:20]  # Top 20
                    for file in modified_list:
                        story.append(Paragraph(f"• {file}", normal_style))
                    if len(data['modified']) > 20:
                        story.append(Paragraph(f"... and {len(data['modified']) - 20} more files", normal_style))
                    story.append(Spacer(1, 10))
                
                # Deleted Files
                if data['deleted']:
                    story.append(Paragraph("Deleted Files:", subheading_style))
                    deleted_list = data['deleted'][:20]  # Top 20
                    for file in deleted_list:
                        story.append(Paragraph(f"• {file}", normal_style))
                    if len(data['deleted']) > 20:
                        story.append(Paragraph(f"... and {len(data['deleted']) - 20} more files", normal_style))
                
                # Security Status
                story.append(Spacer(1, 20))
                story.append(Paragraph("SECURITY STATUS", heading_style))
                
                security_status = [
                    ["Component", "Status", "Details"],
                    ["Hash Records", 
                     "SECURE" if not data['tampered_records'] else "COMPROMISED",
                     "Cryptographically signed and verified" if not data['tampered_records'] else "Signature mismatch detected"],
                    ["Audit Logs",
                     "SECURE" if not data['tampered_logs'] else "COMPROMISED",
                     "Line-by-line HMAC verification passed" if not data['tampered_logs'] else "Log tampering detected"]
                ]
                
                security_table = Table(security_status, colWidths=[1.5*inch, 1.5*inch, 3*inch])
                security_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0d6efd')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dee2e6')),
                    ('PADDING', (0, 0), (-1, -1), 8),
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BACKGROUND', (1, 1), (1, 2), 
                     colors.HexColor('#28a745') if not data['tampered_records'] else colors.HexColor('#dc3545')),
                    ('BACKGROUND', (1, 2), (1, 2), 
                     colors.HexColor('#28a745') if not data['tampered_logs'] else colors.HexColor('#dc3545')),
                    ('TEXTCOLOR', (1, 1), (1, 2), colors.white),
                ]))
                story.append(security_table)
                story.append(Spacer(1, 30))
                
                # Footer
                story.append(Paragraph("Report generated by Secure File Integrity Monitor", normal_style))
                story.append(Paragraph("https://github.com/Manish93345/FileIntegrityChecker.git", normal_style))
                
                # Build PDF
                doc.build(story)
                
                # Clean up temp chart file
                if chart_path and os.path.exists(chart_path):
                    try:
                        os.remove(chart_path)
                    except:
                        pass
                
                self._append_log(f"Comprehensive PDF report exported: {filename}")
                
                # Show success message with option to open folder
                self.root.after(0, lambda: self._show_export_success(filename))
                
            except Exception as e:
                self._append_log(f"PDF report generation failed: {e}")
                traceback.print_exc()
                self.root.after(0, lambda: messagebox.showerror("Export Error", 
                                                               f"Failed to generate PDF report:\n{str(e)}"))
        
        # Run in separate thread
        threading.Thread(target=_generate_report, daemon=True).start()
    
    def export_logs_pdf(self):
        """Export logs as PDF"""
        if not HAS_REPORTLAB:
            messagebox.showwarning("PDF Export", 
                                 "ReportLab not installed. Install with: pip install reportlab")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")],
            initialfile=f"integrity_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        )
        
        if not filename:
            return
        
        def _generate_logs_pdf():
            try:
                self._append_log("Generating logs PDF...")
                
                # Create PDF document
                doc = SimpleDocTemplate(filename, pagesize=A4, topMargin=0.5*inch)
                styles = getSampleStyleSheet()
                
                # Custom styles
                title_style = ParagraphStyle(
                    'CustomTitle',
                    parent=styles['Heading1'],
                    fontSize=16,
                    spaceAfter=20,
                    textColor=colors.HexColor('#0d6efd')
                )
                
                timestamp_style = ParagraphStyle(
                    'TimestampStyle',
                    parent=styles['Normal'],
                    fontSize=9,
                    textColor=colors.grey,
                    spaceAfter=3
                )
                
                log_style = ParagraphStyle(
                    'LogStyle',
                    parent=styles['Code'],
                    fontSize=8,
                    fontName='Courier',
                    spaceAfter=4,
                    leftIndent=10
                )
                
                # Content collection
                story = []
                
                # Title Section
                story.append(Paragraph("SECURITY AUDIT LOGS", title_style))
                story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
                                      styles['Normal']))
                story.append(Paragraph(f"Log File: {os.path.abspath(LOG_FILE)}", styles['Normal']))
                story.append(Spacer(1, 20))
                
                # Read log file
                if os.path.exists(LOG_FILE):
                    try:
                        with open(LOG_FILE, 'r', encoding='utf-8') as f:
                            log_lines = f.readlines()[-1000:]  # Last 1000 lines
                        
                        # Add log entries
                        for line in log_lines:
                            line = line.strip()
                            if line:
                                # Try to extract timestamp
                                if ' - ' in line:
                                    timestamp, message = line.split(' - ', 1)
                                    story.append(Paragraph(timestamp, timestamp_style))
                                    story.append(Paragraph(message, log_style))
                                else:
                                    story.append(Paragraph(line, log_style))
                        
                        story.append(Spacer(1, 20))
                        story.append(Paragraph(f"Total log entries: {len(log_lines)}", styles['Normal']))
                        
                    except Exception as e:
                        story.append(Paragraph(f"Error reading log file: {str(e)}", styles['Normal']))
                else:
                    story.append(Paragraph("No log file found", styles['Normal']))
                
                # Footer
                story.append(Spacer(1, 30))
                story.append(Paragraph("Generated by Secure File Integrity Monitor", styles['Normal']))
                story.append(Paragraph("Security Audit Log Export", styles['Normal']))
                
                # Build PDF
                doc.build(story)
                
                self._append_log(f"Logs PDF exported: {filename}")
                
                # Show success message
                self.root.after(0, lambda: self._show_export_success(filename))
                
            except Exception as e:
                self._append_log(f"Logs PDF generation failed: {e}")
                traceback.print_exc()
                self.root.after(0, lambda: messagebox.showerror("Export Error", 
                                                               f"Failed to generate logs PDF:\n{str(e)}"))
        
        # Run in separate thread
        threading.Thread(target=_generate_logs_pdf, daemon=True).start()
    
    def _show_export_success(self, filepath):
        """Show export success dialog with option to open folder"""
        result = messagebox.askyesno("Export Successful",
                                    f"Report successfully exported to:\n{filepath}\n\n"
                                    "Would you like to open the containing folder?")
        if result:
            try:
                folder_path = os.path.dirname(filepath)
                os.startfile(folder_path)
            except:
                # Fallback for Linux/Mac
                try:
                    import subprocess
                    subprocess.run(['xdg-open', folder_path])
                except:
                    pass

    # ---------- Alert Panel Functions ----------
    def _create_alert_panel(self):
        """Create slide-in alert panel"""
        try:
            self.root.update_idletasks()
        except Exception:
            pass

        root_w = self.root.winfo_width() or self.root.winfo_screenwidth()
        margin = 20
        start_x = root_w + margin
        y = 50
        height = min(400, self.root.winfo_screenheight() - 120)

        if getattr(self, "_alert_frame", None):
            try:
                self._alert_frame.config(width=self.ALERT_PANEL_WIDTH, height=height)
            except Exception:
                pass
            if not getattr(self, "alert_visible", False):
                self._alert_frame.place(x=start_x, y=y, width=self.ALERT_PANEL_WIDTH, height=height)
                self.alert_current_x = start_x
            return

        # Build frame
        self._alert_frame = tk.Frame(self.root, bg=self.colors.get('panel_bg', '#111'), bd=1, relief="solid")
        self._alert_frame.place(x=start_x, y=y, width=self.ALERT_PANEL_WIDTH, height=height)

        header = tk.Frame(self._alert_frame, bg=self.colors.get('accent','#0d6efd'))
        header.pack(fill=tk.X)
        self._alert_title = tk.Label(header, text="🚨 SECURITY ALERTS", bg=self.colors.get('accent'), fg='white', 
                                    font=('Segoe UI',11,'bold'))
        self._alert_title.pack(side=tk.LEFT, padx=8, pady=6)

        close_btn = tk.Button(header, text="✕", command=self._hide_alert, bg=self.colors.get('accent'), fg='white', bd=0)
        close_btn.pack(side=tk.RIGHT, padx=8, pady=4)

        content = tk.Frame(self._alert_frame, bg=self.colors.get('panel_bg'))
        content.pack(fill=tk.BOTH, expand=True)

        self._alert_msg = scrolledtext.ScrolledText(content, wrap=tk.WORD, state="disabled",
                                                   bg=self.colors.get('panel_bg'),
                                                   fg=self.colors.get('panel_fg'),
                                                   height=12, relief='flat')
        self._alert_msg.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        meta = tk.Frame(content, bg=self.colors.get('panel_bg'))
        meta.pack(fill=tk.X, padx=6, pady=(0,6))
        self._alert_meta = tk.Label(meta, text="No active alerts", bg=self.colors.get('panel_bg'), 
                                   fg=self.colors.get('panel_fg'))
        self._alert_meta.pack(side=tk.LEFT)
        self._alert_counter = tk.Label(meta, text="Alerts: 0", bg=self.colors.get('panel_bg'), 
                                      fg=self.colors.get('panel_fg'))
        self._alert_counter.pack(side=tk.RIGHT)

        # Internal state
        self.alert_count = 0
        self.alert_visible = False
        self.alert_current_x = start_x
        self.alert_hide_after_id = None

    def _show_alert(self, title, message, level="info"):
        """Show alert panel with severity"""
        try:
            if not getattr(self, "_alert_frame", None):
                self._create_alert_panel()
            
            # Map level to severity
            severity_map = {
                "info": "INFO",
                "created": "INFO",
                "modified": "MEDIUM",
                "deleted": "MEDIUM",
                "tampered": "CRITICAL",
                "high": "HIGH",
                "critical": "CRITICAL"
            }
            
            severity = severity_map.get(level, "INFO")
            severity_emoji = SEVERITY_EMOJIS.get(severity, "⚪")
            severity_color = SEVERITY_COLORS.get(severity, "#0dcaf0")
            
            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            entry = f"{severity_emoji} {severity} • {ts}\n{title}\n{message}\n{'-'*36}\n"
            
            # Insert at top with color tag
            self._alert_msg.configure(state="normal")
            
            # Configure tag for this severity
            tag_name = f"severity_{severity}"
            self._alert_msg.tag_config(tag_name, foreground=severity_color, 
                                      font=('Segoe UI', 9, 'bold' if severity == 'CRITICAL' else 'normal'))
            
            # Insert text with tag
            self._alert_msg.insert("1.0", entry, tag_name)
            self._alert_msg.configure(state="disabled")
            
            # Update meta
            self.alert_count = getattr(self, "alert_count", 0) + 1
            self._alert_counter.configure(text=f"Alerts: {self.alert_count}")
            self._alert_meta.configure(text=f"Last: {severity} @ {ts}")
            
            # Update severity counter immediately
            if severity in self.severity_counters:
                self.severity_counters[severity] += 1
                if severity == "CRITICAL":
                    self.critical_var.set(str(self.severity_counters["CRITICAL"]))
                elif severity == "HIGH":
                    self.high_var.set(str(self.severity_counters["HIGH"]))
                elif severity == "MEDIUM":
                    self.medium_var.set(str(self.severity_counters["MEDIUM"]))
                elif severity == "INFO":
                    self.info_var.set(str(self.severity_counters["INFO"]))
            
            # Show alert panel
            self._animate_panel_show()
            
        except Exception as e:
            print("Error showing alert:", e)
            traceback.print_exc()

    def _animate_panel_show(self):
        """Animate panel showing"""
        try:
            root_w = self.root.winfo_width() or self.root.winfo_screenwidth()
            margin = 20
            target_x = max(10, root_w - self.ALERT_PANEL_WIDTH - margin)

            if not self.alert_visible:
                self.alert_visible = True

            # Animate
            self._animate_panel(target_x, slide_in=True)

            # Auto hide after interval
            if self.alert_hide_after_id:
                self.root.after_cancel(self.alert_hide_after_id)
            self.alert_hide_after_id = self.root.after(self.ALERT_SHOW_MS, self._hide_alert)

        except Exception as e:
            print("Error animating panel:", e)

    def _hide_alert(self):
        """Hide alert panel"""
        try:
            if not self.alert_visible:
                return

            if self.alert_hide_after_id:
                self.root.after_cancel(self.alert_hide_after_id)
                self.alert_hide_after_id = None

            root_w = self.root.winfo_width() or self.root.winfo_screenwidth()
            off_x = root_w + 40
            self._animate_panel(off_x, slide_in=False)

        except Exception as e:
            print("Error hiding alert:", e)

    def _animate_panel(self, target_x, slide_in=True):
        """Animate panel movement"""
        try:
            current_x = self._alert_frame.winfo_x()
            
            if slide_in:
                step = -abs(self.ALERT_ANIM_STEP)
                if current_x <= target_x:
                    self._alert_frame.place(x=target_x)
                    self.alert_current_x = target_x
                    return
            else:
                step = abs(self.ALERT_ANIM_STEP)
                if current_x >= target_x:
                    self._alert_frame.place_forget()
                    self.alert_visible = False
                    self.alert_current_x = target_x
                    return

            new_x = current_x + step
            if slide_in and new_x < target_x:
                new_x = target_x
            if (not slide_in) and new_x > target_x:
                new_x = target_x

            self._alert_frame.place(x=new_x)
            self.alert_current_x = new_x
            self.root.after(self.ALERT_ANIM_DELAY, lambda: self._animate_panel(target_x, slide_in=slide_in))

        except Exception as e:
            print("Animation error:", e)


        # --- NEW METHOD: CHANGE PASSWORD ---
    def change_admin_password(self):
        """Allow admin to change their password"""
        if self.user_role != 'admin':
            messagebox.showerror("Permission Denied", "Only administrators can change passwords.")
            return

        if not auth:
            messagebox.showerror("Error", "Authentication backend not loaded.")
            return

        # Simple prompt flow
        new_pass = simpledialog.askstring("Change Password", "Enter new password:", show='•', parent=self.root)
        if not new_pass:
            return # Cancelled
        
        confirm_pass = simpledialog.askstring("Confirm Password", "Confirm new password:", show='•', parent=self.root)
        
        if new_pass != confirm_pass:
            messagebox.showerror("Error", "Passwords do not match!")
            return
            
        if len(new_pass) < 4:
            messagebox.showwarning("Weak Password", "Password must be at least 4 characters.")
            return

        # Call backend to update
        # We assume we are updating the current user's password
        success, msg = auth.update_password(self.username, new_pass)
        
        if success:
            messagebox.showinfo("Success", "Password updated successfully!")
            self._append_log(f"Admin password changed for user: {self.username}")
        else:
            messagebox.showerror("Error", f"Failed to update password: {msg}")

    # ... [KEEP ALL OTHER METHODS FROM PREVIOUS integrity_gui.py] ...
    # (normalize_report_data, generate_bar_chart, _show_chart_in_gui, export_report_pdf, 
    #  _create_alert_panel, _show_alert, start_monitor, stop_monitor, etc...)
    
    # -------------------------------------------------------------
    # FOR COMPLETENESS, COPIED HELPER METHODS REQUIRED FOR RUNNING:
    # -------------------------------------------------------------

    # ---------- Core Actions ----------
    def _browse(self):
        """Browse for folder"""
        d = filedialog.askdirectory()
        if d:
            self.watch_folder_var.set(d)
            self.folder_entry.delete(0, tk.END)
            self.folder_entry.insert(0, d)
            self._append_log(f"Selected monitor folder: {d}")


    

    def start_monitor(self):
        """Start monitoring"""
        if not FileIntegrityMonitor:
            messagebox.showerror("Error", "Backend not available.")
            return
        if self.monitor_running:
            messagebox.showinfo("Info", "Monitor already running.")
            return
        
        folder = self.folder_entry.get()
        if not folder or not os.path.exists(folder):
            messagebox.showerror("Error", "Please select a valid folder.")
            return

        def _start():
            try:
                ok = self.monitor.start_monitoring(watch_folder=folder)
                if ok:
                    self.monitor_running = True
                    self.status_var.set(f"🟢 Running — {os.path.basename(folder)}")
                    self._append_log(f"Security monitoring STARTED for: {folder}")
                    self._show_alert("Monitoring started", 
                                   f"Started monitoring folder:\n{folder}", 
                                   "info")
                    self.reset_session_counts()
                else:
                    self._append_log("Monitor failed to start")
                    messagebox.showerror("Error", "Monitor failed to start.")
            except Exception as ex:
                self._append_log(f"Exception starting monitor: {ex}")
                traceback.print_exc()
                messagebox.showerror("Error", f"Exception: {ex}")

        threading.Thread(target=_start, daemon=True).start()

    def stop_monitor(self):
        """Stop monitoring"""
        if not self.monitor_running:
            messagebox.showinfo("Info", "Monitor not running.")
            return
        try:
            self.monitor.stop_monitoring()
            self.monitor_running = False
            self.status_var.set("🔴 Stopped")
            self._append_log("Security monitoring STOPPED by user.")
            self._show_alert("Monitoring Stopped", 
                           "File integrity monitoring has been stopped.", 
                           "info")
        except Exception as ex:
            self._append_log(f"Exception stopping monitor: {ex}")
            traceback.print_exc()
            messagebox.showerror("Error", f"Exception: {ex}")

    def run_verification(self):
        """Run manual verification with severity tracking"""
        folder = self.folder_entry.get()
        if not folder or not os.path.exists(folder):
            messagebox.showerror("Error", "Choose valid folder first.")
            return

        def _verify():
            try:
                self._append_log("Manual security verification started...")
                
                # Run the backend verification
                summary = self.monitor.run_verification(watch_folder=folder)
                
                # Normalize AND SAVE to JSON cache automatically
                normalized = self.normalize_report_data(summary)
                
                # Track file changes with severity
                self._track_file_changes(normalized)

                # Update UI Status Indicators based on verification results
                rec_status = "TAMPERED" if normalized['tampered_records'] else "OK"
                log_status = "TAMPERED" if normalized['tampered_logs'] else "OK"
                
                # Update the text variables
                self.tamper_records_var.set(rec_status)
                self.tamper_logs_var.set(log_status)
                
                # Show tamper alerts with CRITICAL severity if detected
                if normalized['tampered_records']:
                    self._show_alert("CRITICAL: Hash Database Tampered!", 
                                   "File hash records have been tampered with!", 
                                   "critical")
                if normalized['tampered_logs']:
                    self._show_alert("CRITICAL: Log Files Tampered!", 
                                   "Audit log files have been tampered with!", 
                                   "critical")
                
                # Force the dashboard to refresh colors immediately
                self.root.after(0, self._update_tamper_indicators)
                
                # Show results with severity summary
                txt = (f"🔍 SECURITY VERIFICATION COMPLETE\n\n"
                    f"📊 Total monitored: {normalized['total']}\n"
                    f"🟢 New files: {len(normalized['created'])}\n"
                    f"🟡 Modified files: {len(normalized['modified'])}\n"
                    f"🔴 Deleted files: {len(normalized['deleted'])}\n\n"
                    f"🚨 SECURITY STATUS:\n"
                    f"🔥 CRITICAL - Hash DB: {'TAMPERED' if normalized['tampered_records'] else 'SECURE'}\n"
                    f"🔥 CRITICAL - Logs: {'TAMPERED' if normalized['tampered_logs'] else 'SECURE'}\n")
                
                messagebox.showinfo("Security Verification Summary", txt)
                self._append_log("Manual security verification finished.")
                
            except Exception as ex:
                self._append_log(f"Verification error: {ex}")
                traceback.print_exc()
                messagebox.showerror("Error", f"Verification failed: {ex}")

        threading.Thread(target=_verify, daemon=True).start()

    def verify_signatures(self):
        """Verify cryptographic signatures"""
        rec_ok = None
        log_ok = None
        rec_msg = ""
        log_msg = ""
        
        try:
            if verify_records_signature_on_disk:
                rec_ok = verify_records_signature_on_disk()
                rec_msg = "records HMAC OK" if rec_ok else "records HMAC FAILED"
            else:
                rec_msg = "No verify_records available"
        except Exception as ex:
            rec_ok = False
            rec_msg = f"Exception: {ex}"

        try:
            if verify_log_signatures:
                got = verify_log_signatures()
                if isinstance(got, tuple):
                    log_ok, detail = got
                    log_msg = detail
                elif isinstance(got, bool):
                    log_ok = got
                    log_msg = "log sig OK" if log_ok else "log sig FAILED"
                else:
                    log_msg = str(got)
            else:
                log_msg = "No verify_log available"
        except Exception as ex:
            log_ok = False
            log_msg = f"Exception: {ex}"

        # Update UI indicators
        self.tamper_records_var.set("OK" if rec_ok else "TAMPERED" if rec_ok is False else "UNKNOWN")
        self.tamper_logs_var.set("OK" if log_ok else "TAMPERED" if log_ok is False else "UNKNOWN")
        
        # Show alert for tamper detection
        if rec_ok is False or log_ok is False:
            self._show_alert("SIGNATURE TAMPER DETECTED!", 
                           f"Records: {rec_msg}\nLogs: {log_msg}", 
                           "tampered")
        elif rec_ok and log_ok:
            self._show_alert("Signatures Verified", 
                           "All cryptographic signatures are valid and intact.", 
                           "info")
        
        self._append_log(f"Signature verification: records={rec_msg}, logs={log_msg}")

    def open_settings(self):
        """Open settings dialog"""
        win = tk.Toplevel(self.root)
        win.title("Security Settings")
        win.geometry("520x300")
        win.configure(bg=self.colors['bg'])
        
        tk.Label(win, text="🔧 Security Configuration (config.json)", 
                bg=self.colors['bg'], fg=self.colors['fg'], font=('Segoe UI', 12, 'bold')).pack(anchor="w", padx=10, pady=(10, 0))

        cfg = dict(CONFIG)

        tk.Label(win, text="📁 Watch folder:", bg=self.colors['bg'], fg=self.colors['fg'], font=('Segoe UI', 10)).pack(anchor="w", padx=10, pady=(8, 0))
        watch_var = tk.StringVar(value=cfg.get("watch_folder", ""))
        e1 = ttk.Entry(win, textvariable=watch_var, width=70)
        e1.pack(padx=10)

        tk.Label(win, text="⏱️ Verify interval (seconds):", bg=self.colors['bg'], fg=self.colors['fg'], font=('Segoe UI', 10)).pack(anchor="w", padx=10, pady=(8, 0))
        int_var = tk.StringVar(value=str(cfg.get("verify_interval", 1800)))
        e2 = ttk.Entry(win, textvariable=int_var, width=20)
        e2.pack(padx=10)

        tk.Label(win, text="🔔 Webhook URL (optional):", bg=self.colors['bg'], fg=self.colors['fg'], font=('Segoe UI', 10)).pack(anchor="w", padx=10, pady=(8, 0))
        web_var = tk.StringVar(value=str(cfg.get("webhook_url") or ""))
        e3 = ttk.Entry(win, textvariable=web_var, width=70)
        e3.pack(padx=10)

        def save_settings():
            new_cfg = dict(CONFIG)
            new_cfg["watch_folder"] = watch_var.get()
            try:
                new_cfg["verify_interval"] = int(int_var.get())
            except Exception:
                messagebox.showerror("Error", "verify_interval must be integer seconds")
                return
            new_cfg["webhook_url"] = web_var.get() or None
            try:
                with open("config.json", "w", encoding="utf-8") as f:
                    json.dump(new_cfg, f, indent=4)
                if load_config:
                    load_config("config.json")
                messagebox.showinfo("Settings", "Security configuration saved to config.json")
                self._show_alert("Settings Updated", "Security configuration has been updated.", "info")
                win.destroy()
            except Exception as ex:
                messagebox.showerror("Error", f"Failed to save config: {ex}")

        btn_frame = ttk.Frame(win)
        btn_frame.pack(pady=12)
        
        ttk.Button(btn_frame, text="💾 Save Settings", command=save_settings).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="❌ Cancel", command=win.destroy).pack(side=tk.LEFT, padx=5)

    # ---------- Helper Methods ----------
    def _append_log(self, text):
        """Append text to the log display"""
        try:
            self.log_box.configure(state="normal")
            now = datetime.now().strftime("%H:%M:%S")
            self.log_box.insert(tk.END, f"[{now}] {text}\n")
            self.log_box.configure(state="disabled")
            self.log_box.see(tk.END)
        except Exception as e:
            print(f"Error appending to log: {e}")

    def _update_dashboard(self):
        """Update dashboard with current statistics"""
        try:
            # Update total files
            current_total = 0
            if self.monitor and hasattr(self.monitor, 'records'):
                records = self.monitor.records
                current_total = len(records)
                self.total_files_var.set(str(current_total))
            
            # Update session counts
            self.created_var.set(str(self.file_tracking['session_created']))
            self.modified_var.set(str(self.file_tracking['session_modified']))
            self.deleted_var.set(str(self.file_tracking['session_deleted']))

        except Exception as e:
            print(f"Dashboard update error: {e}")
            self.total_files_var.set("0")
            self.created_var.set("0")
            self.modified_var.set("0")
            self.deleted_var.set("0")

        # Update tamper indicators
        self._update_tamper_indicators()

        # Schedule next update
        self.root.after(3000, self._update_dashboard)

    def _update_tamper_indicators(self):
        """Update tamper indicator colors"""
        if hasattr(self, '_rec_indicator'):
            try:
                rec_ok = self.tamper_records_var.get() == "OK"
                log_ok = self.tamper_logs_var.get() == "OK"
                
                rec_bg = (self.colors['indicator_ok'] if rec_ok else 
                         self.colors['indicator_tamper'] if self.tamper_records_var.get() == "TAMPERED" else 
                         self.colors['indicator_unknown'])
                log_bg = (self.colors['indicator_ok'] if log_ok else 
                         self.colors['indicator_tamper'] if self.tamper_logs_var.get() == "TAMPERED" else 
                         self.colors['indicator_unknown'])
                
                self._rec_indicator.configure(bg=rec_bg, fg='white')
                self._log_indicator.configure(bg=log_bg, fg='white')
            except:
                pass

    def reset_session_counts(self):
        """Reset session counts"""
        self.file_tracking['session_created'] = 0
        self.file_tracking['session_modified'] = 0
        self.file_tracking['session_deleted'] = 0
        
        self.created_var.set("0")
        self.modified_var.set("0")
        self.deleted_var.set("0")
        self._append_log("Session file counters reset")

    def _track_file_changes(self, data):
        """Track file changes"""
        if data:
            created_count = len(data.get('created', []))
            modified_count = len(data.get('modified', []))
            deleted_count = len(data.get('deleted', []))
            
            self.file_tracking['session_created'] += created_count
            self.file_tracking['session_modified'] += modified_count
            self.file_tracking['session_deleted'] += deleted_count
            
            self.created_var.set(str(self.file_tracking['session_created']))
            self.modified_var.set(str(self.file_tracking['session_modified']))
            self.deleted_var.set(str(self.file_tracking['session_deleted']))
            
            # Show alerts for changes
            if created_count > 0:
                self._show_alert(f"{created_count} New Files", 
                               f"{created_count} new file(s) detected.", 
                               "created")
            if modified_count > 0:
                self._show_alert(f"{modified_count} Modified Files", 
                               f"{modified_count} file(s) were modified.", 
                               "modified")
            if deleted_count > 0:
                self._show_alert(f"{deleted_count} Deleted Files", 
                               f"{deleted_count} file(s) were deleted.", 
                               "deleted")

    def _tail_log_loop(self):
        """Tail log file"""
        try:
            if os.path.exists(LOG_FILE):
                try:
                    with open(LOG_FILE, "r", encoding="utf-8") as f:
                        lines = f.readlines()[-400:]
                except Exception:
                    lines = []
                
                existing = self.log_box.get("1.0", tk.END)
                for line in lines:
                    if line.strip() and (line not in existing):
                        self.log_box.configure(state="normal")
                        self.log_box.insert(tk.END, line)
                        self.log_box.configure(state="disabled")
                        self.log_box.see(tk.END)
        except Exception as e:
            print(f"Error in log tail: {e}")
        
        self.root.after(2000, self._tail_log_loop)

    # ---------- Other Methods ----------
    def view_report(self):
        """View reports"""
        report_files = ["report_summary.txt", "activity_reports.txt", "detailed_reports.txt"]
        combined_content = ""

        
        severity_summary = self.severity_counters
        combined_content += f"🚨 SECURITY SEVERITY SUMMARY\n"
        combined_content += f"{'='*60}\n"
        combined_content += f"CRITICAL Alerts: {severity_summary.get('CRITICAL', 0)}\n"
        combined_content += f"HIGH Alerts: {severity_summary.get('HIGH', 0)}\n"
        combined_content += f"MEDIUM Alerts: {severity_summary.get('MEDIUM', 0)}\n"
        combined_content += f"INFO Alerts: {severity_summary.get('INFO', 0)}\n"
        combined_content += f"{'='*60}\n\n"
        
        for report_file in report_files:
            if os.path.exists(report_file):
                try:
                    with open(report_file, "r", encoding="utf-8") as f:
                        content = f.read()
                        combined_content += f"\n{'='*60}\n"
                        combined_content += f"CONTENT FROM: {report_file}\n"
                        combined_content += f"{'='*60}\n\n"
                        combined_content += content + "\n"
                except Exception as ex:
                    combined_content += f"Error reading {report_file}: {ex}\n"
        
        if combined_content:
            self._show_text("Combined Security Reports", combined_content)
        else:
            messagebox.showinfo("Report", "No report files found.")

    #  method to reset severity counters
    def reset_severity_counters(self):
        """Reset all severity counters"""
        if messagebox.askyesno("Reset Counters", "Reset all severity counters to zero?"):
            self.severity_counters = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'INFO': 0}
            
            # Update UI
            self.critical_var.set("0")
            self.high_var.set("0")
            self.medium_var.set("0")
            self.info_var.set("0")
            
            # Save to file
            try:
                with open("severity_counters.json", "w", encoding="utf-8") as f:
                    json.dump(self.severity_counters, f, indent=2)
                self._append_log("Severity counters reset to zero")
                self._show_alert("Counters Reset", "All severity counters have been reset to zero.", "info")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save counters: {e}")

    def open_reports_folder(self):
        """Open reports folder"""
        folder = os.path.abspath(".")
        try:
            os.startfile(folder)
        except Exception:
            messagebox.showinfo("Info", f"Open folder: {folder}")

    def _show_text(self, title, content):
        """Show text in new window"""
        w = tk.Toplevel(self.root)
        w.title(f"🔍 {title}")
        w.geometry("800x600")
        w.configure(bg=self.colors['bg'])
        
        header = tk.Label(w, text=title, font=('Segoe UI', 12, 'bold'),
                        bg=self.colors['bg'], fg=self.colors['accent'])
        header.pack(pady=10)
        
        st = scrolledtext.ScrolledText(w, wrap=tk.WORD, 
                                     bg=self.colors['log_bg'], 
                                     fg=self.colors['log_fg'],
                                     font=("Consolas", 10))
        st.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        st.insert(tk.END, content)
        st.configure(state="disabled")
        
        close_btn = ttk.Button(w, text="Close", command=w.destroy)
        close_btn.pack(pady=10)


# ---------- Run ----------
def main():
    try:
        root = tk.Tk()
        app = ProIntegrityGUI(root, user_role='admin', username='DebugAdmin')
        root.mainloop()
    except Exception as e:
        print(f"Failed to start GUI: {e}")
        traceback.print_exc()
        input("Press Enter to close...")

if __name__ == "__main__":
    main()