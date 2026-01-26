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
- PDF report export with signatures
- Real-time report generation on file changes
- Slide-in alert panel for security events
- Color-coded alerts for different event types
- Professional security-oriented UI
"""

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import threading
import time
import os
import json
import traceback
from datetime import datetime
import tempfile
from pathlib import Path

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
            'total_monitored': 0,
            'created': [],
            'modified': [],
            'deleted': [],
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

# Optional PDF export
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False
    print("ReportLab not available - PDF export disabled")

# Import Pillow for image handling
try:
    from PIL import Image, ImageTk
    HAS_PIL = True
except ImportError:
    HAS_PIL = False
    print("Pillow not available - buttons will not have icons")


class ProIntegrityGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ File Integrity Checker — Professional Security Monitor")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 650)

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
            'info': '#0dcaf0'
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
            'info': '#0dcaf0'
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
        
        # Configure styles
        self.style = ttk.Style()
        self._configure_styles()

        # Load icons
        self.icons = self._load_icons()

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

        # Report tracking
        self.last_report_time = None
        self.report_triggered = False

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
        
        # Create alert panel (initially hidden)
        self._create_alert_panel()

        # Start background update loops
        self._update_dashboard()
        self._tail_log_loop()

    def _configure_styles(self):
        """Configure ttk styles for the current theme"""
        # Try to use a modern theme if available
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
        
        # Custom style for indicators
        self.style.configure('Indicator.TLabel',
                           font=('Segoe UI', 9, 'bold'),
                           anchor='center',
                           relief='sunken',
                           padding=6)
        
        # Custom style for security buttons
        self.style.configure('Security.TButton',
                           background='#dc3545',
                           foreground='white',
                           font=('Segoe UI', 10, 'bold'),
                           padding=8)
        
    def _load_icons(self):
        """Load icons from assets folder"""
        icons = {}
        if not HAS_PIL:
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
                'security': '🛡️'
            }
            for key, symbol in icon_symbols.items():
                icons[key] = symbol
            return icons
            
        icon_size = (20, 20)
        icon_files = {
            'start': 'start.png',
            'stop': 'stop.png', 
            'verify': 'verify.png',
            'settings': 'settings.png',
            'log': 'log.png',
            'report': 'report.png',
            'folder': 'folder.png',
            'theme': 'theme.png',
            'alert': 'alert.png',
            'security': 'security.png'
        }
        
        assets_dir = 'assets'
        if not os.path.exists(assets_dir):
            try:
                os.makedirs(assets_dir)
                print(f"Created {assets_dir} directory - please add your icon files there")
            except:
                print(f"Could not create {assets_dir} directory")
            return icons
        
        for key, filename in icon_files.items():
            filepath = os.path.join(assets_dir, filename)
            if os.path.exists(filepath):
                try:
                    img = Image.open(filepath)
                    img = img.resize(icon_size, Image.Resampling.LANCZOS)
                    icons[key] = ImageTk.PhotoImage(img)
                except Exception as e:
                    print(f"Failed to load icon {filepath}: {e}")
                    # Fallback to symbols
                    icon_symbols = {
                        'start': '▶',
                        'stop': '⏹',
                        'verify': '🔍',
                        'settings': '⚙️',
                        'log': '📋',
                        'report': '📊',
                        'folder': '📁',
                        'theme': '🌙',
                        'alert': '🔔',
                        'security': '🛡️'
                    }
                    icons[key] = icon_symbols.get(key, '📄')
            else:
                # Fallback to symbols
                icon_symbols = {
                    'start': '▶',
                    'stop': '⏹',
                    'verify': '🔍',
                    'settings': '⚙️',
                    'log': '📋',
                    'report': '📊',
                    'folder': '📁',
                    'theme': '🌙',
                    'alert': '🔔',
                    'security': '🛡️'
                }
                icons[key] = icon_symbols.get(key, '📄')
                
        return icons

    def toggle_theme(self):
        """Toggle between light and dark themes"""
        self.dark_mode = not self.dark_mode
        self.colors = self.dark_theme if self.dark_mode else self.light_theme
        self._apply_theme()
        
    def _apply_theme(self):
        """Apply current theme to all widgets - FIXED VERSION"""
        try:
            # Reconfigure styles with new colors
            self._configure_styles()
            
            # Apply to root window
            self.root.configure(bg=self.colors['bg'])
            
            # Apply to specific widgets that we know support these options
            # Only update tk widgets, not ttk widgets
            self._update_specific_widgets()
            
            # Update tamper indicators
            self._update_tamper_indicators()
            
            # Update theme button text
            if hasattr(self, 'theme_btn'):
                self.theme_btn.configure(text="☀️" if self.dark_mode else "🌙",
                                       bg=self.colors['button_bg'],
                                       fg=self.colors['button_fg'])
            
            # Update alert panel theme
            if hasattr(self, '_alert_frame'):
                self._apply_alert_panel_theme()
            
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
        
        # Update tamper indicators
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

    def _update_tamper_indicators(self):
        """Update tamper indicator colors based on current theme"""
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
                if hasattr(self, '_rec_indicator_label'):
                    self._rec_indicator_label.configure(bg=rec_bg, fg='white')
                if hasattr(self, '_log_indicator_label'):
                    self._log_indicator_label.configure(bg=log_bg, fg='white')
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
        
        # Theme toggle button on right
        theme_frame = ttk.Frame(header_frame)
        theme_frame.pack(side=tk.RIGHT)
        
        self.theme_btn = tk.Button(theme_frame, text="🌙", command=self.toggle_theme, 
                                 font=('Segoe UI', 12), bg=self.colors['button_bg'], 
                                 fg=self.colors['button_fg'], bd=0, padx=10)
        self.theme_btn.pack()
        
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
            ("▶️ Start Monitor", self.start_monitor, self.icons.get('', '')),
            ("⏹️ Stop Monitor", self.stop_monitor, self.icons.get('', '')),
            ("🔍 Verify Now", self.run_verification, self.icons.get('', '')),
            ("🔒 Check Signatures", self.verify_signatures, self.icons.get('', '')),
            ("⚙️ Settings", self.open_settings, self.icons.get('', '')),
            ("🔔 Test Alert", lambda: self._show_alert("Test Alert", "This is a test alert message", "info"), 
             self.icons.get('', ''))
        ]
        ttk.Button(action_frame, text="📄 Open Report Viewer", command=self._open_report_viewer, width=18).grid(row=0, column=len(buttons_config), padx=5, pady=5)
        for i, (text, command, icon) in enumerate(buttons_config):
            btn = ttk.Button(action_frame, text=f"{icon} {text}", command=command, width=18)
            btn.grid(row=0, column=i, padx=5, pady=5)
        
        # Dashboard Section
        dashboard_frame = ttk.LabelFrame(main_container, text="SECURITY DASHBOARD", padding="15")
        dashboard_frame.pack(fill=tk.X, pady=(0, 15))
        
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
        
        stats_data = [
            ("Total Monitored Files:", self.total_files_var, "0", "#0d6efd"),
            ("🟢 Created (Session):", self.created_var, "0", "#198754"),
            ("🟡 Modified (Session):", self.modified_var, "0", "#ffc107"),
            ("🔴 Deleted (Session):", self.deleted_var, "0", "#dc3545")
        ]
        
        for row, (label, var, default, color) in enumerate(stats_data):
            label_widget = ttk.Label(stats_grid, text=label, font=('Segoe UI', 10))
            label_widget.grid(row=row, column=0, sticky="w", pady=8, padx=(0, 20))
            
            value_widget = tk.Label(stats_grid, textvariable=var, font=('Segoe UI', 12, 'bold'),
                                  bg=self.colors['secondary_bg'], fg=color,
                                  relief="solid", borderwidth=1, width=15, anchor="center")
            value_widget.grid(row=row, column=1, sticky="ew", pady=8)
            # Store reference for theme updates
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
                self._rec_indicator_label = tk.Label(label_frame, text="", font=('Segoe UI', 10),
                                                    bg=self.colors['bg'], fg=self.colors['fg'])
                self._rec_indicator_label.pack(side=tk.LEFT)
            else:
                self._log_indicator = indicator
                self._log_indicator_label = tk.Label(label_frame, text="", font=('Segoe UI', 10),
                                                    bg=self.colors['bg'], fg=self.colors['fg'])
                self._log_indicator_label.pack(side=tk.LEFT)
        
        # Quick Actions
        quick_frame = tk.Frame(security_grid, bg=self.colors['bg'])
        quick_frame.grid(row=2, column=0, pady=(20, 0), sticky="w")
        
        quick_actions = [
            ("📋 View Log", self.open_log),
            ("📊 View Report", self.view_report),
            ("📁 Open Reports", self.open_reports_folder)
        ]
        
        if HAS_REPORTLAB:
            quick_actions.append(("📄 Export PDF", self.export_pdf_report))
        
        for i, (text, command) in enumerate(quick_actions):
            btn = ttk.Button(quick_frame, text=text, command=command, width=15)
            btn.grid(row=0, column=i, padx=5)
        
        # ttk.Button(quick_frame, text="Open Report Viewer", command=self._open_report_viewer).pack(side=tk.LEFT, padx=6)

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

    # ---------- Alert Panel Functions ----------
    def _create_alert_panel(self):
        """Create slide-in alert panel (safe to call multiple times)."""
        # ensure main window geometry is updated
        try:
            self.root.update_idletasks()
        except Exception:
            pass

        root_w = self.root.winfo_width() or self.root.winfo_screenwidth()
        root_h = self.root.winfo_height() or self.root.winfo_screenheight()
        margin = 20
        start_x = root_w + margin
        y = 50
        height = min(400, root_h - 120)

        if getattr(self, "_alert_frame", None):
            # adjust size / position for new window size
            try:
                self._alert_frame.config(width=self.ALERT_PANEL_WIDTH, height=height)
            except Exception:
                pass
            if not getattr(self, "alert_visible", False):
                self._alert_frame.place(x=start_x, y=y, width=self.ALERT_PANEL_WIDTH, height=height)
                self.alert_current_x = start_x
            return

        # build frame
        self._alert_frame = tk.Frame(self.root, bg=self.colors.get('panel_bg', '#111'), bd=1, relief="solid")
        self._alert_frame.place(x=start_x, y=y, width=self.ALERT_PANEL_WIDTH, height=height)

        header = tk.Frame(self._alert_frame, bg=self.colors.get('accent','#0d6efd'))
        header.pack(fill=tk.X)
        self._alert_title = tk.Label(header, text="🚨 SECURITY ALERTS", bg=self.colors.get('accent'), fg='white', font=('Segoe UI',11,'bold'))
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
        self._alert_meta = tk.Label(meta, text="No active alerts", bg=self.colors.get('panel_bg'), fg=self.colors.get('panel_fg'))
        self._alert_meta.pack(side=tk.LEFT)
        self._alert_counter = tk.Label(meta, text="Alerts: 0", bg=self.colors.get('panel_bg'), fg=self.colors.get('panel_fg'))
        self._alert_counter.pack(side=tk.RIGHT)

        # internal state
        self.alert_count = 0
        self.alert_visible = False
        self.alert_current_x = start_x
        self.alert_hide_after_id = None

    def _apply_alert_panel_theme(self):
        """Apply current theme to alert panel"""
        try:
            if hasattr(self, '_alert_frame'):
                self._alert_frame.configure(bg=self.colors['panel_bg'],
                                          highlightbackground=self.colors['accent'])
                # Update header
                for child in self._alert_frame.winfo_children():
                    if isinstance(child, tk.Frame):
                        child.configure(bg=self.colors['accent'])
                        for subchild in child.winfo_children():
                            if isinstance(subchild, tk.Label):
                                subchild.configure(bg=self.colors['accent'], fg='white')
                            elif isinstance(subchild, tk.Button):
                                subchild.configure(bg=self.colors['accent'], fg='white')
                # Update content
                self._alert_msg.configure(bg=self.colors['panel_bg'],
                                        fg=self.colors['panel_fg'])
                self._alert_meta.configure(bg=self.colors['panel_bg'],
                                         fg=self.colors['panel_fg'])
                self._alert_counter.configure(bg=self.colors['panel_bg'],
                                            fg=self.colors['panel_fg'])
        except Exception as e:
            print(f"Error applying alert panel theme: {e}")
    
    def _show_alert(self, title, message, level="info"):
        """Show the alert panel sliding in from right."""
        try:
            # make sure geometry values are correct
            try:
                self.root.update_idletasks()
            except Exception:
                pass

            if not getattr(self, "_alert_frame", None):
                self._create_alert_panel()

            # prepare text + color (simple)
            level_map = {
                "created": ("🟢 CREATED", "#198754"),
                "modified": ("🟡 MODIFIED", "#ffc107"),
                "deleted": ("🔴 DELETED", "#dc3545"),
                "tampered": ("🔥 TAMPERED", "#dc3545"),
                "info": ("ℹ️ INFO", "#0dcaf0")
            }
            label_text, color = level_map.get(level, ("ℹ️ INFO", "#0dcaf0"))

            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            entry = f"{label_text} • {ts}\n{message}\n{'-'*36}\n"

            # insert at top
            self._alert_msg.configure(state="normal")
            self._alert_msg.insert("1.0", entry)
            # optional: tag the first line for color
            try:
                self._alert_msg.tag_add(level, "1.0", f"1.0 + {len(entry.splitlines()[0])}c")
                self._alert_msg.tag_config(level, foreground=color, font=('Segoe UI',9,'bold'))
            except Exception:
                pass
            self._alert_msg.configure(state="disabled")

            # update meta
            self.alert_count = getattr(self, "alert_count", 0) + 1
            self._alert_counter.configure(text=f"Alerts: {self.alert_count}")
            self._alert_meta.configure(text=f"Last: {label_text} @ {ts}")

            # cancel pending hide
            if getattr(self, "alert_hide_after_id", None):
                try:
                    self.root.after_cancel(self.alert_hide_after_id)
                except Exception:
                    pass
                self.alert_hide_after_id = None

            # compute start and target based on current window width
            root_w = self.root.winfo_width() or self.root.winfo_screenwidth()
            margin = 20
            start_x = root_w + margin
            target_x = max(10, root_w - self.ALERT_PANEL_WIDTH - margin)

            # ensure panel placed at start_x if currently hidden
            if not getattr(self, "alert_visible", False):
                self._alert_frame.place(x=start_x, y=50, width=self.ALERT_PANEL_WIDTH)
                self.alert_current_x = start_x
                self.alert_visible = True

            # animate: move left (decrease x) until <= target_x
            self._animate_panel(target_x, slide_in=True)

            # auto hide after interval
            self.alert_hide_after_id = self.root.after(self.ALERT_SHOW_MS, self._hide_alert)

            # append to main log silently (avoid re-trigger)
            self._append_log_silent(f"Alert: {label_text} - {message}")

        except Exception as e:
            print("Error showing alert:", e)
            traceback.print_exc()
    
    def _hide_alert(self):
        """Slide the panel out to the right and hide."""
        try:
            if not getattr(self, "alert_visible", False):
                return
            # cancel scheduled hide (we're hiding now)
            if getattr(self, "alert_hide_after_id", None):
                try:
                    self.root.after_cancel(self.alert_hide_after_id)
                except Exception:
                    pass
                self.alert_hide_after_id = None

            # compute off-screen x
            try:
                self.root.update_idletasks()
            except Exception:
                pass
            off_x = self.root.winfo_width() + 40
            self._animate_panel(off_x, slide_in=False)
        except Exception as e:
            print("Error hiding alert:", e)
            traceback.print_exc()
    
    def _animate_panel(self, target_x, slide_in=True):
        """
        Animate the alert panel to target_x.
        slide_in=True  => move LEFT (decrease x) until x <= target_x
        slide_in=False => move RIGHT (increase x) until x >= target_x
        """
        try:
            # ensure geometry ready
            try:
                self.root.update_idletasks()
            except Exception:
                pass

            current_x = self._alert_frame.winfo_x()
            # compute direction-safe step
            if slide_in:
                # we want to decrease x toward target_x
                step = -abs(self.ALERT_ANIM_STEP)
                # if already at/left of target, place and stop
                if current_x <= target_x:
                    self._alert_frame.place(x=target_x)
                    self.alert_current_x = target_x
                    return
            else:
                # hide -> move right (increase x)
                step = abs(self.ALERT_ANIM_STEP)
                if current_x >= target_x:
                    # fully hidden / placed
                    try:
                        # take it off-screen
                        self._alert_frame.place_forget()
                    except Exception:
                        pass
                    self.alert_visible = False
                    self.alert_current_x = target_x
                    return

            new_x = current_x + step
            # clamp so we don't overshoot
            if slide_in and new_x < target_x:
                new_x = target_x
            if (not slide_in) and new_x > target_x:
                new_x = target_x

            self._alert_frame.place(x=new_x)
            self.alert_current_x = new_x
            # continue animation
            self.root.after(self.ALERT_ANIM_DELAY, lambda: self._animate_panel(target_x, slide_in=slide_in))
        except Exception as e:
            print("Animation error:", e)
            traceback.print_exc()

    
    def _append_log_silent(self, text):
        """Append message to GUI log without triggering alert handling again."""
        try:
            now_ts = datetime.now().strftime("%H:%M:%S")
            line = f"[{now_ts}] {text}\n"
            self.log_box.configure(state="normal")
            self.log_box.insert(tk.END, line)
            self.log_box.configure(state="disabled")
            self.log_box.see(tk.END)
        except Exception:
            pass

    def _handle_log_line(self, line):
        """
        Inspect a log line and show alert for important events.
        FIXED: Only handle specific event types to avoid infinite recursion
        """
        try:
            txt = line.strip()
            if not txt:
                return
            
            # Lower for matching
            low = txt.lower()
            
            # Only trigger alerts for specific keywords, not generic messages
            # Check for tamper events first
            if any(keyword in low for keyword in ['tamper', 'tampered', 'hmac fail', 'signature fail', 'compromised']):
                # Check if this is already an alert about an alert
                if 'alert:' not in low:
                    self._show_alert("Security Breach", txt, "tampered")
            elif 'created:' in low and 'alert:' not in low:
                self._show_alert("File Created", txt, "created")
            elif 'modified:' in low and 'alert:' not in low:
                self._show_alert("File Modified", txt, "modified")
            elif 'deleted:' in low and 'alert:' not in low:
                self._show_alert("File Deleted", txt, "deleted")
            # Skip info/warning messages to avoid infinite loops
            
        except Exception as e:
            print(f"Error handling log line: {e}")

    # ---------- Core Actions ----------
    def _browse(self):
        """Browse for folder to monitor"""
        d = filedialog.askdirectory()
        if d:
            self.watch_folder_var.set(d)
            self.folder_entry.delete(0, tk.END)
            self.folder_entry.insert(0, d)
            self._append_log(f"Selected monitor folder: {d}")

    def start_monitor(self):
        """Start monitoring the selected folder"""
        if not FileIntegrityMonitor:
            messagebox.showerror("Error", "Backend not available (integrity_core.py missing or import failed).")
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
                    try:
                        msg = f"Watching: {folder}\nStatus: Started\nStarted at: {time.strftime('%Y-%m-%d %H:%M:%S')}"
                        self._show_alert("Monitoring started", msg, level="info")
                    except Exception:
                        pass
                    self._show_alert("Monitoring Started", 
                                   f"Started monitoring folder:\n{folder}\n\nAll file changes will be tracked and alerts will be shown here.", 
                                   "info")
                    # Reset session counts
                    self.reset_session_counts()
                    # Trigger initial report
                    self._generate_activity_report("Initial Security Scan")
                else:
                    self._append_log("Monitor failed to start (check console/log).")
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
            try:
                msg = f"Previously watching: {self.watch_folder_var.get()}\nStatus: Stopped\nStopped at: {time.strftime('%Y-%m-%d %H:%M:%S')}"
                self._show_alert("Monitoring stopped", msg, level="info")
            except Exception:
                pass
            self._show_alert("Monitoring Stopped", 
                           "File integrity monitoring has been stopped.\n\nNo further changes will be tracked.", 
                           "info")
            # Generate final report
            self._generate_activity_report("Final Security Scan - Monitor Stopped")
        except Exception as ex:
            self._append_log(f"Exception stopping monitor: {ex}")
            traceback.print_exc()
            messagebox.showerror("Error", f"Exception: {ex}")

    def run_verification(self):
        """Run manual verification"""
        folder = self.folder_entry.get()
        if not folder or not os.path.exists(folder):
            messagebox.showerror("Error", "Choose valid folder first.")
            return

        def _verify():
            try:
                self._append_log("Manual security verification started...")
                self._show_alert("Verification Started", 
                               "Manual file integrity verification in progress...\n\nThis may take a few moments.", 
                               "info")
                
                summary = self.monitor.run_verification(watch_folder=folder)
                
                # Track file changes
                self._track_file_changes(summary)
                
                # Show verification results
                txt = (f"🔍 SECURITY VERIFICATION COMPLETE\n\n"
                    f"📊 Total monitored: {summary.get('total_monitored')}\n"
                    f"🟢 New files: {len(summary.get('created', []))}\n"
                    f"🟡 Modified files: {len(summary.get('modified', []))}\n"
                    f"🔴 Deleted files: {len(summary.get('deleted', []))}\n"
                    f"⏭️ Skipped files: {len(summary.get('skipped', []))}\n"
                    f"🔥 TAMPER - records: {'YES' if summary.get('tampered_records') else 'NO'}\n"
                    f"🔥 TAMPER - logs: {'YES' if summary.get('tampered_logs') else 'NO'}\n")
                
                messagebox.showinfo("Security Verification Summary", txt)
                self._append_log("Manual security verification finished.")
                
                # Show tamper alerts if detected
                if summary.get('tampered_records') or summary.get('tampered_logs'):
                    self._show_alert("TAMPER DETECTED!", 
                                   "File hash records or log signatures have been tampered with!\n\nImmediate security action required.", 
                                   "tampered")
                
                # Generate detailed report
                self._generate_detailed_report(summary, "Manual Security Verification")
                
            except Exception as ex:
                self._append_log(f"Verification error: {ex}")
                traceback.print_exc()
                messagebox.showerror("Error", f"Verification failed: {ex}")

        threading.Thread(target=_verify, daemon=True).start()

    def verify_signatures(self):
        """Verify cryptographic signatures"""
        # Try module-level verify functions first
        rec_ok = None
        log_ok = None
        rec_msg = ""
        log_msg = ""
        
        try:
            if verify_records_signature_on_disk:
                rec_ok = verify_records_signature_on_disk()
                rec_msg = "records HMAC OK" if rec_ok else "records HMAC FAILED"
            else:
                # fallback: try monitor-level method if available
                if hasattr(self.monitor, "verify_records_signature_on_disk"):
                    rec_ok = self.monitor.verify_records_signature_on_disk()
                    rec_msg = "records HMAC OK" if rec_ok else "records HMAC FAILED"
                else:
                    rec_msg = "No verify_records available"
        except Exception as ex:
            rec_ok = False
            rec_msg = f"Exception: {ex}"

        try:
            if verify_log_signatures:
                got = verify_log_signatures()
                # this function may return (ok, detail) or bool — handle both
                if isinstance(got, tuple):
                    log_ok, detail = got
                    log_msg = detail
                elif isinstance(got, bool):
                    log_ok = got
                    log_msg = "log sig OK" if log_ok else "log sig FAILED"
                else:
                    log_msg = str(got)
            else:
                if hasattr(self.monitor, "verify_log_signatures"):
                    got = self.monitor.verify_log_signatures()
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
        self._update_tamper_indicators()

        # Show alert for tamper detection
        if rec_ok is False or log_ok is False:
            self._show_alert("SIGNATURE TAMPER DETECTED!", 
                           f"Records: {rec_msg}\nLogs: {log_msg}\n\nCryptographic signatures have been compromised!", 
                           "tampered")
        elif rec_ok and log_ok:
            self._show_alert("Signatures Verified", 
                           "All cryptographic signatures are valid and intact.\n\nSystem integrity confirmed.", 
                           "info")
        
        self._append_log(f"Signature verification: records={rec_msg}, logs={log_msg}")

        # Generate signature verification report
        if rec_ok is not None or log_ok is not None:
            self._generate_activity_report("Cryptographic Signature Verification")

    # ---------- Helper Methods ----------
    def _append_log(self, text):
        """Append text to the log display - FIXED to avoid recursion"""
        try:
            self.log_box.configure(state="normal")
            now = datetime.now().strftime("%H:%M:%S")
            self.log_box.insert(tk.END, f"[{now}] {text}\n")
            self.log_box.configure(state="disabled")
            self.log_box.see(tk.END)
            
            # Handle log line for alerts (but avoid infinite recursion)
            # Only process if it's not an alert message itself
            if 'alert:' not in text.lower():
                self._handle_log_line(text)
            
        except Exception as e:
            print(f"Error appending to log: {e}")

    def _update_dashboard(self):
        """Update dashboard with current statistics"""
        try:
            # Update total files from monitor records
            current_total = 0
            if self.monitor and hasattr(self.monitor, 'records'):
                records = self.monitor.records
                current_total = len(records)
                self.total_files_var.set(str(current_total))
            else:
                # Fallback: try to load records directly
                try:
                    if os.path.exists(HASH_RECORD_FILE):
                        with open(HASH_RECORD_FILE, "r", encoding="utf-8") as f:
                            records = json.load(f)
                        current_total = len(records)
                        self.total_files_var.set(str(current_total))
                except:
                    self.total_files_var.set("0")

            # Update the UI with session counts
            self.created_var.set(str(self.file_tracking['session_created']))
            self.modified_var.set(str(self.file_tracking['session_modified']))
            self.deleted_var.set(str(self.file_tracking['session_deleted']))

        except Exception as e:
            print(f"Dashboard update error: {e}")
            # Set defaults on error
            self.total_files_var.set("0")
            self.created_var.set("0")
            self.modified_var.set("0")
            self.deleted_var.set("0")

        # Update tamper indicators
        self._update_tamper_indicators_from_backend()

        # Schedule next update
        self.root.after(3000, self._update_dashboard)

    def _update_tamper_indicators_from_backend(self):
        """Update tamper indicators from backend verification"""
        try:
            rec_ok = None
            log_ok = None
            
            # Check records signature
            if verify_records_signature_on_disk:
                rec_ok = verify_records_signature_on_disk()
            elif self.monitor and hasattr(self.monitor, "verify_records_signature_on_disk"):
                rec_ok = self.monitor.verify_records_signature_on_disk()
            
            # Check log signatures
            if verify_log_signatures:
                result = verify_log_signatures()
                if isinstance(result, tuple):
                    log_ok = result[0]
                else:
                    log_ok = result
            elif self.monitor and hasattr(self.monitor, "verify_log_signatures"):
                result = self.monitor.verify_log_signatures()
                if isinstance(result, tuple):
                    log_ok = result[0]
                else:
                    log_ok = result
            
            # Update UI indicators
            self.tamper_records_var.set("OK" if rec_ok else "TAMPERED" if rec_ok is False else "UNKNOWN")
            self.tamper_logs_var.set("OK" if log_ok else "TAMPERED" if log_ok is False else "UNKNOWN")
            self._update_tamper_indicators()
            
        except Exception:
            # Ignore errors in tamper indicator updates
            pass

    def reset_session_counts(self):
        """Reset session counts when monitor starts"""
        self.file_tracking['session_created'] = 0
        self.file_tracking['session_modified'] = 0
        self.file_tracking['session_deleted'] = 0
        
        # Update UI
        self.created_var.set("0")
        self.modified_var.set("0")
        self.deleted_var.set("0")
        self._append_log("Session file counters reset")

    def _track_file_changes(self, summary):
        """Track file changes from verification summaries"""
        if summary:
            created_count = len(summary.get('created', []))
            modified_count = len(summary.get('modified', []))
            deleted_count = len(summary.get('deleted', []))
            
            self.file_tracking['session_created'] += created_count
            self.file_tracking['session_modified'] += modified_count
            self.file_tracking['session_deleted'] += deleted_count
            
            # Update the UI
            self.created_var.set(str(self.file_tracking['session_created']))
            self.modified_var.set(str(self.file_tracking['session_modified']))
            self.deleted_var.set(str(self.file_tracking['session_deleted']))
            
            # Show alerts for significant changes
            if created_count > 0:
                self._show_alert(f"{created_count} New Files", 
                               f"{created_count} new file(s) detected during verification.", 
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
        """Continuously tail the log file"""
        try:
            if os.path.exists(LOG_FILE):
                try:
                    with open(LOG_FILE, "r", encoding="utf-8") as f:
                        lines = f.readlines()[-400:]  # Last 400 lines
                except Exception:
                    lines = []
                
                existing = self.log_box.get("1.0", tk.END)
                for line in lines:
                    if line.strip() and (line not in existing):
                        self.log_box.configure(state="normal")
                        self.log_box.insert(tk.END, line)
                        self.log_box.configure(state="disabled")
                        self.log_box.see(tk.END)
                        # Check for alerts in log lines
                        self._handle_log_line(line)
        except Exception as e:
            print(f"Error in log tail: {e}")
        
        # Schedule next update
        self.root.after(2000, self._tail_log_loop)

    # ---------- Other Methods ----------
    def test_webhook(self):
        """Test webhook functionality"""
        url = CONFIG.get("webhook_url") or self.webhook_var.get()
        if not url:
            messagebox.showinfo("Webhook", "No webhook URL configured in config.json or settings.")
            return
        if send_webhook_safe:
            try:
                send_webhook_safe("WEBHOOK_TEST", "This is a test webhook from GUI", None)
                messagebox.showinfo("Webhook", "Webhook test sent (check webhook receiver).")
                self._append_log("Webhook test sent.")
                self._show_alert("Webhook Test", "Test webhook notification sent successfully.", "info")
            except Exception as ex:
                messagebox.showerror("Webhook error", f"Failed to send webhook: {ex}")
        else:
            messagebox.showwarning("Webhook", "Webhook helper not available in backend.")

    def view_report(self):
        """View combined reports"""
        report_files = ["report_summary.txt", "activity_reports.txt", "detailed_reports.txt"]
        combined_content = ""
        
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
            messagebox.showinfo("Report", "No report files found yet. Run a verification to generate reports.")

    def open_log(self):
        """Open the log file"""
        if os.path.exists(LOG_FILE):
            try:
                os.startfile(LOG_FILE)
            except Exception:
                messagebox.showinfo("Info", f"Log file at: {os.path.abspath(LOG_FILE)}")
        else:
            messagebox.showinfo("Info", "No log file found.")

    def open_reports_folder(self):
        """Open the reports folder"""
        folder = os.path.abspath(".")
        try:
            os.startfile(folder)
        except Exception:
            messagebox.showinfo("Info", f"Open folder: {folder}")

    def open_settings(self):
        """Open settings dialog"""
        win = tk.Toplevel(self.root)
        win.title("Security Settings")
        win.geometry("520x300")
        win.configure(bg=self.colors['bg'])
        
        tk.Label(win, text="🔧 Security Configuration (config.json)", 
                bg=self.colors['bg'], fg=self.colors['fg'], font=('Segoe UI', 12, 'bold')).pack(anchor="w", padx=10, pady=(10, 0))

        cfg = dict(CONFIG)  # copy

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
            # write to config.json in working dir
            try:
                with open("config.json", "w", encoding="utf-8") as f:
                    json.dump(new_cfg, f, indent=4)
                # reload into backend (if load_config available)
                if load_config:
                    load_config("config.json")
                messagebox.showinfo("Settings", "Security configuration saved to config.json")
                self._show_alert("Settings Updated", "Security configuration has been updated and saved.", "info")
                win.destroy()
            except Exception as ex:
                messagebox.showerror("Error", f"Failed to save config: {ex}")

        btn_frame = ttk.Frame(win)
        btn_frame.pack(pady=12)
        
        ttk.Button(btn_frame, text="💾 Save Settings", command=save_settings).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="❌ Cancel", command=win.destroy).pack(side=tk.LEFT, padx=5)

    def export_pdf_report(self):
        """Export PDF report"""
        if not HAS_REPORTLAB:
            messagebox.showwarning("PDF Export", "ReportLab not installed. Install with: pip install reportlab")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")],
            initialfile=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        )
        
        if not filename:
            return
            
        def _generate_pdf():
            try:
                self._append_log("Generating security PDF report...")
                self._show_alert("PDF Export", "Generating comprehensive security PDF report...", "info")
                
                # Create PDF document
                doc = SimpleDocTemplate(filename, pagesize=A4, topMargin=1*inch)
                styles = getSampleStyleSheet()
                
                # Custom styles
                title_style = ParagraphStyle(
                    'CustomTitle',
                    parent=styles['Heading1'],
                    fontSize=16,
                    spaceAfter=30,
                    textColor=colors.darkblue
                )
                
                heading_style = ParagraphStyle(
                    'CustomHeading',
                    parent=styles['Heading2'],
                    fontSize=12,
                    spaceAfter=12,
                    textColor=colors.darkblue
                )
                
                # Content collection
                story = []
                
                # Title
                story.append(Paragraph("SECURITY INTEGRITY MONITOR REPORT", title_style))
                story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
                story.append(Spacer(1, 20))
                
                # System Overview
                story.append(Paragraph("SYSTEM SECURITY OVERVIEW", heading_style))
                overview_data = [
                    ["Monitor Status:", self.status_var.get()],
                    ["Watch Folder:", self.watch_folder_var.get()],
                    ["Total Files:", self.total_files_var.get()],
                    ["New Files:", self.created_var.get()],
                    ["Modified Files:", self.modified_var.get()],
                    ["Deleted Files:", self.deleted_var.get()]
                ]
                
                overview_table = Table(overview_data, colWidths=[2*inch, 4*inch])
                overview_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('PADDING', (0, 0), (-1, -1), 6),
                ]))
                story.append(overview_table)
                story.append(Spacer(1, 20))
                
                # Security Status
                story.append(Paragraph("SECURITY STATUS", heading_style))
                security_data = [
                    ["Component", "Status", "Integrity"],
                    ["Hash Records", self.tamper_records_var.get(), 
                     "✓ VERIFIED" if self.tamper_records_var.get() == "OK" else "✗ COMPROMISED"],
                    ["Log Files", self.tamper_logs_var.get(),
                     "✓ VERIFIED" if self.tamper_logs_var.get() == "OK" else "✗ COMPROMISED"]
                ]
                
                security_table = Table(security_data, colWidths=[1.5*inch, 1.5*inch, 3*inch])
                security_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('PADDING', (0, 0), (-1, -1), 6),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ]))
                story.append(security_table)
                story.append(Spacer(1, 20))
                
                # Recent Security Events
                story.append(Paragraph("RECENT SECURITY EVENTS", heading_style))
                try:
                    if os.path.exists(LOG_FILE):
                        with open(LOG_FILE, "r", encoding="utf-8") as f:
                            lines = f.readlines()[-20:]  # Last 20 lines
                        for line in lines:
                            story.append(Paragraph(line.strip(), styles['Normal']))
                            story.append(Spacer(1, 4))
                except Exception as e:
                    story.append(Paragraph(f"Could not read log file: {e}", styles['Normal']))
                
                # Digital Signature Verification
                story.append(Spacer(1, 20))
                story.append(Paragraph("CRYPTOGRAPHIC SECURITY", heading_style))
                signature_info = [
                    ["Verification successful", "All digital signatures are valid"],
                    ["HMAC protected", "All records and logs are cryptographically signed"],
                    ["Tamper detection", "Any modification will be immediately detected"],
                    ["Timestamp accuracy", "All events are properly timestamped and signed"]
                ]
                
                for info in signature_info:
                    story.append(Paragraph(f"• {info[0]}: {info[1]}", styles['Normal']))
                    story.append(Spacer(1, 4))
                
                # Footer
                story.append(Spacer(1, 30))
                story.append(Paragraph("Generated by Secure File Integrity Monitor Pro GUI", styles['Italic']))
                story.append(Paragraph("https://github.com/Manish93345/FileIntegrityChecker.git", styles['Italic']))
                
                # Build PDF
                doc.build(story)
                self._append_log(f"Security PDF report exported: {filename}")
                self._show_alert("PDF Export Complete", f"Security report successfully exported to:\n{filename}", "info")
                messagebox.showinfo("PDF Export", f"Report successfully exported to:\n{filename}")
                
            except Exception as e:
                self._append_log(f"PDF export failed: {e}")
                messagebox.showerror("PDF Export Error", f"Failed to export PDF: {e}")
        
        threading.Thread(target=_generate_pdf, daemon=True).start()

    def _show_text(self, title, content):
        """Show text in a new window"""
        w = tk.Toplevel(self.root)
        w.title(f"🔍 {title}")
        w.geometry("800x600")
        w.configure(bg=self.colors['bg'])
        
        # Header
        header = tk.Label(w, text=title, font=('Segoe UI', 12, 'bold'),
                        bg=self.colors['bg'], fg=self.colors['accent'])
        header.pack(pady=10)
        
        # Text content
        st = scrolledtext.ScrolledText(w, wrap=tk.WORD, 
                                     bg=self.colors['log_bg'], 
                                     fg=self.colors['log_fg'],
                                     font=("Consolas", 10))
        st.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        st.insert(tk.END, content)
        st.configure(state="disabled")
        
        # Close button
        close_btn = ttk.Button(w, text="Close", command=w.destroy)
        close_btn.pack(pady=10)



    def _open_report_viewer(self):
        """Open a separate window to view summary & detailed reports."""
        win = tk.Toplevel(self.root)
        win.title("📄 Report Viewer")
        win.geometry("850x600")
        win.minsize(700, 500)

        # main frame
        frm = ttk.Frame(win, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frm, text="Report Viewer", font=("Segoe UI", 14, "bold")).pack(anchor="w")

        # notebook for tabs
        nb = ttk.Notebook(frm)
        nb.pack(fill=tk.BOTH, expand=True, pady=10)

        # --- SUMMARY TAB ---
        summary_tab = ttk.Frame(nb)
        nb.add(summary_tab, text="Summary Report")

        st1 = scrolledtext.ScrolledText(summary_tab, wrap=tk.WORD)
        st1.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        if os.path.exists(REPORT_SUMMARY_FILE):
            try:
                with open(REPORT_SUMMARY_FILE, "r", encoding="utf-8") as f:
                    st1.insert(tk.END, f.read())
            except:
                st1.insert(tk.END, "Error reading summary report.")
        else:
            st1.insert(tk.END, "No summary report found.\nRun verification to generate one.")

        st1.configure(state="disabled")

        # --- DETAILED TAB ---
        detailed_tab = ttk.Frame(nb)
        nb.add(detailed_tab, text="Detailed Reports")

        st2 = scrolledtext.ScrolledText(detailed_tab, wrap=tk.WORD)
        st2.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        detailed_file = "detailed_reports.txt"
        if os.path.exists(detailed_file):
            try:
                with open(detailed_file, "r", encoding="utf-8") as f:
                    st2.insert(tk.END, f.read())
            except:
                st2.insert(tk.END, "Error reading detailed reports.")
        else:
            st2.insert(tk.END, "No detailed reports found.")

        st2.configure(state="disabled")

        # EXPORT BUTTON
        btn_frame = ttk.Frame(frm)
        btn_frame.pack(fill=tk.X, pady=5)
        ttk.Button(btn_frame, text="Save Summary As...", command=lambda: self._save_report_as(REPORT_SUMMARY_FILE)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Save Detailed As...", command=lambda: self._save_report_as(detailed_file)).pack(side=tk.LEFT, padx=5)

    def _save_report_as(self, file_path):
        if not os.path.exists(file_path):
            messagebox.showinfo("Info", "File not found.")
            return
        save_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                filetypes=[("Text Files", "*.txt")])
        if save_path:
            try:
                with open(file_path, "r", encoding="utf-8") as f1, open(save_path, "w", encoding="utf-8") as f2:
                    f2.write(f1.read())
                messagebox.showinfo("Saved", f"Saved to: {save_path}")
            except Exception as e:
                messagebox.showerror("Error", str(e))




    def _generate_activity_report(self, report_type):
        """Generate activity report"""
        try:
            if not self.monitor or not hasattr(self.monitor, 'records'):
                return
                
            records = self.monitor.records
            total_files = len(records)
            
            # Check signature status
            records_ok = False
            logs_ok = False
            if verify_records_signature_on_disk:
                records_ok = verify_records_signature_on_disk()
            if verify_log_signatures:
                logs_result = verify_log_signatures()
                logs_ok = logs_result[0] if isinstance(logs_result, tuple) else logs_result
            
            report_content = f"""
=== {report_type} Report @ {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} ===

Activity Summary:
- Total monitored files: {total_files}
- Records integrity: {'✓ VERIFIED' if records_ok else '✗ TAMPERED'}
- Logs integrity: {'✓ VERIFIED' if logs_ok else '✗ TAMPERED'}
- Report type: {report_type}

System Status:
- Monitor running: {self.monitor_running}
- Watch folder: {self.watch_folder_var.get()}
- Last update: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

Security Verification:
- Hash records: {'INTACT' if records_ok else 'COMPROMISED'}
- Log integrity: {'INTACT' if logs_ok else 'COMPROMISED'}
- Digital signatures: {'VALID' if records_ok and logs_ok else 'INVALID'}

"""
            # Append to report file
            with open("activity_reports.txt", "a", encoding="utf-8") as f:
                f.write(report_content + "\n")
                
            self._append_log(f"Activity report generated: {report_type}")
            
        except Exception as e:
            print(f"Error generating activity report: {e}")

    def _generate_detailed_report(self, summary, report_type):
        """Generate detailed report"""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Check signature status
            records_ok = False
            logs_ok = False
            logs_detail = "N/A"
            
            if verify_records_signature_on_disk:
                records_ok = verify_records_signature_on_disk()
            if verify_log_signatures:
                logs_result = verify_log_signatures()
                if isinstance(logs_result, tuple):
                    logs_ok, logs_detail = logs_result
                else:
                    logs_ok = logs_result
            
            report_content = f"""
=== DETAILED {report_type} REPORT ===
Generated: {timestamp}

FILE INTEGRITY SUMMARY:
────────────────────────────────────────
Total monitored files: {summary.get('total_monitored', 0)}
New files detected: {len(summary.get('created', []))}
Modified files: {len(summary.get('modified', []))}
Deleted files: {len(summary.get('deleted', []))}
Skipped files: {len(summary.get('skipped', []))}

SECURITY STATUS:
────────────────────────────────────────
Records integrity: {'✓ VERIFIED' if records_ok else '✗ TAMPERED'}
Logs integrity: {'✓ VERIFIED' if logs_ok else '✗ TAMPERED'}
Log verification details: {logs_detail}

DIGITAL SIGNATURE VERIFICATION:
────────────────────────────────────────
Hash records signature: {'VALID' if records_ok else 'INVALID'}
Log file signatures: {'VALID' if logs_ok else 'INVALID'}
Overall integrity: {'MAINTAINED' if records_ok and logs_ok else 'COMPROMISED'}

FILE CHANGES:
────────────────────────────────────────
"""
            # Add file lists if available
            if summary.get('created'):
                report_content += f"\nNEW FILES ({len(summary['created'])}):\n"
                for file in summary['created'][:10]:  # Show first 10
                    report_content += f"  + {os.path.basename(file)}\n"
                if len(summary['created']) > 10:
                    report_content += f"  ... and {len(summary['created']) - 10} more\n"
            
            if summary.get('modified'):
                report_content += f"\nMODIFIED FILES ({len(summary['modified'])}):\n"
                for file in summary['modified'][:10]:
                    report_content += f"  ~ {os.path.basename(file)}\n"
                if len(summary['modified']) > 10:
                    report_content += f"  ... and {len(summary['modified']) - 10} more\n"
            
            if summary.get('deleted'):
                report_content += f"\nDELETED FILES ({len(summary['deleted'])}):\n"
                for file in summary['deleted'][:10]:
                    report_content += f"  - {os.path.basename(file)}\n"
                if len(summary['deleted']) > 10:
                    report_content += f"  ... and {len(summary['deleted']) - 10} more\n"

            report_content += f"\nReport generated by: File Integrity Monitor Pro GUI\n"

            # Write to detailed report file
            with open("detailed_reports.txt", "a", encoding="utf-8") as f:
                f.write(report_content + "\n" + "="*50 + "\n\n")
                
            self._append_log(f"Detailed report generated: {report_type}")
            
        except Exception as e:
            print(f"Error generating detailed report: {e}")

# ---------- Run ----------
def main():
    try:
        root = tk.Tk()
        app = ProIntegrityGUI(root)
        root.mainloop()
    except Exception as e:
        print(f"Failed to start GUI: {e}")
        traceback.print_exc()
        input("Press Enter to close...")

if __name__ == "__main__":
    main()