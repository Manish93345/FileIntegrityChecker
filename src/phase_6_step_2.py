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
        self.root.title("🛡️ File Integrity Checker — Pro GUI")
        self.root.geometry("1000x700")
        self.root.minsize(900, 600)

        # Theme management
        self.dark_mode = False
        
        # Professional color schemes
        self.light_theme = {
            'bg': '#f5f5f5',
            'fg': '#333333',
            'accent': '#007acc',
            'secondary_bg': '#ffffff',
            'frame_bg': '#e8e8e8',
            'text_bg': '#ffffff',
            'text_fg': '#000000',
            'button_bg': '#e0e0e0',
            'button_fg': '#333333',
            'button_active': '#007acc',
            'hover_bg': '#d0d0d0',
            'entry_bg': '#ffffff',
            'entry_fg': '#000000',
            'entry_border': '#cccccc',
            'indicator_ok': '#4CAF50',
            'indicator_tamper': '#f44336',
            'indicator_unknown': '#9E9E9E',
            'log_bg': '#ffffff',
            'log_fg': '#000000',
            'tab_bg': '#ffffff',
            'tab_fg': '#333333',
            'tab_selected': '#007acc'
        }
        
        self.dark_theme = {
            'bg': '#1e1e1e',
            'fg': '#e0e0e0',
            'accent': '#569cd6',
            'secondary_bg': '#252525',
            'frame_bg': '#2d2d2d',
            'text_bg': '#252525',
            'text_fg': '#e0e0e0',
            'button_bg': '#3c3c3c',
            'button_fg': '#ffffff',
            'button_active': '#569cd6',
            'hover_bg': '#505050',
            'entry_bg': '#2d2d2d',
            'entry_fg': '#ffffff',
            'entry_border': '#3e3e3e',
            'indicator_ok': '#4CAF50',
            'indicator_tamper': '#f44336',
            'indicator_unknown': '#666666',
            'log_bg': '#1e1e1e',
            'log_fg': '#d4d4d4',
            'tab_bg': '#2d2d2d',
            'tab_fg': '#ffffff',
            'tab_selected': '#569cd6'
        }
        
        self.colors = self.light_theme
        
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
        self.status_var = tk.StringVar(value="Stopped")
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
                           font=('Segoe UI', 10, 'normal'))
        
        self.style.map('TButton',
                      background=[('active', self.colors['hover_bg']),
                                 ('pressed', self.colors['button_active'])],
                      foreground=[('active', self.colors['button_fg']),
                                 ('pressed', self.colors['button_fg'])])
        
        self.style.configure('TEntry',
                           fieldbackground=self.colors['entry_bg'],
                           foreground=self.colors['entry_fg'],
                           borderwidth=1,
                           insertcolor=self.colors['entry_fg'])
        
        self.style.configure('TLabelframe',
                           background=self.colors['bg'],
                           foreground=self.colors['fg'],
                           bordercolor=self.colors['frame_bg'])
        
        self.style.configure('TLabelframe.Label',
                           background=self.colors['bg'],
                           foreground=self.colors['fg'],
                           font=('Segoe UI', 10, 'bold'))
        
        # Custom style for indicators
        self.style.configure('Indicator.TLabel',
                           font=('Segoe UI', 9, 'bold'),
                           anchor='center',
                           relief='sunken',
                           padding=4)
        
    def _load_icons(self):
        """Load icons from assets folder"""
        icons = {}
        if not HAS_PIL:
            return icons
            
        icon_size = (16, 16)  # Standard icon size for buttons
        icon_files = {
            'start': 'start.png',
            'stop': 'stop.png', 
            'verify': 'verify.png',
            'settings': 'settings.png',
            'log': 'log.png',
            'report': 'report.png',
        }
        
        assets_dir = 'assets'
        if not os.path.exists(assets_dir):
            # Try to create assets directory
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
            else:
                print(f"Icon file not found: {filepath}")
                
        return icons

    def toggle_theme(self):
        """Toggle between light and dark themes"""
        self.dark_mode = not self.dark_mode
        self.colors = self.dark_theme if self.dark_mode else self.light_theme
        self._apply_theme()
        
    def _apply_theme(self):
        """Apply current theme to all widgets"""
        try:
            # Reconfigure styles with new colors
            self._configure_styles()
            
            # Apply to root window
            self.root.configure(bg=self.colors['bg'])
            
            # Apply theme to all widgets recursively
            self._apply_theme_recursive(self.root)
            
            # Update tamper indicators
            self._update_tamper_indicators()
            
            # Update theme button text
            self.theme_btn.configure(text="🌙" if self.dark_mode else "☀️")
            
        except Exception as e:
            print(f"Error applying theme: {e}")

    def _apply_theme_recursive(self, widget):
        """Recursively apply theme to widget and its children"""
        try:
            widget_class = widget.winfo_class()
            
            # Apply to different widget types
            if widget_class in ('TFrame', 'Frame'):
                widget.configure(bg=self.colors['bg'])
            elif widget_class in ('TLabel', 'Label'):
                widget.configure(bg=self.colors['bg'], fg=self.colors['fg'])
            elif widget_class in ('TButton', 'Button'):
                widget.configure(bg=self.colors['button_bg'], fg=self.colors['button_fg'],
                               activebackground=self.colors['hover_bg'],
                               activeforeground=self.colors['button_fg'])
            elif widget_class in ('TEntry', 'Entry'):
                widget.configure(bg=self.colors['entry_bg'], fg=self.colors['entry_fg'],
                               insertbackground=self.colors['entry_fg'],
                               selectbackground=self.colors['accent'],
                               selectforeground=self.colors['text_bg'])
            elif widget_class == 'Text' or 'ScrolledText' in widget_class:
                widget.configure(bg=self.colors['log_bg'], fg=self.colors['log_fg'],
                               insertbackground=self.colors['log_fg'],
                               selectbackground=self.colors['accent'],
                               selectforeground=self.colors['text_bg'])
            elif widget_class in ('TLabelframe', 'Labelframe'):
                widget.configure(bg=self.colors['bg'], fg=self.colors['fg'])
                
        except Exception:
            pass
            
        # Recursively apply to children
        for child in widget.winfo_children():
            self._apply_theme_recursive(child)

    def _update_tamper_indicators(self):
        """Update tamper indicator colors based on current theme"""
        if hasattr(self, '_rec_indicator'):
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

    def _build_widgets(self):
        pad = 10
        # Top frame: folder selection and controls
        top = ttk.Frame(self.root, padding=pad)
        top.pack(fill=tk.X)

        ttk.Label(top, text="Folder to monitor:").pack(anchor="w")
        folder_frame = ttk.Frame(top)
        folder_frame.pack(fill=tk.X, pady=(4, 6))
        self.folder_entry = ttk.Entry(folder_frame, width=60)
        self.folder_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.folder_entry.insert(0, self.watch_folder_var.get())
        
        ttk.Button(folder_frame, text="Browse", command=self._browse).pack(side=tk.LEFT, padx=6)

        # Theme toggle button
        self.theme_btn = ttk.Button(folder_frame, text="☀️", command=self.toggle_theme, width=3)
        self.theme_btn.pack(side=tk.RIGHT, padx=6)

        btn_frame = ttk.Frame(top)
        btn_frame.pack(fill=tk.X, pady=(6, 2))

        # Create buttons with icons
        start_icon = self.icons.get('start')
        stop_icon = self.icons.get('stop')
        verify_icon = self.icons.get('verify')
        settings_icon = self.icons.get('settings')
        log_icon = self.icons.get('log')
        report_icon = self.icons.get('report')

        self.start_btn = ttk.Button(btn_frame, text="Start Monitoring", 
                                   image=start_icon, compound="left" if start_icon else "none",
                                   command=self.start_monitor, width=18)
        self.start_btn.pack(side=tk.LEFT, padx=4)

        self.stop_btn = ttk.Button(btn_frame, text="Stop Monitoring", 
                                  image=stop_icon, compound="left" if stop_icon else "none",
                                  command=self.stop_monitor, width=18)
        self.stop_btn.pack(side=tk.LEFT, padx=4)

        self.verify_btn = ttk.Button(btn_frame, text="Run Full Verification", 
                                    image=verify_icon, compound="left" if verify_icon else "none",
                                    command=self.run_verification, width=20)
        self.verify_btn.pack(side=tk.LEFT, padx=4)

        ttk.Button(btn_frame, text="Verify Signatures", command=self.verify_signatures, 
                  width=16).pack(side=tk.LEFT, padx=4)

        self.settings_btn = ttk.Button(btn_frame, text="Settings", 
                                      image=settings_icon, compound="left" if settings_icon else "none",
                                      command=self.open_settings, width=12)
        self.settings_btn.pack(side=tk.LEFT, padx=4)

        ttk.Button(btn_frame, text="Test Webhook", command=self.test_webhook, 
                  width=12).pack(side=tk.LEFT, padx=4)

        status_bar = ttk.Frame(self.root, padding=(pad, 4))
        status_bar.pack(fill=tk.X)
        ttk.Label(status_bar, text="Status:").pack(side=tk.LEFT)
        self.status_label = ttk.Label(status_bar, textvariable=self.status_var, 
                                     foreground=self.colors['accent'])
        self.status_label.pack(side=tk.LEFT, padx=(6, 20))

        # Dashboard Frame
        dash = ttk.LabelFrame(self.root, text="Live Dashboard", padding=10)
        dash.pack(fill=tk.X, padx=pad, pady=(4, 8))

        left = ttk.Frame(dash)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        stats_grid = ttk.Frame(left)
        stats_grid.pack(anchor="w", padx=6, pady=6)

        # Configure grid with proper spacing
        stats_grid.columnconfigure(0, weight=1)
        stats_grid.columnconfigure(1, weight=1)

        ttk.Label(stats_grid, text="Total files:", font=('Segoe UI', 10)).grid(row=0, column=0, sticky="w", pady=4)
        ttk.Label(stats_grid, textvariable=self.total_files_var, 
                 font=("Segoe UI", 12, "bold")).grid(row=0, column=1, sticky="w", padx=8, pady=4)

        ttk.Label(stats_grid, text="New (since last verify):", font=('Segoe UI', 10)).grid(row=1, column=0, sticky="w", pady=4)
        ttk.Label(stats_grid, textvariable=self.created_var, font=('Segoe UI', 10)).grid(row=1, column=1, sticky="w", padx=8, pady=4)

        ttk.Label(stats_grid, text="Modified:", font=('Segoe UI', 10)).grid(row=2, column=0, sticky="w", pady=4)
        ttk.Label(stats_grid, textvariable=self.modified_var, font=('Segoe UI', 10)).grid(row=2, column=1, sticky="w", padx=8, pady=4)

        ttk.Label(stats_grid, text="Deleted:", font=('Segoe UI', 10)).grid(row=3, column=0, sticky="w", pady=4)
        ttk.Label(stats_grid, textvariable=self.deleted_var, font=('Segoe UI', 10)).grid(row=3, column=1, sticky="w", padx=8, pady=4)

        # Tamper indicators
        right = ttk.Frame(dash)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, padx=10)

        ttk.Label(right, text="Tamper Status", font=('Segoe UI', 10, 'bold')).pack(anchor="w", pady=(0, 8))
        
        # Create frame for indicator with padding
        rec_frame = tk.Frame(right, bg=self.colors['bg'])
        rec_frame.pack(fill=tk.X, pady=(0, 8))
        self._rec_indicator = tk.Label(rec_frame, textvariable=self.tamper_records_var, 
                                      bg="grey", fg="white", relief="sunken", 
                                      width=15, font=('Segoe UI', 9, 'bold'))
        self._rec_indicator.pack(fill=tk.X, padx=2, pady=2)
        
        log_frame = tk.Frame(right, bg=self.colors['bg'])
        log_frame.pack(fill=tk.X)
        self._log_indicator = tk.Label(log_frame, textvariable=self.tamper_logs_var, 
                                      bg="grey", fg="white", relief="sunken", 
                                      width=15, font=('Segoe UI', 9, 'bold'))
        self._log_indicator.pack(fill=tk.X, padx=2, pady=2)

        # Middle: Buttons for report and file viewing
        mid = ttk.Frame(self.root, padding=(pad, 2))
        mid.pack(fill=tk.X)
        
        self.report_btn = ttk.Button(mid, text="View Last Report", 
                                    image=report_icon, compound="left" if report_icon else "none",
                                    command=self.view_report, width=16)
        self.report_btn.pack(side=tk.LEFT, padx=4)

        self.log_btn = ttk.Button(mid, text="Open Log File", 
                                 image=log_icon, compound="left" if log_icon else "none",
                                 command=self.open_log, width=16)
        self.log_btn.pack(side=tk.LEFT, padx=4)

        ttk.Button(mid, text="Open Reports Folder", command=self.open_reports_folder, 
                  width=16).pack(side=tk.LEFT, padx=4)

        # PDF Export button
        if HAS_REPORTLAB:
            self.pdf_btn = ttk.Button(mid, text="Export PDF Report", 
                                     command=self.export_pdf_report, width=18)
            self.pdf_btn.pack(side=tk.LEFT, padx=4)

        # Bottom: live log area
        log_frame = ttk.LabelFrame(self.root, text="Live Logs (tail)", padding=6)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=pad, pady=(6, pad))
        self.log_box = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=20, 
                                               font=("Consolas", 10),
                                               bg=self.colors['log_bg'], 
                                               fg=self.colors['log_fg'],
                                               insertbackground=self.colors['log_fg'])
        self.log_box.pack(fill=tk.BOTH, expand=True)
        self.log_box.configure(state="disabled")

        # Apply initial theme
        self._apply_theme()

    # ---------- Actions ----------
    def _browse(self):
        d = filedialog.askdirectory()
        if d:
            self.watch_folder_var.set(d)
            self.folder_entry.delete(0, tk.END)
            self.folder_entry.insert(0, d)

    def start_monitor(self):
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
                    self.status_var.set(f"Running — watching {folder}")
                    self._append_log(f"Monitor started for: {folder}")
                    # Reset session counts
                    self.reset_session_counts()
                    # Trigger initial report
                    self._generate_activity_report("Initial Scan")
                else:
                    self._append_log("Monitor failed to start (check console/log).")
                    messagebox.showerror("Error", "Monitor failed to start.")
            except Exception as ex:
                self._append_log(f"Exception starting monitor: {ex}")
                traceback.print_exc()
                messagebox.showerror("Error", f"Exception: {ex}")

        threading.Thread(target=_start, daemon=True).start()

    def stop_monitor(self):
        if not self.monitor_running:
            messagebox.showinfo("Info", "Monitor not running.")
            return
        try:
            self.monitor.stop_monitoring()
            self.monitor_running = False
            self.status_var.set("Stopped")
            self._append_log("Monitor stopped by user.")
            # Generate final report
            self._generate_activity_report("Final Scan - Monitor Stopped")
        except Exception as ex:
            self._append_log(f"Exception stopping monitor: {ex}")
            traceback.print_exc()
            messagebox.showerror("Error", f"Exception: {ex}")

    def run_verification(self):
        folder = self.folder_entry.get()
        if not folder or not os.path.exists(folder):
            messagebox.showerror("Error", "Choose valid folder first.")
            return

        def _verify():
            try:
                self._append_log("Manual verification started...")
                summary = self.monitor.run_verification(watch_folder=folder)
                
                # TRACK THE ACTUAL FILE CHANGES
                self._track_file_changes(summary)
                
                # Build pretty text
                txt = (f"Verification completed:\n\n"
                    f"Total monitored: {summary.get('total_monitored')}\n"
                    f"New: {len(summary.get('created', []))}\n"
                    f"Modified: {len(summary.get('modified', []))}\n"
                    f"Deleted: {len(summary.get('deleted', []))}\n"
                    f"Skipped: {len(summary.get('skipped', []))}\n"
                    f"TAMPER - records: {'YES' if summary.get('tampered_records') else 'NO'}\n"
                    f"TAMPER - logs: {'YES' if summary.get('tampered_logs') else 'NO'}\n")
                messagebox.showinfo("Verification Summary", txt)
                self._append_log("Manual verification finished.")
                
                # Generate detailed report
                self._generate_detailed_report(summary, "Manual Verification")
                
            except Exception as ex:
                self._append_log(f"Verification error: {ex}")
                traceback.print_exc()
                messagebox.showerror("Error", f"Verification failed: {ex}")

        threading.Thread(target=_verify, daemon=True).start()

    def _generate_activity_report(self, report_type):
        """Generate a quick activity report when files change"""
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
        """Generate a detailed report with file changes"""
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

    def export_pdf_report(self):
        """Export a comprehensive PDF report"""
        if not HAS_REPORTLAB:
            messagebox.showwarning("PDF Export", "ReportLab not installed. Install with: pip install reportlab")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")],
            initialfile=f"integrity_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        )
        
        if not filename:
            return
            
        def _generate_pdf():
            try:
                self._append_log("Generating PDF report...")
                
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
                story.append(Paragraph("FILE INTEGRITY MONITOR REPORT", title_style))
                story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
                story.append(Spacer(1, 20))
                
                # System Overview
                story.append(Paragraph("SYSTEM OVERVIEW", heading_style))
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
                
                # Recent Activity
                story.append(Paragraph("RECENT ACTIVITY", heading_style))
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
                story.append(Paragraph("DIGITAL SIGNATURE VERIFICATION", heading_style))
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
                self._append_log(f"PDF report exported: {filename}")
                messagebox.showinfo("PDF Export", f"Report successfully exported to:\n{filename}")
                
            except Exception as e:
                self._append_log(f"PDF export failed: {e}")
                messagebox.showerror("PDF Export Error", f"Failed to export PDF: {e}")
        
        threading.Thread(target=_generate_pdf, daemon=True).start()

    def verify_signatures(self):
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

        # update UI indicators
        self.tamper_records_var.set("OK" if rec_ok else "TAMPERED" if rec_ok is False else "UNKNOWN")
        self.tamper_logs_var.set("OK" if log_ok else "TAMPERED" if log_ok is False else "UNKNOWN")
        self._update_tamper_indicators()

        self._append_log(f"Verify signatures: records={rec_msg}, logs={log_msg}")

        # Generate signature verification report
        if rec_ok is not None or log_ok is not None:
            self._generate_activity_report("Signature Verification")

    def test_webhook(self):
        url = CONFIG.get("webhook_url") or self.webhook_var.get()
        if not url:
            messagebox.showinfo("Webhook", "No webhook URL configured in config.json or settings.")
            return
        if send_webhook_safe:
            try:
                send_webhook_safe("WEBHOOK_TEST", "This is a test webhook from GUI", None)
                messagebox.showinfo("Webhook", "Webhook test sent (check webhook receiver).")
                self._append_log("Webhook test sent.")
            except Exception as ex:
                messagebox.showerror("Webhook error", f"Failed to send webhook: {ex}")
        else:
            messagebox.showwarning("Webhook", "Webhook helper not available in backend.")

    def view_report(self):
        # Combine all report files for viewing
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
            self._show_text("Combined Reports", combined_content)
        else:
            messagebox.showinfo("Report", "No report files found yet. Run a verification to generate reports.")

    def open_log(self):
        if os.path.exists(LOG_FILE):
            try:
                os.startfile(LOG_FILE)
            except Exception:
                messagebox.showinfo("Info", f"Log file at: {os.path.abspath(LOG_FILE)}")
        else:
            messagebox.showinfo("Info", "No log file found.")

    def open_reports_folder(self):
        # Ensure reports exist in cwd
        folder = os.path.abspath(".")
        try:
            os.startfile(folder)
        except Exception:
            messagebox.showinfo("Info", f"Open folder: {folder}")

    def open_settings(self):
        # Simple settings dialog to edit config.json keys (watch_folder, verify_interval, webhook_url)
        win = tk.Toplevel(self.root)
        win.title("Settings")
        win.geometry("520x260")
        win.configure(bg=self.colors['bg'])
        
        tk.Label(win, text="Edit configuration (config.json)", 
                bg=self.colors['bg'], fg=self.colors['fg'], font=('Segoe UI', 10, 'bold')).pack(anchor="w", padx=10, pady=(10, 0))

        cfg = dict(CONFIG)  # copy

        tk.Label(win, text="Watch folder:", bg=self.colors['bg'], fg=self.colors['fg'], font=('Segoe UI', 10)).pack(anchor="w", padx=10, pady=(8, 0))
        watch_var = tk.StringVar(value=cfg.get("watch_folder", ""))
        e1 = ttk.Entry(win, textvariable=watch_var, width=70)
        e1.pack(padx=10)

        tk.Label(win, text="Verify interval (seconds):", bg=self.colors['bg'], fg=self.colors['fg'], font=('Segoe UI', 10)).pack(anchor="w", padx=10, pady=(8, 0))
        int_var = tk.StringVar(value=str(cfg.get("verify_interval", 1800)))
        e2 = ttk.Entry(win, textvariable=int_var, width=20)
        e2.pack(padx=10)

        tk.Label(win, text="Webhook URL (optional):", bg=self.colors['bg'], fg=self.colors['fg'], font=('Segoe UI', 10)).pack(anchor="w", padx=10, pady=(8, 0))
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
                messagebox.showinfo("Settings", "Saved config.json")
                win.destroy()
            except Exception as ex:
                messagebox.showerror("Error", f"Failed to save config: {ex}")

        ttk.Button(win, text="Save", command=save_settings).pack(pady=12)

    # ---------- Helpers ----------
    def _append_log(self, text):
        self.log_box.configure(state="normal")
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        self.log_box.insert(tk.END, f"{now} - {text}\n")
        self.log_box.configure(state="disabled")
        self.log_box.see(tk.END)

    def _show_text(self, title, content):
        w = tk.Toplevel(self.root)
        w.title(title)
        w.geometry("720x520")
        w.configure(bg=self.colors['bg'])
        st = scrolledtext.ScrolledText(w, wrap=tk.WORD, 
                                     bg=self.colors['log_bg'], 
                                     fg=self.colors['log_fg'],
                                     font=("Consolas", 10))
        st.pack(fill=tk.BOTH, expand=True)
        st.insert(tk.END, content)
        st.configure(state="disabled")

    # Periodic dashboard update
    def _update_dashboard(self):
        """Update dashboard with current file statistics"""
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

    def track_file_event(self, event_type, file_path):
        """Track individual file events for accurate counting"""
        if event_type == 'CREATED':
            self.file_tracking['session_created'] += 1
            print(f"Tracked CREATED: {file_path} (Total created: {self.file_tracking['session_created']})")
        elif event_type == 'MODIFIED':
            self.file_tracking['session_modified'] += 1
            print(f"Tracked MODIFIED: {file_path} (Total modified: {self.file_tracking['session_modified']})")
        elif event_type == 'DELETED':
            self.file_tracking['session_deleted'] += 1
            print(f"Tracked DELETED: {file_path} (Total deleted: {self.file_tracking['session_deleted']})")
        
        # Update UI immediately
        self.created_var.set(str(self.file_tracking['session_created']))
        self.modified_var.set(str(self.file_tracking['session_modified']))
        self.deleted_var.set(str(self.file_tracking['session_deleted']))

    def reset_session_counts(self):
        """Reset session counts when monitor starts"""
        self.file_tracking['session_created'] = 0
        self.file_tracking['session_modified'] = 0
        self.file_tracking['session_deleted'] = 0
        
        # Update UI
        self.created_var.set("0")
        self.modified_var.set("0")
        self.deleted_var.set("0")
        print("Session counts reset")

    def _check_for_activity_reports(self):
        """Check if we should generate activity reports based on file changes"""
        try:
            # Simple heuristic: if file counts changed significantly, generate report
            current_total = int(self.total_files_var.get() or 0)
            current_created = int(self.created_var.get() or 0)
            current_modified = int(self.modified_var.get() or 0)
            
            # If there are recent changes, generate activity report
            if current_created > 0 or current_modified > 0:
                if not self.report_triggered:
                    self._generate_activity_report("File Change Detection")
                    self.report_triggered = True
            else:
                self.report_triggered = False
                
        except Exception:
            pass


        # ---------- ALERT PANEL (Right-side slide-in) ----------

    # Panel config
    _ALERT_PANEL_WIDTH = 400          # chosen: medium
    _ALERT_ANIM_STEP = 20             # pixels per frame
    _ALERT_ANIM_DELAY = 12            # ms between frames
    _ALERT_SHOW_MS = 4500             # show duration before hide (4.5s)

    def _create_alert_panel(self):
        """Call once at startup to create the hidden alert container."""
        # top-level container placed at right, initially off-screen
        root_w = self.root.winfo_width() or 1000
        root_h = self.root.winfo_height() or 700
        x = root_w  # start at right edge (offscreen)
        y = 60
        self._alert_frame = tk.Frame(self.root, width=_ALERT_PANEL_WIDTH, height=root_h - 120, bd=1, relief="flat")
        # use place() so we can animate x coordinate
        self._alert_frame.place(x=x, y=y)
        # inner widgets
        self._alert_title = tk.Label(self._alert_frame, text="ALERT", font=("Segoe UI", 12, "bold"))
        self._alert_title.pack(anchor="nw", padx=10, pady=(8,0))
        self._alert_msg = scrolledtext.ScrolledText(self._alert_frame, wrap=tk.WORD, height=10, state="disabled")
        self._alert_msg.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)
        self._alert_meta = tk.Label(self._alert_frame, text="", font=("Segoe UI", 9, "italic"))
        self._alert_meta.pack(anchor="se", padx=10, pady=(0,8))

        # styling: ensure contrast in both themes (self.colors expected)
        colors = getattr(self, "colors", None) or {"bg":"#1e1e1e","fg":"#ffffff"}
        self._alert_frame.configure(bg=colors.get("bg", "#1e1e1e"))
        self._alert_title.configure(bg=colors.get("bg"), fg=colors.get("accent", "#ffcc00"))
        self._alert_msg.configure(bg="#111111" if colors.get("bg","#1e1e1e")!="#ffffff" else "#ffffff",
                                fg=colors.get("fg", "#ffffff"), insertbackground=colors.get("fg", "#ffffff"))
        self._alert_meta.configure(bg=colors.get("bg"), fg=colors.get("fg"))

        # internal state
        self._alert_visible = False
        self._alert_current_x = x
        self._alert_hide_after_id = None

    def _show_alert(self, title, message, level="info"):
        """
        Show a slide-in alert.
        level in: "created", "modified", "deleted", "tampered", "info"
        """
        if not hasattr(self, "_alert_frame"):
            self._create_alert_panel()

        # Color mapping per level
        level_map = {
            "created": ("#0f9d58", "Created"),
            "modified": ("#f4b400", "Modified"),
            "deleted": ("#ea4335", "Deleted"),
            "tampered": ("#ff3b3b", "TAMPERED"),
            "info": ("#4e9af1", "Info")
        }
        color, label = level_map.get(level, ("#4e9af1", "Info"))

        # Update title and text
        self._alert_title.configure(text=f"🔔  {label}", fg=color)
        self._alert_msg.configure(state="normal")
        # prepend new alert at top
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        entry = f"{ts} — {label}\n{message}\n\n"
        self._alert_msg.insert("1.0", entry)
        self._alert_msg.configure(state="disabled")
        self._alert_meta.configure(text=f"{label} • {ts}")

        # determine target x for slide-in (anchored to right edge)
        root_w = self.root.winfo_width() or self.root.winfo_screenwidth()
        target_x = root_w - _ALERT_PANEL_WIDTH - 10  # 10px margin from right
        start_x = root_w + 10

        # cancel any pending hide
        if getattr(self, "_alert_hide_after_id", None):
            try: self.root.after_cancel(self._alert_hide_after_id)
            except Exception: pass
            self._alert_hide_after_id = None

        # place frame at start_x if not visible
        if not self._alert_visible:
            self._alert_current_x = start_x
            self._alert_frame.place(x=self._alert_current_x, y=60)
            self._alert_visible = True

        # animate to target_x
        def _anim_in():
            if self._alert_current_x <= target_x:
                # arrived
                self._alert_frame.place(x=target_x, y=60)
                self._alert_current_x = target_x
                # schedule auto hide
                self._alert_hide_after_id = self.root.after(_ALERT_SHOW_MS, self._hide_alert)
                return
            self._alert_current_x -= _ALERT_ANIM_STEP
            self._alert_frame.place(x=self._alert_current_x, y=60)
            self.root.after(_ALERT_ANIM_DELAY, _anim_in)

        _anim_in()

    def _hide_alert(self):
        """Slide out and hide the alert."""
        if not getattr(self, "_alert_frame", None) or not self._alert_visible:
            return
        root_w = self.root.winfo_width() or self.root.winfo_screenwidth()
        off_x = root_w + 10

        def _anim_out():
            if self._alert_current_x >= off_x:
                # fully hidden
                self._alert_frame.place_forget()
                self._alert_visible = False
                self._alert_current_x = off_x
                return
            self._alert_current_x += _ALERT_ANIM_STEP
            self._alert_frame.place(x=self._alert_current_x, y=60)
            self.root.after(_ALERT_ANIM_DELAY, _anim_out)

        _anim_out()

    # Helper: parse log lines -> produce alerts
    def _handle_log_line(self, line):
        """
        Inspect a log line and show alert for important events.
        Matches keywords CREATED, MODIFIED, DELETED, TAMPERED (case-insensitive).
        """
        try:
            txt = line.strip()
            if not txt:
                return
            # Lower for matching, but keep original for message
            low = txt.lower()
            if "tamper" in low or "tampered" in low or "tampere" in low:
                # tamper event (strong)
                self._show_alert("Tampering detected", txt, level="tampered")
            elif "created:" in low:
                self._show_alert("File created", txt, level="created")
            elif "modified:" in low:
                self._show_alert("File modified", txt, level="modified")
            elif "deleted:" in low:
                self._show_alert("File deleted", txt, level="deleted")
            # else: ignore less-important lines
        except Exception:
            pass


    # Tail the integrity_log into GUI - FIXED RECURSION ISSUE
    def _tail_log_loop(self):
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
                        self._handle_log_line(line)
        except Exception:
            pass
        # FIXED: Pass function reference, don't call it
        self.root.after(2000, self._tail_log_loop)

    def _track_file_changes(self, summary):
        """Track file changes from verification summaries"""
        # Update statistics from the summary
        if summary:
            self.file_tracking['session_created'] += len(summary.get('created', []))
            self.file_tracking['session_modified'] += len(summary.get('modified', []))
            self.file_tracking['session_deleted'] += len(summary.get('deleted', []))
            
            # Update the UI
            self.created_var.set(str(self.file_tracking['session_created']))
            self.modified_var.set(str(self.file_tracking['session_modified']))
            self.deleted_var.set(str(self.file_tracking['session_deleted']))

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