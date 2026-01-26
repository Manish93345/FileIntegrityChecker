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
"""

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import threading
import time
import os
import json
import traceback

# Try import from your backend
try:
    from integrity_core import (
        load_config,
        FileIntegrityMonitor,
        CONFIG,
        LOG_FILE,
        REPORT_SUMMARY_FILE,
    )
except Exception as e:
    # graceful fallback if import fails
    print("Failed to import integrity_core:", e)
    FileIntegrityMonitor = None
    load_config = None
    CONFIG = {}
    LOG_FILE = "integrity_log.txt"
    REPORT_SUMMARY_FILE = "report_summary.txt"

# Optional helpers (may or may not exist)
try:
    from integrity_core import (
        verify_records_signature_on_disk,
        verify_log_signatures,
        send_webhook_safe,
    )
except Exception:
    verify_records_signature_on_disk = None
    verify_log_signatures = None
    send_webhook_safe = None

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
        self.colors = self._get_light_theme()
        
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
        except Exception:
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

        # Build UI
        self._build_widgets()

        # Start background update loops
        self._update_dashboard()
        self._tail_log_loop()

    def _get_light_theme(self):
        return {
            'bg': '#f0f0f0',
            'fg': 'black',
            'accent': '#007acc',
            'secondary_bg': '#ffffff',
            'frame_bg': '#e8e8e8',
            'text_bg': 'white',
            'text_fg': 'black',
            'button_bg': '#e1e1e1',
            'hover_bg': '#d0d0d0',
            'indicator_ok': '#4CAF50',
            'indicator_tamper': '#f44336',
            'indicator_unknown': '#9E9E9E'
        }

    def _get_dark_theme(self):
        return {
            'bg': '#2b2b2b',
            'fg': 'white',
            'accent': '#007acc',
            'secondary_bg': '#3c3c3c',
            'frame_bg': '#363636',
            'text_bg': '#1e1e1e',
            'text_fg': 'white',
            'button_bg': '#404040',
            'hover_bg': '#505050',
            'indicator_ok': '#4CAF50',
            'indicator_tamper': '#f44336',
            'indicator_unknown': '#666666'
        }

    def _configure_styles(self):
        """Configure ttk styles for light/dark theme"""
        self.style.configure('.', background=self.colors['bg'], foreground=self.colors['fg'])
        self.style.configure('Custom.TFrame', background=self.colors['bg'])
        self.style.configure('Custom.TLabelframe', background=self.colors['bg'], foreground=self.colors['fg'])
        self.style.configure('Custom.TLabelframe.Label', background=self.colors['bg'], foreground=self.colors['fg'])
        self.style.configure('Custom.TButton', 
                           background=self.colors['button_bg'],
                           foreground=self.colors['fg'])
        self.style.map('Custom.TButton',
                      background=[('active', self.colors['hover_bg']),
                                 ('pressed', self.colors['accent'])])
        
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
            'report': 'report.png'
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
        self.colors = self._get_dark_theme() if self.dark_mode else self._get_light_theme()
        self._apply_theme()
        
    def _apply_theme(self):
        """Apply current theme to all widgets"""
        # Update styles
        self._configure_styles()
        
        # Apply to root and all frames
        self.root.configure(bg=self.colors['bg'])
        
        # Update all child widgets
        self._update_widget_colors(self.root)
        
        # Update tamper indicators
        self._update_tamper_indicators()

    def _update_widget_colors(self, widget):
        """Recursively update widget colors"""
        try:
            if isinstance(widget, (tk.Frame, ttk.Frame)):
                if isinstance(widget, ttk.Frame):
                    widget.configure(style='Custom.TFrame')
                else:
                    widget.configure(bg=self.colors['bg'])
            elif isinstance(widget, tk.Label):
                widget.configure(bg=self.colors['bg'], fg=self.colors['fg'])
            elif isinstance(widget, tk.Button):
                widget.configure(bg=self.colors['button_bg'], fg=self.colors['fg'],
                               activebackground=self.colors['hover_bg'])
            elif isinstance(widget, tk.Entry):
                widget.configure(bg=self.colors['text_bg'], fg=self.colors['text_fg'],
                               insertbackground=self.colors['fg'])
            elif isinstance(widget, scrolledtext.ScrolledText):
                widget.configure(bg=self.colors['text_bg'], fg=self.colors['text_fg'])
            elif isinstance(widget, (ttk.LabelFrame, ttk.Labelframe)):
                widget.configure(style='Custom.TLabelframe')
        except Exception:
            pass
            
        # Recursively update children
        for child in widget.winfo_children():
            self._update_widget_colors(child)

    def _update_tamper_indicators(self):
        """Update tamper indicator colors based on current theme"""
        rec_ok = self.tamper_records_var.get() == "OK"
        log_ok = self.tamper_logs_var.get() == "OK"
        
        rec_bg = (self.colors['indicator_ok'] if rec_ok else 
                 self.colors['indicator_tamper'] if self.tamper_records_var.get() == "TAMPERED" else 
                 self.colors['indicator_unknown'])
        log_bg = (self.colors['indicator_ok'] if log_ok else 
                 self.colors['indicator_tamper'] if self.tamper_logs_var.get() == "TAMPERED" else 
                 self.colors['indicator_unknown'])
        
        self._rec_indicator.configure(background=rec_bg, foreground='white')
        self._log_indicator.configure(background=log_bg, foreground='white')

    def _build_widgets(self):
        pad = 8
        # Top frame: folder selection and controls
        top = ttk.Frame(self.root, padding=pad, style='Custom.TFrame')
        top.pack(fill=tk.X)

        ttk.Label(top, text="Folder to monitor:", background=self.colors['bg'], foreground=self.colors['fg']).pack(anchor="w")
        folder_frame = ttk.Frame(top, style='Custom.TFrame')
        folder_frame.pack(fill=tk.X, pady=(4, 6))
        self.folder_entry = ttk.Entry(folder_frame, width=60)
        self.folder_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.folder_entry.insert(0, self.watch_folder_var.get())
        
        ttk.Button(folder_frame, text="Browse", command=self._browse, style='Custom.TButton').pack(side=tk.LEFT, padx=6)

        # Theme toggle button
        theme_btn = ttk.Button(folder_frame, text="🌗", command=self.toggle_theme, 
                              style='Custom.TButton', width=3)
        theme_btn.pack(side=tk.RIGHT, padx=6)

        btn_frame = ttk.Frame(top, style='Custom.TFrame')
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
                                   command=self.start_monitor, width=18, style='Custom.TButton')
        self.start_btn.pack(side=tk.LEFT, padx=6)

        self.stop_btn = ttk.Button(btn_frame, text="Stop Monitoring", 
                                  image=stop_icon, compound="left" if stop_icon else "none",
                                  command=self.stop_monitor, width=18, style='Custom.TButton')
        self.stop_btn.pack(side=tk.LEFT, padx=6)

        self.verify_btn = ttk.Button(btn_frame, text="Run Full Verification", 
                                    image=verify_icon, compound="left" if verify_icon else "none",
                                    command=self.run_verification, width=18, style='Custom.TButton')
        self.verify_btn.pack(side=tk.LEFT, padx=6)

        ttk.Button(btn_frame, text="Verify Signatures", command=self.verify_signatures, 
                  width=16, style='Custom.TButton').pack(side=tk.LEFT, padx=6)

        self.settings_btn = ttk.Button(btn_frame, text="Settings", 
                                      image=settings_icon, compound="left" if settings_icon else "none",
                                      command=self.open_settings, width=12, style='Custom.TButton')
        self.settings_btn.pack(side=tk.LEFT, padx=6)

        ttk.Button(btn_frame, text="Test Webhook", command=self.test_webhook, 
                  width=12, style='Custom.TButton').pack(side=tk.LEFT, padx=6)

        status_bar = ttk.Frame(self.root, padding=(pad, 4), style='Custom.TFrame')
        status_bar.pack(fill=tk.X)
        ttk.Label(status_bar, text="Status:", background=self.colors['bg'], foreground=self.colors['fg']).pack(side=tk.LEFT)
        self.status_label = ttk.Label(status_bar, textvariable=self.status_var, 
                                     foreground=self.colors['accent'], background=self.colors['bg'])
        self.status_label.pack(side=tk.LEFT, padx=(6,20))

        # Dashboard Frame
        dash = ttk.LabelFrame(self.root, text="Live Dashboard", padding=10, style='Custom.TLabelframe')
        dash.pack(fill=tk.X, padx=pad, pady=(4, 8))

        left = ttk.Frame(dash, style='Custom.TFrame')
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        stats_grid = ttk.Frame(left, style='Custom.TFrame')
        stats_grid.pack(anchor="w", padx=6, pady=6)

        ttk.Label(stats_grid, text="Total files:", background=self.colors['bg'], foreground=self.colors['fg']).grid(row=0, column=0, sticky="w")
        ttk.Label(stats_grid, textvariable=self.total_files_var, 
                 font=("TkDefaultFont", 12, "bold"), background=self.colors['bg'], 
                 foreground=self.colors['fg']).grid(row=0, column=1, sticky="w", padx=8)

        ttk.Label(stats_grid, text="New (since last verify):", background=self.colors['bg'], foreground=self.colors['fg']).grid(row=1, column=0, sticky="w")
        ttk.Label(stats_grid, textvariable=self.created_var, background=self.colors['bg'], 
                 foreground=self.colors['fg']).grid(row=1, column=1, sticky="w", padx=8)

        ttk.Label(stats_grid, text="Modified:", background=self.colors['bg'], foreground=self.colors['fg']).grid(row=2, column=0, sticky="w")
        ttk.Label(stats_grid, textvariable=self.modified_var, background=self.colors['bg'], 
                 foreground=self.colors['fg']).grid(row=2, column=1, sticky="w", padx=8)

        ttk.Label(stats_grid, text="Deleted:", background=self.colors['bg'], foreground=self.colors['fg']).grid(row=3, column=0, sticky="w")
        ttk.Label(stats_grid, textvariable=self.deleted_var, background=self.colors['bg'], 
                 foreground=self.colors['fg']).grid(row=3, column=1, sticky="w", padx=8)

        # Tamper indicators - FIXED: removed padding option from tk.Label
        right = ttk.Frame(dash, style='Custom.TFrame')
        right.pack(side=tk.RIGHT, fill=tk.BOTH, padx=10)

        ttk.Label(right, text="Tamper Status", background=self.colors['bg'], 
                 foreground=self.colors['fg']).pack(anchor="w")
        
        # Create frame for indicator with padding instead of using padding in Label
        rec_frame = tk.Frame(right, bg=self.colors['bg'])
        rec_frame.pack(fill=tk.X, pady=(6, 10))
        self._rec_indicator = tk.Label(rec_frame, textvariable=self.tamper_records_var, 
                                      background="grey", foreground="white")
        self._rec_indicator.pack(fill=tk.X, padx=2, pady=2)
        
        log_frame = tk.Frame(right, bg=self.colors['bg'])
        log_frame.pack(fill=tk.X)
        self._log_indicator = tk.Label(log_frame, textvariable=self.tamper_logs_var, 
                                      background="grey", foreground="white")
        self._log_indicator.pack(fill=tk.X, padx=2, pady=2)

        # Middle: Buttons for report and file viewing
        mid = ttk.Frame(self.root, padding=(pad,2), style='Custom.TFrame')
        mid.pack(fill=tk.X)
        
        self.report_btn = ttk.Button(mid, text="View Last Report", 
                                    image=report_icon, compound="left" if report_icon else "none",
                                    command=self.view_report, width=16, style='Custom.TButton')
        self.report_btn.pack(side=tk.LEFT, padx=6)

        self.log_btn = ttk.Button(mid, text="Open Log File", 
                                 image=log_icon, compound="left" if log_icon else "none",
                                 command=self.open_log, width=16, style='Custom.TButton')
        self.log_btn.pack(side=tk.LEFT, padx=6)

        ttk.Button(mid, text="Open Reports Folder", command=self.open_reports_folder, 
                  width=16, style='Custom.TButton').pack(side=tk.LEFT, padx=6)

        # Bottom: live log area
        log_frame = ttk.LabelFrame(self.root, text="Live Logs (tail)", padding=6, style='Custom.TLabelframe')
        log_frame.pack(fill=tk.BOTH, expand=True, padx=pad, pady=(6, pad))
        self.log_box = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=20, 
                                               font=("Consolas", 10),
                                               bg=self.colors['text_bg'], 
                                               fg=self.colors['text_fg'])
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
            except Exception as ex:
                self._append_log(f"Verification error: {ex}")
                traceback.print_exc()
                messagebox.showerror("Error", f"Verification failed: {ex}")

        threading.Thread(target=_verify, daemon=True).start()

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
        if os.path.exists(REPORT_SUMMARY_FILE):
            try:
                with open(REPORT_SUMMARY_FILE, "r", encoding="utf-8") as f:
                    txt = f.read()
                self._show_text("Report Summary", txt)
            except Exception as ex:
                messagebox.showerror("Error", f"Failed to open report: {ex}")
        else:
            messagebox.showinfo("Report", "No report_summary.txt found yet. Run a verification to generate one.")

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
                bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor="w", padx=10, pady=(10,0))

        cfg = dict(CONFIG)  # copy

        tk.Label(win, text="Watch folder:", bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor="w", padx=10, pady=(8,0))
        watch_var = tk.StringVar(value=cfg.get("watch_folder", ""))
        e1 = ttk.Entry(win, textvariable=watch_var, width=70)
        e1.pack(padx=10)

        tk.Label(win, text="Verify interval (seconds):", bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor="w", padx=10, pady=(8,0))
        int_var = tk.StringVar(value=str(cfg.get("verify_interval", 1800)))
        e2 = ttk.Entry(win, textvariable=int_var, width=20)
        e2.pack(padx=10)

        tk.Label(win, text="Webhook URL (optional):", bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor="w", padx=10, pady=(8,0))
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

        ttk.Button(win, text="Save", command=save_settings, style='Custom.TButton').pack(pady=12)

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
                                     bg=self.colors['text_bg'], 
                                     fg=self.colors['text_fg'])
        st.pack(fill=tk.BOTH, expand=True)
        st.insert(tk.END, content)
        st.configure(state="disabled")

    # Periodic dashboard update
    def _update_dashboard(self):
        # update counts from monitor.records if available
        try:
            records = getattr(self.monitor, "records", {}) or {}
            total = len(records)
            self.total_files_var.set(str(total))
            # created/modified/deleted counts: we don't have exact historic counts here;
            # attempt to read last summary from report file (quick heuristic)
            created = modified = deleted = 0
            if os.path.exists(REPORT_SUMMARY_FILE):
                try:
                    with open(REPORT_SUMMARY_FILE, "r", encoding="utf-8") as f:
                        txt = f.read()
                    # naive parsing: look for last block
                    blocks = txt.strip().split("=== Summary @")
                    last = blocks[-1] if blocks else ""
                    created = txt.count("New files:") and int(last.split("New files:")[-1].splitlines()[0].strip() or 0)
                except Exception:
                    created = modified = deleted = 0
            self.created_var.set(str(created))
            self.modified_var.set(str(modified))
            self.deleted_var.set(str(deleted))
        except Exception:
            pass

        # tamper indicators: try module-level verify checks or monitor methods
        try:
            rec_ok = None
            log_ok = None
            if verify_records_signature_on_disk:
                rec_ok = verify_records_signature_on_disk()
            elif hasattr(self.monitor, "verify_records_signature_on_disk"):
                rec_ok = self.monitor.verify_records_signature_on_disk()
            if verify_log_signatures:
                got = verify_log_signatures()
                if isinstance(got, tuple):
                    log_ok = got[0]
                elif isinstance(got, bool):
                    log_ok = got
            elif hasattr(self.monitor, "verify_log_signatures"):
                got = self.monitor.verify_log_signatures()
                if isinstance(got, tuple):
                    log_ok = got[0]
                elif isinstance(got, bool):
                    log_ok = got
            # update UI
            self.tamper_records_var.set("OK" if rec_ok else "TAMPERED" if rec_ok is False else "UNKNOWN")
            self.tamper_logs_var.set("OK" if log_ok else "TAMPERED" if log_ok is False else "UNKNOWN")
            self._update_tamper_indicators()
        except Exception:
            # ignore errors
            pass

        # schedule next update
        self.root.after(2500, self._update_dashboard)

    # Tail the integrity_log into GUI
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
        except Exception:
            pass
        self.root.after(2000, self._tail_log_loop)

# ---------- Run ----------
def main():
    root = tk.Tk()
    app = ProIntegrityGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()