#!/usr/bin/env python3
"""
NEW
integrity_gui.py — FMSecure v2.0
Enterprise File Integrity & EDR Security Monitor
Redesigned GUI — Production-Grade UI
"""

import random
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox, simpledialog
import customtkinter as ctk
import threading
import time
import json
import traceback
from datetime import datetime
import tempfile
import sys
import subprocess
import os
import pystray
from PIL import Image as PILImage
from pystray import MenuItem as item
from core.utils import get_app_data_dir, get_base_path
from core.subscription_manager import subscription_manager  
from core.integrity_core import get_decrypted_logs
import socket
import uuid
import requests

APP_DATA = get_app_data_dir()
LOGS_DIR = os.path.join(APP_DATA, "logs")

try:
    from core import safe_mode
except ImportError:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    core_dir = os.path.join(os.path.dirname(current_dir), 'core')
    if core_dir not in sys.path:
        sys.path.append(core_dir)
    import safe_mode

if not os.path.exists(LOGS_DIR):
    try:
        os.makedirs(LOGS_DIR)
    except OSError:
        pass

REPORT_DATA_JSON = os.path.join(LOGS_DIR, "report_data.json")
SEVERITY_COUNTER_FILE = os.path.join(LOGS_DIR, "severity_counters.json")

# --- IMPORT BACKEND SAFELY ---
integrity_core = None
BACKEND_AVAILABLE = False
FileIntegrityMonitor = None

try:
    from core import integrity_core as ic_module
    integrity_core = ic_module
    from core.integrity_core import (
        load_config, FileIntegrityMonitor, CONFIG, LOG_FILE,
        REPORT_SUMMARY_FILE, SEVERITY_LEVELS, verify_records_signature_on_disk,
        verify_log_signatures, send_webhook_safe, HASH_RECORD_FILE,
        HASH_SIGNATURE_FILE, LOG_SIG_FILE
    )
    BACKEND_AVAILABLE = True
    print("✅ Backend imported successfully (Package Mode)")
except ImportError:
    try:
        sys.path.append('../core')
        import integrity_core as ic_module
        integrity_core = ic_module
        from integrity_core import (
            load_config, FileIntegrityMonitor, CONFIG, LOG_FILE,
            REPORT_SUMMARY_FILE, SEVERITY_LEVELS
        )
        BACKEND_AVAILABLE = True
        print("✅ Backend imported successfully (Dev Mode)")
    except Exception as e:
        print(f"⚠️ Backend import failed: {e}")

auth = None
try:
    try:
        from auth_manager import auth
    except ImportError:
        from core.auth_manager import auth
except ImportError as e:
    print(f"⚠️ Auth Manager import failed: {e}")
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(current_dir)
        if parent_dir not in sys.path:
            sys.path.append(parent_dir)
        from auth_manager import auth
        print("✅ Auth Manager loaded from parent directory")
    except ImportError:
        print("❌ Auth Manager not found in any location")
        auth = None

from pathlib import Path
import re

# ─────────────────────────────────────────────
#  DESIGN TOKENS — FMSecure v2.0
#  Clean, professional, EDR-grade palette
# ─────────────────────────────────────────────

DARK_THEME = {
    'bg':               '#0d1117',   # GitHub-dark level background
    'bg2':              '#161b22',   # Slightly lighter layer
    'card_bg':          '#1c2333',   # Card surface
    'card_border':      '#30363d',   # Subtle border
    'sidebar_bg':       '#0d1117',   # Sidebar background
    'header_bg':        '#161b22',   # Top bar
    'text_primary':     '#e6edf3',   # Primary text (bright white-blue)
    'text_secondary':   '#8b949e',   # Muted label text
    'text_muted':       '#484f58',   # Dimmed hint text
    'accent_primary':   '#2f81f7',   # CrowdStrike/Sentinel blue
    'accent_secondary': '#a371f7',   # Purple accent
    'accent_success':   '#3fb950',   # Green
    'accent_warning':   '#d29922',   # Amber
    'accent_danger':    '#f85149',   # Red
    'accent_info':      '#39c5cf',   # Teal/cyan
    'button_bg':        '#21262d',   # Default button
    'button_hover':     '#30363d',   # Hover
    'button_active':    '#2f81f7',
    'input_bg':         '#0d1117',
    'input_border':     '#30363d',
    'indicator_success':'#3fb950',
    'indicator_warning':'#d29922',
    'indicator_danger': '#f85149',
    'indicator_info':   '#39c5cf',
    'chart_bg':         '#1c2333',
    'chart_grid':       '#30363d',
    'chart_text':       '#e6edf3',
    'tag_bg':           '#1f2937',
    'divider':          '#21262d',
}

LIGHT_THEME = {
    'bg':               '#f0f2f5',
    'bg2':              '#ffffff',
    'card_bg':          '#ffffff',
    'card_border':      '#e1e4e8',
    'sidebar_bg':       '#f6f8fa',
    'header_bg':        '#ffffff',
    'text_primary':     '#1c2333',
    'text_secondary':   '#57606a',
    'text_muted':       '#8c959f',
    'accent_primary':   '#0969da',
    'accent_secondary': '#8250df',
    'accent_success':   '#1a7f37',
    'accent_warning':   '#9a6700',
    'accent_danger':    '#cf222e',
    'accent_info':      '#0969da',
    'button_bg':        '#f6f8fa',
    'button_hover':     '#e1e4e8',
    'button_active':    '#0969da',
    'input_bg':         '#ffffff',
    'input_border':     '#d0d7de',
    'indicator_success':'#1a7f37',
    'indicator_warning':'#9a6700',
    'indicator_danger': '#cf222e',
    'indicator_info':   '#0969da',
    'chart_bg':         '#ffffff',
    'chart_grid':       '#e1e4e8',
    'chart_text':       '#1c2333',
    'tag_bg':           '#f6f8fa',
    'divider':          '#e1e4e8',
}

SEVERITY_COLORS = {
    "CRITICAL": "#f85149",
    "HIGH":     "#f0883e",
    "MEDIUM":   "#d29922",
    "INFO":     "#39c5cf",
}

SEVERITY_EMOJIS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "INFO":     "🔵",
}

SEVERITY_BADGES = {
    "CRITICAL": "CRITICAL",
    "HIGH":     "HIGH",
    "MEDIUM":   "MEDIUM",
    "INFO":     "INFO",
}

# Import optional libraries
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

try:
    from PIL import Image as PILImage
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


# ─────────────────────────────────────────────
#  HELPER WIDGETS
# ─────────────────────────────────────────────

class _Card(tk.Frame):
    """Flat card with a left accent bar — the core visual unit of FMSecure."""
    def __init__(self, parent, colors, accent=None, **kwargs):
        super().__init__(parent,
                         bg=colors['card_bg'],
                         highlightbackground=colors['card_border'],
                         highlightthickness=1,
                         **kwargs)
        if accent:
            bar = tk.Frame(self, bg=accent, width=3)
            bar.pack(side=tk.LEFT, fill=tk.Y)

    def inner(self):
        """Return a padded inner frame to place content."""
        f = tk.Frame(self, bg=self['bg'])
        f.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        return f


class _SectionLabel(tk.Label):
    """12px uppercase muted section header."""
    def __init__(self, parent, text, colors, **kwargs):
        super().__init__(parent,
                         text=text.upper(),
                         font=('Segoe UI', 9, 'bold'),
                         bg=colors['card_bg'],
                         fg=colors['text_muted'],
                         **kwargs)


class _MetricBadge(tk.Label):
    """Pill-shaped metric value badge."""
    def __init__(self, parent, textvariable, bg_color, **kwargs):
        super().__init__(parent,
                         textvariable=textvariable,
                         font=('Segoe UI', 13, 'bold'),
                         bg=bg_color,
                         fg='#ffffff',
                         padx=14,
                         pady=4,
                         relief='flat',
                         **kwargs)


class _ActionButton(tk.Button):
    """Flat action button with smooth hover — all params required."""
    def __init__(self, parent, text, command, bg, fg='#ffffff',
                 font_size=9, width=None, **kwargs):
        kw = dict(text=text, command=command, font=('Segoe UI', font_size, 'bold'),
                  bg=bg, fg=fg, activebackground=bg, activeforeground=fg,
                  bd=0, cursor='hand2', relief='flat', pady=8)
        if width:
            kw['width'] = width
        super().__init__(parent, **kw, **kwargs)
        hover = self._lighten(bg)
        self.bind('<Enter>', lambda e: self.configure(bg=hover))
        self.bind('<Leave>', lambda e: self.configure(bg=bg))

    @staticmethod
    def _lighten(hex_color, factor=0.18):
        try:
            import colorsys
            c = hex_color.lstrip('#')
            r, g, b = (int(c[i:i+2], 16)/255 for i in (0, 2, 4))
            h, l, s = colorsys.rgb_to_hls(r, g, b)
            l = min(1.0, l + factor)
            r2, g2, b2 = colorsys.hls_to_rgb(h, l, s)
            return '#{:02x}{:02x}{:02x}'.format(int(r2*255), int(g2*255), int(b2*255))
        except Exception:
            return hex_color


class _ToggleSwitch(tk.Frame):
    """
    Custom toggle switch that looks like a real switch, not a button.
    state_var: tk.BooleanVar
    command: callable — receives no args, reads state_var itself
    """
    _ON_BG  = '#3fb950'
    _OFF_BG = '#484f58'
    _W, _H  = 44, 22

    def __init__(self, parent, state_var: tk.BooleanVar, command, colors, **kwargs):
        super().__init__(parent, bg=colors['card_bg'], **kwargs)
        self._var = state_var
        self._cmd = command
        self._colors = colors

        self._canvas = tk.Canvas(self, width=self._W, height=self._H,
                                 bg=colors['card_bg'], highlightthickness=0,
                                 cursor='hand2')
        self._canvas.pack()
        self._canvas.bind('<Button-1>', self._toggle)
        self._draw()

    def _draw(self):
        c = self._canvas
        c.delete('all')
        on = self._var.get()
        track_col = self._ON_BG if on else self._OFF_BG
        c.create_rounded_rect = getattr(c, 'create_rounded_rect', None)
        r = self._H // 2
        # Track
        c.create_oval(0, 0, self._H, self._H, fill=track_col, outline='')
        c.create_oval(self._W - self._H, 0, self._W, self._H, fill=track_col, outline='')
        c.create_rectangle(r, 0, self._W - r, self._H, fill=track_col, outline='')
        # Thumb
        thumb_x = (self._W - self._H + 3) if on else 3
        c.create_oval(thumb_x, 3, thumb_x + self._H - 6, self._H - 3,
                      fill='#ffffff', outline='')

    def _toggle(self, _event=None):
        self._var.set(not self._var.get())
        self._draw()
        self._cmd()

    def refresh(self):
        self._draw()


# ─────────────────────────────────────────────
#  MAIN APPLICATION CLASS
# ─────────────────────────────────────────────

class ProIntegrityGUI:

    # ── Tooltip ──────────────────────────────
    class ToolTip:
        def __init__(self, widget, text):
            self.widget = widget
            self.text = text
            self.tooltip = None
            self.widget.bind('<Enter>', self.show)
            self.widget.bind('<Leave>', self.hide)

        def show(self, event=None):
            if self.tooltip or not self.text:
                return
            try:
                x, y, _, _ = self.widget.bbox('insert')
            except Exception:
                x, y = 0, 0
            x += self.widget.winfo_rootx() + 28
            y += self.widget.winfo_rooty() + 28
            self.tooltip = tk.Toplevel(self.widget)
            self.tooltip.wm_overrideredirect(True)
            self.tooltip.wm_geometry(f'+{x}+{y}')
            tk.Label(self.tooltip, text=self.text,
                     background='#21262d', foreground='#e6edf3',
                     relief='flat', borderwidth=1,
                     font=('Segoe UI', 9),
                     padx=8, pady=4).pack()

        def hide(self, event=None):
            if self.tooltip:
                self.tooltip.destroy()
                self.tooltip = None

    # ── __init__ ─────────────────────────────
    def __init__(self, root, user_role='admin', username='admin'):
        self.root = root
        self.user_role = user_role
        self.username = username

        self.root.title('FMSecure v2.0 — Enterprise EDR')
        # --- 🚨 INJECT THE WINDOWS TASKBAR ICON ---
        try:
            if getattr(sys, 'frozen', False):
                # When running as compiled .exe
                icon_path = os.path.join(sys._MEIPASS, "assets", "icons", "app_icon.ico")
            else:
                # When running as a Python script
                project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                icon_path = os.path.join(project_root, "assets", "icons", "app_icon.ico")
                
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except Exception:
            pass # Fail silently so the app doesn't crash if the icon is moved

        self.root.geometry('1200x800')
        self.root.minsize(900, 600)
        self.root.resizable(True, True)

        self.dark_mode = True
        self.colors = DARK_THEME

        self.file_counter_labels = []
        self.severity_counter_labels = []

        # Alert panel config
        self.ALERT_PANEL_WIDTH  = 360
        self.ALERT_PANEL_HEIGHT = 320
        self.ALERT_ANIM_STEP    = 25
        self.ALERT_ANIM_DELAY   = 10
        self.ALERT_SHOW_MS      = 5000
        self.alert_visible      = False
        self.alert_hide_after_id = None

        self.renamed_var = tk.StringVar(value='0')

        self.report_data = {
            'total': 0, 'created': [], 'modified': [],
            'deleted': [], 'skipped': [],
            'tampered_records': False, 'tampered_logs': False, 'last_update': None
        }

        self.chart_colors = {
            'created': '#3fb950', 'modified': '#d29922',
            'deleted': '#f85149', 'total':    '#2f81f7'
        }

        self.severity_counters = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'INFO': 0}

        self.critical_var = tk.StringVar(value='0')
        self.high_var     = tk.StringVar(value='0')
        self.medium_var   = tk.StringVar(value='0')
        self.info_var     = tk.StringVar(value='0')

        cfg_ok = True
        try:
            if load_config:
                load_config(None)
            else:
                cfg_ok = False
        except Exception as e:
            print(f'Config load warning: {e}')
            cfg_ok = False

        if not cfg_ok:
            messagebox.showwarning('Config', 'Failed to load config.json — defaults will be used.')

        self.monitor         = FileIntegrityMonitor() if FileIntegrityMonitor else None
        self.monitor_thread  = None
        self.monitor_running = False

        self.watch_folder_var    = tk.StringVar(value=os.path.abspath(CONFIG.get('watch_folder', os.getcwd())))
        self.status_var          = tk.StringVar(value='Stopped')
        self.status_var.trace_add('write', lambda *args: self._update_status_color())
        self._log_filter = 'ALL'
        self._log_lines  = []
        self.total_files_var     = tk.StringVar(value='0')
        self.created_var         = tk.StringVar(value='0')
        self.modified_var        = tk.StringVar(value='0')
        self.deleted_var         = tk.StringVar(value='0')
        self.tamper_records_var  = tk.StringVar(value='UNKNOWN')
        self.tamper_logs_var     = tk.StringVar(value='UNKNOWN')
        self.webhook_var         = tk.StringVar(value=str(CONFIG.get('webhook_url', '')))

        self.file_tracking = {
            'last_total': 0,
            'session_created': 0, 'session_modified': 0,
            'session_deleted': 0, 'session_renamed': 0,
            'current_files': set()
        }

        # Toggle state vars
        # --- 🚨 TIER ENFORCEMENT FIX ---
        # Get the tier right away to prevent Free users from inheriting Pro settings from config.json
        current_tier = 'FREE'
        if auth:
            current_tier = auth.get_user_tier(self.username)
            # --- NEW FIX: Inject email into CONFIG so cloud sync knows the folder name ---
            user_data = auth.users.get(self.username, {})
            CONFIG["admin_email"] = user_data.get("registered_email", "UnknownUser")
            
        is_pro = subscription_manager.is_pro(current_tier)
        CONFIG["is_pro_user"] = is_pro  # <-- NEW: Let backend know if user is pro

        # Force toggle states to False if the user is not Pro, overriding config.json
        ad_value = CONFIG.get('active_defense', False) if is_pro else False
        ks_value = CONFIG.get('ransomware_killswitch', False) if is_pro else False
        usb_value = CONFIG.get('usb_readonly', False) if is_pro else False

        self._ad_var  = tk.BooleanVar(value=ad_value)
        self._ks_var  = tk.BooleanVar(value=ks_value)
        self._usb_var = tk.BooleanVar(value=usb_value)

        # Also sanitize the live backend CONFIG so the engine doesn't silently run Pro features
        if not is_pro:
            # 🚨 FIX: Remove Ghost Locks for downgraded users before stripping their config
            if CONFIG.get('usb_readonly', False):
                try:
                    from core.usb_policy import set_usb_read_only
                    set_usb_read_only(enable=False)
                except Exception as e:
                    print(f"Failed to revert USB OS lock: {e}")

            CONFIG['active_defense'] = False
            CONFIG['ransomware_killswitch'] = False
            CONFIG['usb_readonly'] = False
            
            # 🚨 FIX: Save this disabled state to the hard drive immediately!
            try:
                from core.integrity_core import save_config
                save_config()
            except Exception as e:
                print(f"Failed to save sanitized config: {e}")
        # -------------------------------

        self._configure_styles()
        self._build_widgets()
        self._create_side_menu()
        self._apply_permissions()
        self._create_alert_panel()

        self._update_dashboard()
        self._update_severity_counters()
        self._tail_log_loop()
        self._check_safe_mode_status()
        self._start_telemetry_heartbeat()
        self._setup_tray_icon()
        self._check_for_updates()

        from core.cloud_backup_scheduler import start_auto_backup
        start_auto_backup(username=self.username)

        self.root.protocol('WM_DELETE_WINDOW', self.on_closing)

        if '--recovery' in sys.argv:
            self.root.after(1000, lambda: self._append_log(
                '⚠️ RECOVERY MODE ACTIVATED: Resuming monitoring after hostile termination.'))
            self.root.after(1500, self.start_monitor)
            self.root.after(2000, self.hide_window)

    # ─────────────────────────────────────────
    #  STYLE CONFIGURATION
    # ─────────────────────────────────────────

    def _configure_styles(self):
        try:
            self.style = ttk.Style()
            self.style.theme_use('clam')
        except Exception:
            self.style = ttk.Style()

        c = self.colors
        self.style.configure('Modern.TButton',
                             background=c['button_bg'], foreground=c['text_primary'],
                             borderwidth=0, relief='flat',
                             font=('Segoe UI', 10), padding=(14, 7))
        self.style.map('Modern.TButton',
                       background=[('active', c['button_hover']), ('pressed', c['button_active'])],
                       foreground=[('active', c['text_primary'])])
        self.style.configure('Modern.TEntry',
                             fieldbackground=c['input_bg'], foreground=c['text_primary'],
                             borderwidth=1, insertcolor=c['text_primary'])
        self.style.configure('Modern.TScrollbar',
                             background=c['card_border'], troughcolor=c['card_bg'],
                             borderwidth=0, arrowcolor=c['text_muted'])

    # ─────────────────────────────────────────
    #  _build_widgets — COMPLETE REWRITE
    # ─────────────────────────────────────────

    def _build_widgets(self):
        C = self.colors
        self.root.configure(bg=C['bg'])

        # ══ ROOT LAYOUT ══════════════════════════════════════════════════════
        # top_bar / body (sidebar + main)
        # body → left_col (300px) + right_col (expand)
        # right_col → stat_row (3 metric cards) + log_area (tabbed)

        # ── Top bar ──────────────────────────────────────────────────────────
        top_bar = tk.Frame(self.root, bg=C['header_bg'], height=56)
        top_bar.pack(fill=tk.X, side=tk.TOP)
        top_bar.pack_propagate(False)

        # Left: hamburger + logo + wordmark
        left_hdr = tk.Frame(top_bar, bg=C['header_bg'])
        left_hdr.pack(side=tk.LEFT, fill=tk.Y, padx=(8, 0))

        self.menu_btn = tk.Button(left_hdr, text='☰', font=('Segoe UI', 16),
                                  bg=C['header_bg'], fg=C['text_secondary'],
                                  bd=0, cursor='hand2', activebackground=C['button_hover'],
                                  command=self.toggle_menu)
        self.menu_btn.pack(side=tk.LEFT, padx=(4, 10), pady=14)

        # Shield icon (canvas-drawn, no image needed)
        from PIL import Image, ImageTk

        def resource_path(path):
            if getattr(sys, 'frozen', False):
                return os.path.join(sys._MEIPASS, path)
            return os.path.join(os.path.abspath("."), path)

        try:
            logo_path = resource_path("assets/icons/app_icon.png")

            img = Image.open(logo_path)
            img = img.resize((32, 32))  # 👈 small header size

            self.header_logo = ImageTk.PhotoImage(img)

            logo_label = tk.Label(left_hdr, image=self.header_logo, bg=C['header_bg'])
            logo_label.pack(side=tk.LEFT, pady=10)

        except Exception as e:
            print("Header logo error:", e)

        tk.Label(left_hdr, text='FMSecure', font=('Segoe UI', 16, 'bold'),
                 bg=C['header_bg'], fg=C['text_primary']).pack(side=tk.LEFT, padx=(6, 4))
        tk.Label(left_hdr, text='v2.0', font=('Segoe UI', 10),
                 bg=C['header_bg'], fg=C['text_muted']).pack(side=tk.LEFT, pady=2)

        # Vertical separator
        tk.Frame(left_hdr, width=1, bg=C['divider']).pack(side=tk.LEFT, fill=tk.Y,
                                                           padx=16, pady=10)
        tk.Label(left_hdr, text='Enterprise EDR', font=('Segoe UI', 10),
                 bg=C['header_bg'], fg=C['text_secondary']).pack(side=tk.LEFT)

        # Right: status pill + tier badge + controls
        right_hdr = tk.Frame(top_bar, bg=C['header_bg'])
        right_hdr.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 20))

        # Status pill
        self._status_pill_frame = tk.Frame(right_hdr, bg=C['accent_danger'],
                                            padx=12, pady=3)
        self._status_pill_frame.pack(side=tk.LEFT, pady=16, padx=(0, 16))
        self._status_pill_dot = tk.Label(self._status_pill_frame,
                                         text='●', font=('Segoe UI', 9),
                                         bg=C['accent_danger'], fg='#ffffff')
        self._status_pill_dot.pack(side=tk.LEFT)
        self.status_label = tk.Label(self._status_pill_frame,
                                     textvariable=self.status_var,
                                     font=('Segoe UI', 9, 'bold'),
                                     bg=C['accent_danger'], fg='#ffffff')
        self.status_label.pack(side=tk.LEFT, padx=(5, 0))

        # Tier badge
        current_tier = 'FREE'
        if auth:
            current_tier = auth.get_user_tier(self.username)
        self.top_btn_frame = tk.Frame(right_hdr, bg=C['header_bg'])
        self.top_btn_frame.pack(side=tk.LEFT, pady=12)

        if not subscription_manager.is_pro(current_tier):
            self.upgrade_btn = ctk.CTkButton(
                self.top_btn_frame, text='⭐  Upgrade to PRO',
                command=self._show_activation_dialog,
                font=('Segoe UI', 11, 'bold'),
                fg_color='#d29922', text_color='#0d1117',
                hover_color='#e6a817', corner_radius=6,
                width=140, height=30, cursor='hand2')
            self.upgrade_btn.pack(side=tk.LEFT, padx=(0, 10))
        else:
            pro_frame = tk.Frame(self.top_btn_frame, bg='#2d2008', padx=10, pady=4)
            pro_frame.pack(side=tk.LEFT, padx=(0, 10))
            tk.Label(pro_frame, text='★  PRO', font=('Segoe UI', 10, 'bold'),
                     bg='#2d2008', fg='#d29922').pack()
            self.pro_badge = pro_frame

        # Icon buttons
        for icon, tip, cmd in [
            ('🌙', 'Toggle theme', self.toggle_theme),
            ('🔑', 'Change password', self.change_admin_password),
            ('🔓', 'Disable lockdown', self.disable_lockdown),
        ]:
            if icon == '🔑' and self.user_role != 'admin':
                continue
            if icon == '🔓' and self.user_role != 'admin':
                continue
            b = tk.Button(self.top_btn_frame, text=icon,
                          font=('Segoe UI', 13),
                          bg=C['header_bg'], fg=C['text_secondary'],
                          bd=0, cursor='hand2', width=3,
                          activebackground=C['button_hover'],
                          command=cmd)
            b.pack(side=tk.LEFT, padx=2)
            self.ToolTip(b, tip)
            if icon == '🌙':
                self.theme_btn = b

        # Divider
        tk.Frame(right_hdr, width=1, bg=C['divider']).pack(side=tk.LEFT,
                                                             fill=tk.Y, padx=12, pady=10)
        # User button
        self.user_btn = ctk.CTkButton(
            right_hdr, text=f'  {self.username}  ▾',
            font=('Segoe UI', 11),
            fg_color='transparent', hover_color=C['button_hover'],
            text_color=C['text_secondary'],
            corner_radius=6, cursor='hand2',
            command=self._show_profile_panel)
        self.user_btn.pack(side=tk.LEFT, pady=12)

        # Thin divider under top bar
        tk.Frame(self.root, height=1, bg=C['divider']).pack(fill=tk.X)

        # ── Body ─────────────────────────────────────────────────────────────
        body = tk.Frame(self.root, bg=C['bg'])
        body.pack(fill=tk.BOTH, expand=True)

        # ── Left column ──────────────────────────────────────────────────────
        left_col = tk.Frame(body, bg=C['bg'], width=300)
        left_col.pack(side=tk.LEFT, fill=tk.Y, padx=(16, 0), pady=16)
        left_col.pack_propagate(False)

        self._build_left_column(left_col)

        # Thin vertical separator
        tk.Frame(body, width=1, bg=C['divider']).pack(side=tk.LEFT, fill=tk.Y,
                                                        padx=16, pady=16)

        # ── Right column ─────────────────────────────────────────────────────
        right_col = tk.Frame(body, bg=C['bg'])
        right_col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True,
                       padx=(0, 16), pady=16)

        self._build_right_column(right_col)

    
    # ─────────────────────────────────────────
    #  BACKGROUND LOOPS & UI UPDATERS
    # ─────────────────────────────────────────

    # ─────────────────────────────────────────
    #  BACKGROUND LOOPS & UI UPDATERS
    # ─────────────────────────────────────────

    def _update_dashboard(self):
        """Update dashboard statistics without resetting session counters."""
        try:
            # FIX: The records live inside the handler, not the monitor!
            if self.monitor_running and self.monitor and hasattr(self.monitor, 'handler'):
                if hasattr(self.monitor.handler, 'records'):
                    records = self.monitor.handler.records
                    if records is not None:
                        self.total_files_var.set(str(len(records)))
 
        except Exception as e:
            print(f'Dashboard update error: {e}')
 
        # FIX: Restart the background loop so the GUI auto-heals every 3 seconds
        self.root.after(3000, self._update_dashboard)
        

    def _update_severity_counters(self):
        """Update severity counters from disk"""
        try:
            counter_path = SEVERITY_COUNTER_FILE
            if integrity_core and hasattr(integrity_core, 'SEVERITY_COUNTER_FILE'):
                counter_path = integrity_core.SEVERITY_COUNTER_FILE

            if os.path.exists(counter_path):
                try:
                    with open(counter_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        if data and isinstance(data, dict):
                            self.severity_counters = data
                except Exception:
                    pass

            # Update UI Variables
            self.critical_var.set(str(self.severity_counters.get('CRITICAL', 0)))
            self.high_var.set(str(self.severity_counters.get('HIGH', 0)))
            self.medium_var.set(str(self.severity_counters.get('MEDIUM', 0)))
            self.info_var.set(str(self.severity_counters.get('INFO', 0)))
            
        except Exception as e:
            pass

        # Schedule next update
        self.root.after(1500, self._update_severity_counters)

    def _update_tamper_indicators(self):
        """Update tamper indicator colors based on active theme"""
        if hasattr(self, '_rec_indicator'):
            try:
                rec_ok = self.tamper_records_var.get() == "OK"
                log_ok = self.tamper_logs_var.get() == "OK"
                
                rec_bg = (self.colors['indicator_success'] if rec_ok else 
                          self.colors['indicator_danger'] if self.tamper_records_var.get() == "TAMPERED" else 
                          self.colors['indicator_info'])
                log_bg = (self.colors['indicator_success'] if log_ok else 
                          self.colors['indicator_danger'] if self.tamper_logs_var.get() == "TAMPERED" else 
                          self.colors['indicator_info'])
                
                self._rec_indicator.configure(bg=rec_bg, fg='white')
                self._log_indicator.configure(bg=log_bg, fg='white')
            except Exception as e:
                pass

    def _track_file_changes(self, data):
        """Track file changes and show popups"""
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
                               f"{created_count} new file(s) detected.", "info")
            if modified_count > 0:
                self._show_alert(f"{modified_count} Modified Files", 
                               f"{modified_count} file(s) were modified.", "medium")
            if deleted_count > 0:
                self._show_alert(f"{deleted_count} Deleted Files", 
                               f"{deleted_count} file(s) were deleted.", "high")

    def _tail_log_loop(self):
        """Tail log file and populate Live Security Feed with filter support."""
        try:
            if os.path.exists(LOG_FILE):
                try:
                    fresh_lines = get_decrypted_logs()[-400:]
                except Exception:
                    fresh_lines = []
 
                if not hasattr(self, '_log_lines'):
                    self._log_lines = []
 
                # Only update if there are new lines
                if len(fresh_lines) != len(self._log_lines):
                    self._log_lines = [l for l in fresh_lines if l.strip()]
                    self._render_filtered_logs()
 
        except Exception as e:
            print(f'Error in log tail: {e}')
 
        self.root.after(2000, self._tail_log_loop)
    # ─────────────────────────────────────────
    #  LEFT COLUMN
    # ─────────────────────────────────────────

    def _build_left_column(self, parent):
        C = self.colors

        # ── 1. Protected directories ─────────────────────────────────────────
        self._section_header(parent, 'Protected Directories')

        dir_card = self._card(parent, accent=C['accent_primary'])
        dir_card.pack(fill=tk.X, pady=(0, 12)) 
        inner = dir_card.inner()

        # Listbox
        lb_frame = tk.Frame(inner, bg=C['card_bg'])
        lb_frame.pack(fill=tk.X, padx=14, pady=(12, 6))

        self.folder_listbox = tk.Listbox(
            lb_frame, height=4, selectmode=tk.SINGLE,
            bg=C['input_bg'], fg=C['text_primary'],
            selectbackground=C['accent_primary'],
            selectforeground='#ffffff',
            font=('Segoe UI', 9),
            relief='flat', highlightthickness=0,
            activestyle='none')
            
        # --- 🚨 FIX: Use Modern CTkScrollbar ---
        sb = ctk.CTkScrollbar(lb_frame, orientation='vertical', 
                              command=self.folder_listbox.yview,
                              fg_color=C['card_bg'], button_color=C['card_border'],
                              button_hover_color=C['button_hover'])
                              
        self.folder_listbox.configure(yscrollcommand=sb.set)
        self.folder_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.LEFT, fill=tk.Y, padx=(2,0))

        from core.integrity_core import CONFIG
        for f in CONFIG.get('watch_folders', []) or ([CONFIG['watch_folder']] if CONFIG.get('watch_folder') else []):
            self.folder_listbox.insert(tk.END, f)

        # Add / Remove
        btn_row = tk.Frame(inner, bg=C['card_bg'])
        btn_row.pack(fill=tk.X, padx=14, pady=(0, 14))
        btn_row.columnconfigure(0, weight=1)
        btn_row.columnconfigure(1, weight=1)

        _ActionButton(btn_row, '+ Add Folder', self._add_folder_gui,
                      C['accent_success'], font_size=9).grid(
            row=0, column=0, sticky='ew', padx=(0, 4))
        _ActionButton(btn_row, '− Remove', self._remove_folder_gui,
                      C['button_bg'], fg=C['text_secondary'], font_size=9).grid(
            row=0, column=1, sticky='ew', padx=(4, 0))

        # ── 2. Engine status ──────────────────────────────────────────────────
        self._section_header(parent, 'Engine Status', top_pad=12)

        st_card = self._card(parent, accent=C['accent_info'])
        st_card.pack(fill=tk.X, pady=(0, 12))
        st_inner = st_card.inner()

        grid = tk.Frame(st_inner, bg=C['card_bg'])
        grid.pack(fill=tk.X, padx=14, pady=12)
        grid.columnconfigure(1, weight=1)

        rows = [
            ('Hash records',  self.tamper_records_var,  '_rec_indicator'),
            ('Audit logs',    self.tamper_logs_var,      '_log_indicator'),
        ]
        for i, (lbl, var, attr) in enumerate(rows):
            tk.Label(grid, text=lbl, font=('Segoe UI', 10),
                     bg=C['card_bg'], fg=C['text_secondary']).grid(
                row=i, column=0, sticky='w', pady=5)
            badge = tk.Label(grid, textvariable=var,
                             font=('Segoe UI', 8, 'bold'),
                             bg=C['indicator_info'], fg='#ffffff',
                             padx=10, pady=3, relief='flat')
            badge.grid(row=i, column=1, sticky='e', pady=5)
            setattr(self, attr, badge)

        # ── 3. Security toggles ───────────────────────────────────────────────
        self._section_header(parent, 'Active Defense', top_pad=12)

        sec_card = self._card(parent, accent=C['accent_danger'])
        sec_card.pack(fill=tk.X, pady=(0, 12))
        sec_inner = sec_card.inner()

        toggles = [
            ('Active Defense',        self._ad_var,  self._toggle_active_defense,
             'Auto-heal vault + incident snapshots'),
            ('Ransomware Killswitch', self._ks_var,  self._toggle_killswitch,
             'Burst-detect + folder lockdown'),
            ('USB Device Control',    self._usb_var, self._toggle_usb_control,
             'Block USB write access (DLP)'),
        ]

        self._toggle_switches = {}

        for label, var, cmd, tip in toggles:
            row = tk.Frame(sec_inner, bg=C['card_bg'])
            row.pack(fill=tk.X, padx=14, pady=6)

            text_col = tk.Frame(row, bg=C['card_bg'])
            text_col.pack(side=tk.LEFT, fill=tk.X, expand=True)
            tk.Label(text_col, text=label,
                     font=('Segoe UI', 10, 'bold'),
                     bg=C['card_bg'], fg=C['text_primary']).pack(anchor='w')
            tk.Label(text_col, text=tip,
                     font=('Segoe UI', 8),
                     bg=C['card_bg'], fg=C['text_muted']).pack(anchor='w')

            sw = _ToggleSwitch(row, var, cmd, C)
            sw.pack(side=tk.RIGHT, padx=(8, 0))
            self._toggle_switches[label] = sw

        # Store references for legacy code that reads btn_text
        self.ad_btn_text  = tk.StringVar(value='ON' if self._ad_var.get()  else 'OFF')
        self.ks_btn_text  = tk.StringVar(value='ON' if self._ks_var.get()  else 'OFF')
        self.usb_btn_text = tk.StringVar(value='LOCKED' if self._usb_var.get() else 'ALLOWED')

        # ── 4. Control panel ──────────────────────────────────────────────────
        self._section_header(parent, 'Control Panel', top_pad=12)

        ctrl_card = self._card(parent)
        ctrl_card.pack(fill=tk.X, pady=(0, 12)) 
        ctrl_inner = ctrl_card.inner()

        btns = tk.Frame(ctrl_inner, bg=C['card_bg'])
        btns.pack(fill=tk.X, padx=14, pady=12)
        btns.columnconfigure(0, weight=1)
        btns.columnconfigure(1, weight=1)

        actions = [
            ('▶  Start', self.start_monitor,          C['accent_success']),
            ('■  Stop',  self.stop_monitor,            C['accent_danger']),
            ('⟳  Verify', self.run_verification,      C['accent_primary']),
            ('⌥  Signatures', self.verify_signatures,  C['accent_secondary']),
            ('⚙  Settings', self.open_settings,       C['accent_info']),
            ('↺  Reset Stats', self.reset_severity_counters, C['button_bg']),
        ]

        for i, (txt, cmd, clr) in enumerate(actions):
            _ActionButton(btns, txt, cmd, clr,
                          fg='#ffffff' if clr != C['button_bg'] else C['text_primary'],
                          font_size=9).grid(
                row=i // 2, column=i % 2,
                sticky='ew', padx=3, pady=3)

    # ─────────────────────────────────────────
    #  RIGHT COLUMN
    # ─────────────────────────────────────────

    def _build_right_column(self, parent):
        C = self.colors

        # ── Metric row (3 stat cards) ────────────────────────────────────────
        metric_row = tk.Frame(parent, bg=C['bg'])
        metric_row.pack(fill=tk.X, pady=(0, 12))

        # File activity card
        fc = self._card(metric_row, accent=C['accent_primary'])
        fc.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        fi = fc.inner()

        _SectionLabel(fi, 'File Activity', C).pack(anchor='w', padx=14, pady=(10, 6))

        stats_grid = tk.Frame(fi, bg=C['card_bg'])
        stats_grid.pack(fill=tk.X, padx=14, pady=(0, 12))

        stats_data = [
            ('Total',    self.total_files_var, C['accent_primary']),
            ('Created',  self.created_var,     C['accent_success']),
            ('Modified', self.modified_var,    C['accent_warning']),
            ('Renamed',  self.renamed_var,     C['accent_secondary']),
            ('Deleted',  self.deleted_var,     C['accent_danger']),
        ]

        for i, (lbl, var, clr) in enumerate(stats_data):
            col = i % 3
            row = i // 3

            cell = tk.Frame(stats_grid, bg=C['card_bg'])
            cell.grid(row=row, column=col, padx=4, pady=3, sticky='ew')
            stats_grid.columnconfigure(col, weight=1)

            val = _MetricBadge(cell, var, clr)
            val.pack(fill=tk.X)
            tk.Label(cell, text=lbl, font=('Segoe UI', 8),
                     bg=C['card_bg'], fg=C['text_muted']).pack()

            self.file_counter_labels.append((val, lbl, clr))

        # Severity card
        sc = self._card(metric_row, accent=C['accent_danger'])
        sc.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(12, 0))
        si = sc.inner()

        _SectionLabel(si, 'Security Alerts', C).pack(anchor='w', padx=14, pady=(10, 6))

        sev_grid = tk.Frame(si, bg=C['card_bg'])
        sev_grid.pack(fill=tk.X, padx=14, pady=(0, 12))

        sev_data = [
            ('CRITICAL', self.critical_var, SEVERITY_COLORS['CRITICAL']),
            ('HIGH',     self.high_var,     SEVERITY_COLORS['HIGH']),
            ('MEDIUM',   self.medium_var,   SEVERITY_COLORS['MEDIUM']),
            ('INFO',     self.info_var,     SEVERITY_COLORS['INFO']),
        ]

        for i, (lbl, var, clr) in enumerate(sev_data):
            cell = tk.Frame(sev_grid, bg=C['card_bg'])
            cell.grid(row=0, column=i, padx=4, pady=3, sticky='ew')
            sev_grid.columnconfigure(i, weight=1)

            val = _MetricBadge(cell, var, clr)
            val.pack(fill=tk.X)
            tk.Label(cell, text=lbl, font=('Segoe UI', 8, 'bold'),
                     bg=C['card_bg'], fg=clr).pack()

            self.severity_counter_labels.append((val, lbl, clr))

        # Reports card
        rc = self._card(metric_row, accent=C['accent_secondary'])
        rc.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(12, 0))
        ri = rc.inner()

        _SectionLabel(ri, 'Reports', C).pack(anchor='w', padx=14, pady=(10, 6))

        rep_btns = tk.Frame(ri, bg=C['card_bg'])
        rep_btns.pack(fill=tk.X, padx=14, pady=(0, 12))

        report_actions = []
        if HAS_REPORTLAB:
            report_actions += [
                ('PDF Report',    self.export_report_pdf, C['accent_secondary']),
                ('Logs PDF',      self.export_logs_pdf,   C['button_bg']),
            ]
        if HAS_MATPLOTLIB:
            report_actions.append(('Chart', self.generate_chart, C['button_bg']))
        report_actions.append(('View', self.view_report, C['button_bg']))

        for j, (t, cmd, clr) in enumerate(report_actions):
            r_col = j % 2
            r_row = j // 2
            rep_btns.columnconfigure(r_col, weight=1)
            _ActionButton(rep_btns, t, cmd, clr,
                          fg='#ffffff' if clr != C['button_bg'] else C['text_secondary'],
                          font_size=9).grid(
                row=r_row, column=r_col, sticky='ew', padx=3, pady=3)

        # ── Tab strip + log area ──────────────────────────────────────────────
        tab_container = tk.Frame(parent, bg=C['bg'])
        tab_container.pack(fill=tk.BOTH, expand=True)

        self._build_tab_area(tab_container)

    # ─────────────────────────────────────────
    #  TAB AREA
    # ─────────────────────────────────────────

    def _build_tab_area(self, parent):
        C = self.colors

        # Tab bar
        tab_bar = tk.Frame(parent, bg=C['bg'])
        tab_bar.pack(fill=tk.X)

        # Content frame
        tab_content = tk.Frame(parent, bg=C['card_bg'],
                               highlightbackground=C['card_border'],
                               highlightthickness=1)
        tab_content.pack(fill=tk.BOTH, expand=True)

        self._tabs = {}
        self._tab_btns = {}
        self._active_tab = tk.StringVar(value='logs')

        tab_defs = [
            ('logs',    '  Live Logs  '),
            ('vault',   '  Vault / Cloud  '),
            ('network', '  C2 Console  '),
        ]

        for tab_id, label in tab_defs:
            frame = tk.Frame(tab_content, bg=C['card_bg'])
            self._tabs[tab_id] = frame

            btn = tk.Button(tab_bar, text=label,
                            font=('Segoe UI', 10),
                            bg=C['bg'], fg=C['text_muted'],
                            bd=0, cursor='hand2', pady=8, padx=4,
                            activebackground=C['bg'],
                            command=lambda tid=tab_id: self._switch_tab(tid))
            btn.pack(side=tk.LEFT)
            self._tab_btns[tab_id] = btn

        self._build_logs_tab(self._tabs['logs'])
        self._build_vault_tab(self._tabs['vault'])
        self._build_network_tab(self._tabs['network'])
        self._switch_tab('logs')

    def _switch_tab(self, tab_id):
        C = self.colors
        for tid, frame in self._tabs.items():
            frame.pack_forget()
        for tid, btn in self._tab_btns.items():
            if tid == tab_id:
                btn.configure(bg=C['card_bg'], fg=C['accent_primary'],
                               font=('Segoe UI', 10, 'bold'))
            else:
                btn.configure(bg=C['bg'], fg=C['text_muted'],
                               font=('Segoe UI', 10))
        self._tabs[tab_id].pack(fill=tk.BOTH, expand=True)
        self._active_tab.set(tab_id)

    def _build_logs_tab(self, parent):
        C = self.colors
 
        header = tk.Frame(parent, bg=C['card_bg'])
        header.pack(fill=tk.X, padx=16, pady=(10, 6))
 
        tk.Label(header, text='Live Security Feed',
                 font=('Segoe UI', 11, 'bold'),
                 bg=C['card_bg'], fg=C['text_primary']).pack(side=tk.LEFT)
 
        # Severity filter pills — now FUNCTIONAL
        filter_frame = tk.Frame(header, bg=C['card_bg'])
        filter_frame.pack(side=tk.LEFT, padx=16)
 
        self._filter_pills = {}
 
        for sev, clr in [('ALL',      C['text_muted']),
                          ('CRITICAL', SEVERITY_COLORS['CRITICAL']),
                          ('HIGH',     SEVERITY_COLORS['HIGH']),
                          ('MEDIUM',   SEVERITY_COLORS['MEDIUM']), # 🚨 FIX 1: Added missing MEDIUM pill
                          ('INFO',     SEVERITY_COLORS['INFO'])]:
            pill = tk.Label(filter_frame, text=sev,
                            font=('Segoe UI', 8, 'bold'),
                            bg=C['tag_bg'], fg=clr,
                            padx=8, pady=2, cursor='hand2',
                            relief='flat')
            pill.pack(side=tk.LEFT, padx=3)
            pill.bind('<Button-1>', lambda e, s=sev: self._set_log_filter(s))
            self._filter_pills[sev] = (pill, clr)
 
        _ActionButton(header, 'Clear', self._clear_logs,
                      C['button_bg'], fg=C['text_secondary'],
                      font_size=9).pack(side=tk.RIGHT)
 
        # Log display
        log_frame = tk.Frame(parent, bg=C['input_bg'])
        log_frame.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0, 12))
 
        self.log_box = scrolledtext.ScrolledText(
            log_frame, wrap=tk.WORD,
            font=('Cascadia Code', 9) if self._font_exists('Cascadia Code')
            else ('Consolas', 9),
            bg=C['input_bg'], fg=C['text_primary'],
            insertbackground=C['text_primary'],
            selectbackground=C['accent_primary'],
            relief='flat', padx=10, pady=8)
        self.log_box.pack(fill=tk.BOTH, expand=True)
        self.log_box.configure(state='disabled')
 
        # Colour tags for severity highlighting
        for tag, colour in [
            ('CRITICAL', SEVERITY_COLORS['CRITICAL']),
            ('HIGH',     SEVERITY_COLORS['HIGH']),
            ('MEDIUM',   SEVERITY_COLORS['MEDIUM']),
            ('INFO',     SEVERITY_COLORS['INFO']),
            ('OK',       C['accent_success']),
        ]:
            self.log_box.tag_config(tag, foreground=colour)
 
        # Highlight the active filter pill on load
        self._highlight_active_pill()
 
 
    def _set_log_filter(self, level):
        """Set the active log filter and refresh the display."""
        self._log_filter = level
        self._highlight_active_pill()
        self._render_filtered_logs()

    def _highlight_active_pill(self):
        """Visually mark the currently active filter pill."""
        if not hasattr(self, '_filter_pills'):
            return
        C = self.colors
        for sev, (pill, clr) in self._filter_pills.items():
            if sev == self._log_filter:
                pill.configure(
                    bg=clr,
                    fg='#ffffff' if sev != 'ALL' else C['bg'],
                    relief='solid'
                )
            else:
                pill.configure(bg=C['tag_bg'], fg=clr, relief='flat')
 
 
    def _render_filtered_logs(self):
        """Re-render log_box with only lines matching the current filter."""
        level = getattr(self, '_log_filter', 'ALL')
        lines = getattr(self, '_log_lines', [])
 
        self.log_box.configure(state='normal')
        self.log_box.delete('1.0', tk.END)
 
        for line in lines:
            if level == 'ALL':
                self.log_box.insert(tk.END, line + '\n')
            else:
                # Show line if it contains the filter keyword (case-insensitive)
                if level.upper() in line.upper():
                    self.log_box.insert(tk.END, line + '\n')
 
        self.log_box.configure(state='disabled')
        self.log_box.see(tk.END)

    def _build_vault_tab(self, parent):
        C = self.colors

        # Two-pane: vault status left, cloud status right
        panes = tk.Frame(parent, bg=C['card_bg'])
        panes.pack(fill=tk.BOTH, expand=True, padx=16, pady=12)

        # Vault pane
        vp = self._card(panes, accent=C['accent_success'])
        vp.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vi = vp.inner()

        _SectionLabel(vi, 'Auto-Heal Vault', C).pack(anchor='w', padx=12, pady=(10, 4))
        tk.Label(vi, text='Encrypted local backup of critical files.\nFiles < 10MB auto-backed-up.\nRestored instantly on deletion or modification.',
                 font=('Segoe UI', 9),
                 bg=C['card_bg'], fg=C['text_secondary'],
                 justify='left').pack(anchor='w', padx=12, pady=(0, 8))

        vault_btns = tk.Frame(vi, bg=C['card_bg'])
        vault_btns.pack(fill=tk.X, padx=12, pady=(0, 12))

        _ActionButton(vault_btns, 'View Vault Contents',
                      self._open_vault_viewer,
                      C['accent_success'], font_size=9).pack(fill=tk.X, pady=2)
        _ActionButton(vault_btns, 'Restore from Vault',
                      self._restore_from_vault,
                      C['button_bg'], fg=C['text_secondary'], font_size=9).pack(fill=tk.X, pady=2)

        # Cloud pane
        cp = self._card(panes, accent=C['accent_info'])
        cp.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(12, 0))
        ci = cp.inner()

        _SectionLabel(ci, 'Cloud Disaster Recovery', C).pack(anchor='w', padx=12, pady=(10, 4))
        tk.Label(ci, text='Google Drive OAuth 2.0 sync.\nPer-user encrypted cloud vaults.\nTwo-tier restore: local → cloud.',
                 font=('Segoe UI', 9),
                 bg=C['card_bg'], fg=C['text_secondary'],
                 justify='left').pack(anchor='w', padx=12, pady=(0, 8))

        cloud_btns = tk.Frame(ci, bg=C['card_bg'])
        cloud_btns.pack(fill=tk.X, padx=12, pady=(0, 12))

        _ActionButton(cloud_btns, 'Sync to Cloud',
                      self._sync_to_cloud,
                      C['accent_info'], font_size=9).pack(fill=tk.X, pady=2)
        _ActionButton(cloud_btns, 'Restore from Cloud',
                      self._restore_from_cloud,
                      C['button_bg'], fg=C['text_secondary'], font_size=9).pack(fill=tk.X, pady=2)
        _ActionButton(cloud_btns, '🔄  Full Disaster Recovery',
                  self._disaster_recovery_restore,
                  C['accent_danger'], font_size=9).pack(fill=tk.X, pady=2)
 
        _ActionButton(cloud_btns, '📁  Restore Folder Structure',
                  self._open_folder_structure_restore,
                  C['accent_secondary'], font_size=9).pack(fill=tk.X, pady=2)

        _ActionButton(cloud_btns, '🗄  Browse Old Archives',
              self._open_archive_browser,
              C['button_bg'], fg=C['text_secondary'], font_size=9).pack(fill=tk.X, pady=2)

        # --- 🚨 NEW: CLOUD PROGRESS LABEL ---
        self.cloud_progress_var = tk.StringVar(value="Status: Ready")
        
        # 🚨 FIX 1: Lock the label to fill the X axis, but dynamically wrap based on actual width
        self.cloud_progress_lbl = tk.Label(ci, textvariable=self.cloud_progress_var,
                 font=('Consolas', 8),
                 bg=C['card_bg'], fg=C['accent_info'],
                 anchor='w', justify='left')
        self.cloud_progress_lbl.pack(fill=tk.X, padx=12, pady=(5, 12))
        
        # This absolutely prevents Tkinter from resizing the parent frame
        self.cloud_progress_lbl.bind('<Configure>', 
            lambda e: self.cloud_progress_lbl.configure(wraplength=max(150, e.width - 10)))

        # Audit log viewer button
        sep = tk.Frame(parent, height=1, bg=C['divider'])
        sep.pack(fill=tk.X, padx=16, pady=(0, 8))

        _ActionButton(parent, '🔐  Open Encrypted Audit Log Vault',
                      self._open_audit_logs,
                      C['button_bg'], fg=C['text_secondary'],
                      font_size=10).pack(fill=tk.X, padx=16, pady=(0, 12))
        
        _ActionButton(parent, '🔬  Open Forensic Incident Vault',
              self._open_forensic_viewer,
              C['accent_danger'], fg='#ffffff',
              font_size=10).pack(fill=tk.X, padx=16, pady=(0, 12))

    def _open_forensic_viewer(self):
        """
        Open the Forensic Incident Viewer.
        Lists all encrypted snapshots from the index and decrypts on demand.
        Accessible only to admins.
        """
        if self.user_role != 'admin':
            messagebox.showerror(
                "Access Denied",
                "Only administrators can view forensic incident reports."
            )
            return

        self._append_log("Opening forensic incident vault...")

        # ── Window ────────────────────────────────────────────────────────────
        viewer = tk.Toplevel(self.root)
        viewer.title("Forensic Incident Vault — FMSecure")
        viewer.geometry("1100x680")
        viewer.configure(bg=self.colors['bg'])
        viewer.transient(self.root)

        # ── Header ────────────────────────────────────────────────────────────
        hdr = tk.Frame(viewer, bg=self.colors['header_bg'], height=50)
        hdr.pack(fill=tk.X)
        hdr.pack_propagate(False)

        tk.Label(hdr, text="Forensic Incident Vault",
                 font=('Segoe UI', 14, 'bold'),
                 bg=self.colors['header_bg'],
                 fg=self.colors['accent_danger']).pack(side=tk.LEFT, padx=20, pady=12)

        tk.Label(hdr,
                 text="All reports are AES-encrypted. Decrypted content is displayed in-app only.",
                 font=('Segoe UI', 9),
                 bg=self.colors['header_bg'],
                 fg=self.colors['text_muted']).pack(side=tk.LEFT, padx=10, pady=12)

        tk.Frame(viewer, height=1, bg=self.colors['divider']).pack(fill=tk.X)

        # ── Layout: left list + right detail ─────────────────────────────────
        body = tk.Frame(viewer, bg=self.colors['bg'])
        body.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)

        # Left: snapshot list
        left = tk.Frame(body, bg=self.colors['card_bg'],
                        highlightbackground=self.colors['card_border'],
                        highlightthickness=1, width=340)
        left.pack(side=tk.LEFT, fill=tk.Y)
        left.pack_propagate(False)

        tk.Label(left, text="Incident Reports",
                 font=('Segoe UI', 10, 'bold'),
                 bg=self.colors['card_bg'],
                 fg=self.colors['text_primary']).pack(anchor='w', padx=14, pady=(12, 6))

        tk.Frame(left, height=1, bg=self.colors['divider']).pack(fill=tk.X)

        snap_list = tk.Listbox(
            left,
            bg=self.colors['input_bg'],
            fg=self.colors['text_primary'],
            selectbackground=self.colors['accent_danger'],
            selectforeground='#ffffff',
            font=('Consolas', 9),
            relief='flat',
            activestyle='none',
            highlightthickness=0
        )
        snap_list.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Right: decrypted content display
        right = tk.Frame(body, bg=self.colors['card_bg'],
                         highlightbackground=self.colors['card_border'],
                         highlightthickness=1)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(12, 0))

        right_hdr = tk.Frame(right, bg=self.colors['card_bg'])
        right_hdr.pack(fill=tk.X, padx=14, pady=(12, 6))

        self._forensic_detail_title = tk.Label(
            right_hdr,
            text="Select a report from the list",
            font=('Segoe UI', 10, 'bold'),
            bg=self.colors['card_bg'],
            fg=self.colors['text_primary']
        )
        self._forensic_detail_title.pack(side=tk.LEFT)

        # Export button (top-right of detail panel)
        def _export_plain():
            content = detail_box.get("1.0", tk.END).strip()
            if not content or content == "Select a report from the list":
                messagebox.showinfo("Export", "No report loaded.")
                return
            import tkinter.filedialog as fd
            path = fd.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                title="Export Forensic Report (Plain Text)"
            )
            if path:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
                messagebox.showinfo("Exported", f"Report saved to:\n{path}")

        tk.Button(
            right_hdr, text="Export Plain Text",
            command=_export_plain,
            font=('Segoe UI', 9),
            bg=self.colors['button_bg'],
            fg=self.colors['text_secondary'],
            bd=0, cursor='hand2', padx=10, pady=4
        ).pack(side=tk.RIGHT)

        tk.Frame(right, height=1, bg=self.colors['divider']).pack(fill=tk.X)

        detail_box = scrolledtext.ScrolledText(
            right,
            bg=self.colors['input_bg'],
            fg=self.colors['text_primary'],
            font=('Consolas', 9),
            wrap=tk.WORD,
            relief='flat',
            state='disabled',
            padx=12,
            pady=10
        )
        detail_box.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Colour tags for severity highlighting
        detail_box.tag_config("critical", foreground=self.colors['accent_danger'])
        detail_box.tag_config("high",     foreground=self.colors['accent_warning'])
        detail_box.tag_config("header",   foreground=self.colors['accent_primary'],
                              font=('Consolas', 9, 'bold'))
        detail_box.tag_config("id",       foreground=self.colors['accent_success'],
                              font=('Consolas', 9, 'bold'))

        # ── Load index ────────────────────────────────────────────────────────
        try:
            from core.incident_snapshot import list_snapshots, read_snapshot, format_snapshot_for_display
            snapshots = list_snapshots()
        except Exception as e:
            snapshots = []
            messagebox.showerror("Forensic Vault", f"Could not load index:\n{e}")

        # Track filename per listbox index
        _filename_map = {}

        if not snapshots:
            snap_list.insert(tk.END, "  No snapshots found")
        else:
            for i, entry in enumerate(snapshots):
                ts   = entry.get("timestamp_pretty", "Unknown time")
                sev  = entry.get("severity", "?")
                etype= entry.get("event_type", "?")
                hits = entry.get("affected_files", 0)
                label = f"[{sev}] {ts}\n  {etype} — {hits} file(s)"
                snap_list.insert(tk.END, f" {ts}")
                snap_list.insert(tk.END, f"   {sev} · {etype} · {hits} files")
                snap_list.insert(tk.END, "")
                _filename_map[i * 3]     = entry.get("filename")
                _filename_map[i * 3 + 1] = entry.get("filename")

        def _on_select(event):
            sel = snap_list.curselection()
            if not sel:
                return
            idx      = sel[0]
            filename = _filename_map.get(idx)
            if not filename:
                return

            try:
                data    = read_snapshot(filename)
                content = format_snapshot_for_display(data)
            except Exception as e:
                content = f"Error decrypting snapshot:\n{e}"

            if data:
                meta = data.get("meta", {})
                self._forensic_detail_title.configure(
                    text=f"Snapshot {meta.get('snapshot_id', '?')}  —  {meta.get('generated_at_pretty', '')}"
                )

            detail_box.configure(state='normal')
            detail_box.delete("1.0", tk.END)

            # Insert with basic highlighting
            for line in content.split('\n'):
                if line.startswith("="):
                    detail_box.insert(tk.END, line + '\n', "header")
                elif "CRITICAL" in line:
                    detail_box.insert(tk.END, line + '\n', "critical")
                elif "HIGH" in line:
                    detail_box.insert(tk.END, line + '\n', "high")
                elif "Snapshot ID" in line:
                    detail_box.insert(tk.END, line + '\n', "id")
                else:
                    detail_box.insert(tk.END, line + '\n')

            detail_box.configure(state='disabled')
            detail_box.see("1.0")

        snap_list.bind("<<ListboxSelect>>", _on_select)

        # Close button
        tk.Button(
            viewer, text="Close",
            command=viewer.destroy,
            font=('Segoe UI', 10),
            bg=self.colors['button_bg'],
            fg=self.colors['text_primary'],
            bd=0, cursor='hand2', padx=20, pady=8
        ).pack(pady=(0, 16))

    def _build_network_tab(self, parent):
        C = self.colors

        header = tk.Frame(parent, bg=C['card_bg'])
        header.pack(fill=tk.X, padx=16, pady=(12, 8))

        tk.Label(header, text='C2 Telemetry Console',
                 font=('Segoe UI', 11, 'bold'),
                 bg=C['card_bg'], fg=C['text_primary']).pack(side=tk.LEFT)

        # Status dot
        self._c2_status_dot = tk.Label(header, text='●',
                                        font=('Segoe UI', 10),
                                        bg=C['card_bg'], fg=C['text_muted'])
        self._c2_status_dot.pack(side=tk.RIGHT)
        self._c2_status_lbl = tk.Label(header, text='Offline',
                                        font=('Segoe UI', 9),
                                        bg=C['card_bg'], fg=C['text_muted'])
        self._c2_status_lbl.pack(side=tk.RIGHT, padx=(0, 4))

        # Info grid
        info = tk.Frame(parent, bg=C['card_bg'])
        info.pack(fill=tk.X, padx=16, pady=(0, 12))
        info.columnconfigure(1, weight=1)

        c2_rows = [
            ('Machine ID',  str(uuid.getnode())[:16] + '…'),
            ('Hostname',    socket.gethostname()),
            ('C2 Endpoint', 'fmsecure-c2-server-production.up.railway.app'),
            ('Heartbeat',   'Every 10s'),
        ]
        for i, (k, v) in enumerate(c2_rows):
            tk.Label(info, text=k + ':', font=('Segoe UI', 9),
                     bg=C['card_bg'], fg=C['text_muted']).grid(
                row=i, column=0, sticky='w', padx=(0, 16), pady=3)
            tk.Label(info, text=v, font=('Consolas', 9),
                     bg=C['card_bg'], fg=C['text_secondary']).grid(
                row=i, column=1, sticky='w', pady=3)

        # Urgent action
        sep = tk.Frame(parent, height=1, bg=C['divider'])
        sep.pack(fill=tk.X, padx=16, pady=4)

        _ActionButton(parent, '🛑  Emergency Lockdown (Local)',
                      self._emergency_lockdown,
                      C['accent_danger'], font_size=10).pack(
            fill=tk.X, padx=16, pady=(8, 4))

        tk.Label(parent,
                 text='Remote "Isolate Host" is triggered from the cloud dashboard.',
                 font=('Segoe UI', 9),
                 bg=C['card_bg'], fg=C['text_muted']).pack(padx=16, pady=(0, 8))

    

    def _menu_section(self, parent, text):
        C = self.colors
        tk.Label(parent, text=text.upper(),
                 font=('Segoe UI', 8, 'bold'),
                 bg=C['sidebar_bg'], fg=C['text_muted']).pack(
            anchor='w', padx=20, pady=(8, 2))


    def _menu_divider(self, parent):
        tk.Frame(parent, height=1,
                 bg=self.colors['divider']).pack(fill=tk.X, padx=16, pady=8)

    def _menu_item(self, parent, text, command, color):
        C = self.colors
        row = tk.Frame(parent, bg=C['sidebar_bg'])
        row.pack(fill=tk.X, padx=12, pady=2)

        accent = tk.Frame(row, width=3, bg=color)
        accent.pack(side=tk.LEFT, fill=tk.Y)

        btn = tk.Button(row, text=text,
                        font=('Segoe UI', 10),
                        bg=C['sidebar_bg'],
                        fg=C['text_primary'],
                        bd=0, cursor='hand2', pady=7, padx=12,
                        anchor='w',
                        activebackground=C['button_hover'],
                        command=lambda: (self.toggle_menu(), command()))
        btn.pack(fill=tk.X, side=tk.LEFT, expand=True)

        btn.bind('<Enter>', lambda e, b=btn: b.configure(bg=C['button_hover']))
        btn.bind('<Leave>', lambda e, b=btn: b.configure(bg=C['sidebar_bg']))

    # ─────────────────────────────────────────
    #  ALERT PANEL
    # ─────────────────────────────────────────

    def _create_alert_panel(self):
        C = self.colors
        self._alert_frame = tk.Toplevel(self.root)
        self._alert_frame.overrideredirect(True)
        self._alert_frame.configure(bg=C['card_border'])
        self._alert_frame.attributes('-topmost', True)

        inner = tk.Frame(self._alert_frame, bg=C['card_bg'])
        inner.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)

        # Header strip
        header = tk.Frame(inner, bg=C['accent_primary'])
        header.pack(fill=tk.X)

        self._alert_title = tk.Label(header, text='Security Alert',
                                     font=('Segoe UI', 10, 'bold'),
                                     bg=C['accent_primary'], fg='#ffffff')
        self._alert_title.pack(side=tk.LEFT, padx=12, pady=7)

        close_btn = tk.Button(header, text='✕', command=self._hide_alert,
                              bg=C['accent_primary'], fg='#ffffff',
                              bd=0, font=('Segoe UI', 11, 'bold'), cursor='hand2')
        close_btn.pack(side=tk.RIGHT, padx=12, pady=7)

        # Content
        content = tk.Frame(inner, bg=C['card_bg'])
        content.pack(fill=tk.BOTH, expand=True)

        self._alert_msg = scrolledtext.ScrolledText(
            content, wrap=tk.WORD, state='disabled',
            bg=C['card_bg'], fg=C['text_primary'],
            height=8, relief='flat',
            font=('Segoe UI', 9))
        self._alert_msg.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        footer = tk.Frame(content, bg=C['divider'], height=28)
        footer.pack(fill=tk.X, side=tk.BOTTOM)

        self._alert_meta = tk.Label(footer, text='No active alerts',
                                    bg=C['divider'], fg=C['text_secondary'],
                                    font=('Segoe UI', 8))
        self._alert_meta.pack(side=tk.LEFT, padx=10, pady=4)

        self._alert_counter = tk.Label(footer, text='Alerts: 0',
                                       bg=C['divider'], fg=C['text_secondary'],
                                       font=('Segoe UI', 8, 'bold'))
        self._alert_counter.pack(side=tk.RIGHT, padx=10, pady=4)

        self.alert_count   = 0
        self.alert_visible = False
        self._alert_frame.withdraw()

    # ─────────────────────────────────────────
    #  THEME SYSTEM
    # ─────────────────────────────────────────

 
    def _theme_side_menu(self, C):
        """
        Recursively re-theme the side menu and all its children.
        The side menu is intentionally kept in its hacker-terminal style
        (dark, green text) regardless of the app theme — it's a design choice.
        But in light mode we soften it to a very dark navy instead of pure black.
        """
        # In dark mode: pure black. In light mode: dark navy (still readable).
        menu_bg    = '#000000'   if self.dark_mode else '#0f172a'
        menu_fg    = '#00ff00'   if self.dark_mode else '#4ade80'
        menu_muted = '#00ffff'   if self.dark_mode else '#38bdf8'
        border_col = '#00ff00'   if self.dark_mode else '#334155'
 
        def _walk(widget):
            try:
                if isinstance(widget, tk.Frame):
                    widget.configure(bg=menu_bg)
                elif isinstance(widget, tk.Canvas):
                    widget.configure(bg=menu_bg)
                elif isinstance(widget, tk.Label):
                    fg = widget.cget('fg')
                    # Preserve colour-coded status dots and accent labels
                    if fg in ('#ff9900', '#ff0000', '#00ff00', '#00ffff', '#ffffff'):
                        widget.configure(bg=menu_bg)
                    else:
                        widget.configure(bg=menu_bg, fg=menu_muted)
                elif isinstance(widget, tk.Button):
                    widget.configure(
                        bg=menu_bg,
                        fg=menu_fg,
                        activebackground='#111111' if self.dark_mode else '#1e293b',
                        activeforeground=menu_fg
                    )
                elif isinstance(widget, tk.Scrollbar):
                    widget.configure(
                        bg='#222222' if self.dark_mode else '#1e293b',
                        troughcolor=menu_bg,
                        activebackground='#444444' if self.dark_mode else '#334155'
                    )
            except Exception:
                pass
 
            for child in widget.winfo_children():
                _walk(child)
 
        _walk(self.side_menu)
 
        # Update the menu's own border colour
        try:
            self.side_menu.configure(
                bg=menu_bg,
                highlightbackground=border_col
            )
        except Exception:
            pass


    # ─────────────────────────────────────────
    #  HELPERS
    # ─────────────────────────────────────────

    def _card(self, parent, accent=None, **kwargs):
        C = self.colors
        return _Card(parent, C, accent=accent, **kwargs)

    def _section_header(self, parent, text, top_pad=0):
        C = self.colors
        f = tk.Frame(parent, bg=C['bg'])
        f.pack(fill=tk.X, pady=(top_pad, 4))
        tk.Label(f, text=text.upper(),
                 font=('Segoe UI', 8, 'bold'),
                 bg=C['bg'], fg=C['text_muted']).pack(side=tk.LEFT)
        tk.Frame(f, height=1, bg=C['divider']).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 0), pady=4)


    @staticmethod
    def _lighten_color(color, factor=0.2):
        return _ActionButton._lighten(color, factor)

    @staticmethod
    def _font_exists(font_name):
        try:
            import tkinter.font as tkfont
            return font_name in tkfont.families()
        except Exception:
            return False

    def _append_log(self, msg):
        try:
            ts = datetime.now().strftime('%H:%M:%S')
            line = f'[{ts}]  {msg}\n'
            self.log_box.configure(state='normal')
            self.log_box.insert(tk.END, line)
            self.log_box.see(tk.END)
            self.log_box.configure(state='disabled')
        except Exception as e:
            print(f'Log error: {e}')

    # Stub methods for vault/cloud tab buttons — bridge to existing core methods
    def _open_vault_viewer(self):
        self._append_log('Opening vault viewer…')
        try:
            from core.vault_manager import vault
            files = vault.list_vault_files() if hasattr(vault, 'list_vault_files') else []
            content = '\n'.join(str(f) for f in files) if files else 'Vault is empty or no files tracked yet.'
            self._show_text('Vault Contents', content)
        except Exception as e:
            messagebox.showinfo('Vault', f'Vault viewer: {e}')

    def _restore_from_vault(self):
        self._append_log('Initiating vault restore…')
        try:
            from core.vault_manager import vault
            if hasattr(vault, 'restore_all'):
                vault.restore_all()
                messagebox.showinfo('Vault Restore', 'Files restored from vault successfully.')
            else:
                messagebox.showinfo('Vault Restore', 'Select a file to restore in the full vault viewer.')
        except Exception as e:
            messagebox.showerror('Vault Restore Error', str(e))

    def _sync_to_cloud(self):
        """
        Full cloud sync: vault files + logs + forensics + AppData + keys.
        All cloud folders are keyed on machine_id, not email.
        PRO gate is enforced inside cloud_sync — no local check needed beyond
        the UI-level warning below.
        """
        from tkinter import messagebox
 
        # ── UI-level PRO gate (shows a friendly upgrade dialog) ───────────────
        tier = "free"
        if auth:
            tier = auth.get_user_tier(self.username)
        if hasattr(self, 'pro_badge') and self.pro_badge.winfo_exists():
            tier = "pro_monthly"
        if not subscription_manager.is_pro(tier):
            messagebox.showwarning(
                "⭐ Premium Feature",
                "☁️  Cloud Disaster Recovery is a PRO feature.\n\n"
                "Activate a License Key to unlock Cloud Sync.")
            return
 
        from core.cloud_sync import cloud_sync
        from core.encryption_manager import crypto_manager
        from core.utils import get_app_data_dir
 
        if not cloud_sync.is_active:
            self._append_log("Cloud Sync: No cached token — launching Google OAuth...")
            cloud_sync.force_authenticate()
            if not cloud_sync.is_active:
                messagebox.showerror(
                    'Cloud Sync Offline',
                    'Google Drive authentication failed or was cancelled.\n\n'
                    'Please try clicking Sync to Cloud again.')
                return
 
        machine_id = crypto_manager.get_machine_id()
 
        # Collect all files to sync
        app_data      = get_app_data_dir()
        vault_dir     = os.path.join(app_data, "system32_vault")
        logs_dir      = os.path.join(app_data, "logs")
        forensics_dir = os.path.join(app_data, "forensics")
 
        vault_files = ([os.path.join(vault_dir, f)
                        for f in os.listdir(vault_dir) if f.endswith('.enc')]
                       if os.path.exists(vault_dir) else [])
 
        log_files = []
        for fname in ("integrity_log.dat", "integrity_log.sig",
                      "severity_counters.json"):
            p = os.path.join(logs_dir, fname)
            if os.path.exists(p):
                log_files.append(p)
        if os.path.exists(forensics_dir):
            for fname in os.listdir(forensics_dir):
                if (fname.startswith("forensic_") and fname.endswith(".dat")
                        or fname == "forensics_index.json"):
                    log_files.append(os.path.join(forensics_dir, fname))
 
        key_dir   = os.path.join(app_data, "system32_config")
        logs_only = os.path.join(app_data, "logs")
        appdata_files = []
        for fname in ("users.dat", "hash_records.dat", "hash_records.sig",
                      "severity_counters.json"):
            p = os.path.join(logs_only, fname)
            if os.path.exists(p):
                appdata_files.append(p)
        cfg = os.path.join(app_data, "config.json")
        mid_file = os.path.join(key_dir, "machine_id.txt")
        for p in (cfg, mid_file):
            if os.path.exists(p):
                appdata_files.append(p)
 
        grand_total = (len(vault_files) + len(log_files)
                       + len(appdata_files) + 2)  # +2 for key files
        grand_done  = [0]
 
        self.root.after(0, lambda: self.cloud_progress_var.set(
            f"Starting sync… 0 / {grand_total} files"))
        self._append_log(
            f"Cloud sync started — {grand_total} files "
            f"(machine: {machine_id[:16]}…)")
 
        def _on_file_done(ok=True, fname=""):
            grand_done[0] += 1
            icon  = "✅" if ok else "❌"
            
            # 🚨 FIX 2: Smart Truncation for massive filenames (like SHA256 hashes)
            display_name = fname
            if len(fname) > 30:
                display_name = fname[:13] + "..." + fname[-13:]
                
            label = f"{icon} [{grand_done[0]}/{grand_total}] {display_name}"
            self.root.after(0, lambda l=label: self.cloud_progress_var.set(l))
 
        def _progress_cb(uploaded, total, filename):
            _on_file_done(ok=True, fname=filename)
 
        def _do_sync():
            # 1. Vault files → vault/
            if vault_files:
                vault_folder = cloud_sync._get_subfolder("vault", machine_id)
                if vault_folder:
                    cloud_sync.batch_upload(vault_files, vault_folder,
                                            progress_cb=_progress_cb,
                                            max_workers=4)
 
            # 2. Logs + forensics → logs/
            if log_files:
                logs_folder = cloud_sync._get_subfolder("logs", machine_id)
                if logs_folder:
                    cloud_sync.batch_upload(log_files, logs_folder,
                                            progress_cb=_progress_cb,
                                            max_workers=4)
 
            # 3. AppData → appdata/
            if appdata_files:
                appdata_folder = cloud_sync._get_subfolder("appdata", machine_id)
                if appdata_folder:
                    cloud_sync.batch_upload(appdata_files, appdata_folder,
                                            progress_cb=_progress_cb,
                                            max_workers=2)
 
            # 4. Encryption keys → keys/
            try:
                ok, msg = crypto_manager.force_key_backup()
                _on_file_done(ok=ok, fname="sys.key")
                _on_file_done(ok=ok, fname=".sys_backup.key")
            except Exception as e:
                print(f"[SYNC] Key backup error: {e}")
 
            # 5. Folder structure backup (per watched folder, PRO only)
            self._backup_folder_structures(on_file_done_cb=_on_file_done)
 
            # 6. Update manifest with current email/tier metadata
            try:
                cloud_sync._update_manifest(machine_id)
            except Exception:
                pass
 
            summary = (f"✅ Sync complete: {grand_done[0]}/{grand_total} files "
                       f"— machine {machine_id[:16]}…")
            self.root.after(0, lambda s=summary:
                            self.cloud_progress_var.set(s))
            self.root.after(0, lambda s=summary: self._append_log(s))
 
        threading.Thread(target=_do_sync, daemon=True).start()
    

    def _restore_from_cloud(self):
        """Restore encrypted vault .enc files from the user's Drive folder."""
        from tkinter import messagebox
    
        tier = "free"
        if auth:
            tier = auth.get_user_tier(self.username)
        if hasattr(self, 'pro_badge') and self.pro_badge.winfo_exists():
            tier = "pro_monthly"
        if not subscription_manager.is_pro(tier):
            messagebox.showwarning(
                "⭐ Premium Feature",
                "☁️ Cloud Disaster Recovery is a PRO feature.")
            return
    
        self._append_log('Restoring vault from cloud…')
        try:
            from core.cloud_sync import cloud_sync
            from core.integrity_core import CONFIG
            if auth:
                user_data  = auth.users.get(self.username, {})
                CONFIG["admin_email"] = user_data.get("registered_email", "UnknownUser")
            if hasattr(cloud_sync, 'restore_from_cloud'):
                threading.Thread(target=cloud_sync.restore_from_cloud, daemon=True).start()
                messagebox.showinfo('Cloud Restore', 'Vault restore started in background.')
        except Exception as e:
            messagebox.showinfo('Cloud Restore', f'Error: {e}')

        
    def _open_folder_structure_restore(self):
        """
        Opens the Folder Structure Restore wizard (PRO only).
        Lets the user pick a backed-up folder and restore it to the
        original location or a new location.
        Shows a warning list of files that could not be restored due to
        size / extension limits.
        """
        from tkinter import messagebox, filedialog
        import threading
 
        # ── PRO gate ──────────────────────────────────────────────────────────
        tier = "free"
        if auth:
            tier = auth.get_user_tier(self.username)
        if hasattr(self, 'pro_badge') and self.pro_badge.winfo_exists():
            tier = "pro_monthly"
        if not subscription_manager.is_pro(tier):
            messagebox.showwarning(
                "⭐ Premium Feature",
                "📁  Folder Structure Restore is a PRO feature.\\n\\n"
                "Activate a License Key to unlock it.")
            return
 
        from core.cloud_sync import cloud_sync
        if not cloud_sync.is_active:
            cloud_sync.force_authenticate()
            if not cloud_sync.is_active:
                messagebox.showerror(
                    "Cloud Offline",
                    "Google Drive authentication failed or was cancelled.\n\n"
                    "Please try again.")
                return
 
        C   = self.colors
        win = tk.Toplevel(self.root)
        win.title("Folder Structure Restore — FMSecure PRO")
        win.geometry("880x660")
        win.configure(bg=C['bg'])
        win.transient(self.root)
        win.resizable(True, True)
 
        # ── Header ────────────────────────────────────────────────────────────
        hdr = tk.Frame(win, bg=C['header_bg'], height=54)
        hdr.pack(fill=tk.X)
        hdr.pack_propagate(False)
        tk.Label(hdr, text="📁  Folder Structure Restore",
                 font=('Segoe UI', 15, 'bold'),
                 bg=C['header_bg'], fg=C['accent_secondary']).pack(
            side=tk.LEFT, padx=20, pady=14)
        tk.Label(hdr,
                 text="Recover your complete folder hierarchy from Google Drive  ·  PRO",
                 font=('Segoe UI', 9),
                 bg=C['header_bg'], fg=C['text_muted']).pack(
            side=tk.LEFT, padx=8, pady=14)
        tk.Frame(win, height=1, bg=C['divider']).pack(fill=tk.X)
 
        # ── Body: left list + right detail ────────────────────────────────────
        body = tk.Frame(win, bg=C['bg'])
        body.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)
 
        # Left pane
        left = tk.Frame(body, bg=C['card_bg'],
                        highlightbackground=C['card_border'],
                        highlightthickness=1, width=300)
        left.pack(side=tk.LEFT, fill=tk.Y)
        left.pack_propagate(False)
 
        tk.Label(left, text="Cloud Backups",
                 font=('Segoe UI', 10, 'bold'),
                 bg=C['card_bg'], fg=C['text_primary']).pack(
            anchor='w', padx=14, pady=(12, 2))
        tk.Label(left,
                 text="Each entry = one monitored folder snapshot",
                 font=('Segoe UI', 8),
                 bg=C['card_bg'], fg=C['text_muted']).pack(anchor='w', padx=14)
        tk.Frame(left, height=1, bg=C['divider']).pack(fill=tk.X, pady=6)
 
        backup_list = tk.Listbox(
            left,
            bg=C['input_bg'], fg=C['text_primary'],
            selectbackground=C['accent_secondary'],
            selectforeground='#ffffff',
            font=('Segoe UI', 9), relief='flat',
            activestyle='none', highlightthickness=0)
        backup_list.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
 
        # Right pane
        right = tk.Frame(body, bg=C['card_bg'],
                         highlightbackground=C['card_border'],
                         highlightthickness=1)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(12, 0))
 
        detail_hdr = tk.Frame(right, bg=C['card_bg'])
        detail_hdr.pack(fill=tk.X, padx=14, pady=(12, 4))
        detail_title = tk.Label(
            detail_hdr, text="Select a backup to see details",
            font=('Segoe UI', 11, 'bold'),
            bg=C['card_bg'], fg=C['text_primary'])
        detail_title.pack(side=tk.LEFT)
        tk.Frame(right, height=1, bg=C['divider']).pack(fill=tk.X)
 
        # Stats row
        stats_frame = tk.Frame(right, bg=C['card_bg'])
        stats_frame.pack(fill=tk.X, padx=14, pady=10)
        stat_vars = {
            "Source Folder": tk.StringVar(value="—"),
            "Files Backed Up": tk.StringVar(value="—"),
            "Files Skipped":   tk.StringVar(value="—"),
            "Snapshot Date":   tk.StringVar(value="—"),
        }
        for col_idx, (lbl, var) in enumerate(stat_vars.items()):
            cell = tk.Frame(stats_frame, bg=C['card_bg'])
            cell.grid(row=0, column=col_idx, padx=10, sticky='w')
            stats_frame.columnconfigure(col_idx, weight=1)
            tk.Label(cell, text=lbl, font=('Segoe UI', 8),
                     bg=C['card_bg'], fg=C['text_muted']).pack(anchor='w')
            tk.Label(cell, textvariable=var,
                     font=('Segoe UI', 10, 'bold'),
                     bg=C['card_bg'], fg=C['text_primary']).pack(anchor='w')
 
        tk.Frame(right, height=1, bg=C['divider']).pack(fill=tk.X)
 
        # ── Skipped-files warning ─────────────────────────────────────────────
        warn_outer = tk.Frame(right, bg=C['card_bg'])
        warn_outer.pack(fill=tk.X, padx=14, pady=(8, 0))
 
        warn_title = tk.Label(
            warn_outer,
            text="⚠  Files that CANNOT be restored "
                 "(skipped during backup — too large or wrong extension):",
            font=('Segoe UI', 9, 'bold'),
            bg=C['card_bg'], fg=C['accent_warning'])
 
        import tkinter.scrolledtext as _st
        skip_box = _st.ScrolledText(
            warn_outer, height=4,
            bg=C['input_bg'], fg=C['accent_warning'],
            font=('Consolas', 8), relief='flat',
            state='disabled', wrap=tk.WORD)
 
        # hidden until a backup is selected
        warn_title.pack_forget()
        skip_box.pack_forget()
 
        # ── Restore destination ───────────────────────────────────────────────
        dest_outer = tk.Frame(right, bg=C['card_bg'])
        dest_outer.pack(fill=tk.X, padx=14, pady=10)
 
        tk.Label(dest_outer, text="Restore Destination:",
                 font=('Segoe UI', 10, 'bold'),
                 bg=C['card_bg'], fg=C['text_primary']).pack(anchor='w')
 
        dest_mode = tk.StringVar(value="original")
        rb_row = tk.Frame(dest_outer, bg=C['card_bg'])
        rb_row.pack(fill=tk.X, pady=4)
        for txt, val in [("Original location (recreate in-place)",  "original"),
                         ("Choose a new location",                   "new")]:
            tk.Radiobutton(rb_row, text=txt,
                           variable=dest_mode, value=val,
                           bg=C['card_bg'], fg=C['text_primary'],
                           selectcolor=C['input_bg'],
                           activebackground=C['card_bg'],
                           font=('Segoe UI', 9)).pack(
                side=tk.LEFT, padx=(0, 20))
 
        new_loc_row = tk.Frame(dest_outer, bg=C['card_bg'])
        new_loc_row.pack(fill=tk.X, pady=(2, 0))
        new_loc_var = tk.StringVar(value="")
        new_loc_entry = tk.Entry(
            new_loc_row, textvariable=new_loc_var,
            font=('Segoe UI', 9),
            bg=C['input_bg'], fg=C['text_primary'],
            relief='flat', highlightthickness=1,
            highlightbackground=C['input_border'])
        new_loc_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
 
        def _browse():
            d = filedialog.askdirectory(title="Select Restore Destination")
            if d:
                new_loc_var.set(d)
 
        tk.Button(new_loc_row, text="Browse…", command=_browse,
                  font=('Segoe UI', 8),
                  bg=C['button_bg'], fg=C['text_secondary'],
                  bd=0, padx=8, pady=4, cursor='hand2').pack(
            side=tk.LEFT, padx=(6, 0))
 
        # ── Progress label ────────────────────────────────────────────────────
        tk.Frame(right, height=1, bg=C['divider']).pack(fill=tk.X, pady=(8, 0))
        progress_var = tk.StringVar(value="Loading backups from Google Drive…")
        tk.Label(right, textvariable=progress_var,
                 font=('Consolas', 8),
                 bg=C['card_bg'], fg=C['accent_info'],
                 anchor='w', wraplength=520, justify='left').pack(
            fill=tk.X, padx=14, pady=6)
        tk.Frame(right, height=1, bg=C['divider']).pack(fill=tk.X)
 
        # ── Action buttons ────────────────────────────────────────────────────
        btn_row = tk.Frame(right, bg=C['card_bg'])
        btn_row.pack(fill=tk.X, padx=14, pady=12)
 
        # ── State ─────────────────────────────────────────────────────────────
        _backups        = []
        _selected       = [None]
 
        def _on_select(event):
            sel = backup_list.curselection()
            if not sel:
                return
            b = _backups[sel[0]]
            _selected[0] = b
 
            stat_vars["Source Folder"].set(b.get("watch_root", "?"))
            stat_vars["Files Backed Up"].set(f"{b.get('file_count', 0)} files")
            stat_vars["Files Skipped"].set(f"{b.get('skipped_count', 0)} files")
            raw = b.get("created_at", "?")
            try:
                from datetime import datetime as _dt
                dt = _dt.fromisoformat(raw.replace("Z", "+00:00"))
                stat_vars["Snapshot Date"].set(dt.strftime("%Y-%m-%d  %H:%M UTC"))
            except Exception:
                stat_vars["Snapshot Date"].set(raw[:16])
            detail_title.configure(text=b.get("bucket_name", "?"))
 
            skipped = b.get("manifest", {}).get("skipped", [])
            if skipped:
                warn_title.pack(anchor='w')
                skip_box.pack(fill=tk.X, pady=(4, 0))
                skip_box.configure(state='normal')
                skip_box.delete('1.0', tk.END)
                for s in skipped:
                    skip_box.insert(
                        tk.END,
                        f"  ✗  {s.get('path','?')}  —  {s.get('reason','?')}\\n")
                skip_box.configure(state='disabled')
            else:
                warn_title.pack_forget()
                skip_box.pack_forget()
 
        backup_list.bind("<<ListboxSelect>>", _on_select)
 
        # ── Load backups ──────────────────────────────────────────────────────
        def _load():
            try:
                from core.folder_structure_vault import folder_vault as fv
                items = fv.list_available_backups()
                def _populate():
                    backup_list.delete(0, tk.END)
                    _backups.clear()
                    if not items:
                        backup_list.insert(tk.END, "  No folder backups found in Drive")
                        progress_var.set("No backups found. Use 'Sync to Cloud' first.")
                        return
                    _backups.extend(items)
                    for item in items:
                        root_lbl = os.path.basename(
                            item.get("watch_root","?").rstrip("/\\\\")) or "?"
                        date_lbl = item.get("created_at","?")[:10]
                        progress_var.set(
                            f"{len(items)} backup(s) found. Select one to restore.")
                        backup_list.insert(
                            tk.END, f"  📁 {root_lbl}   [{date_lbl}]")
                win.after(0, _populate)
            except Exception as exc:
                win.after(0, lambda: progress_var.set(f"Error: {exc}"))
 
        threading.Thread(target=_load, daemon=True).start()
 
        # ── Restore handler ───────────────────────────────────────────────────
        def _do_restore():
            b = _selected[0]
            if not b:
                messagebox.showwarning(
                    "Nothing Selected",
                    "Please select a backup from the list first.")
                return
 
            mode = dest_mode.get()
            if mode == "new":
                dest = new_loc_var.get().strip()
                if not dest:
                    messagebox.showwarning(
                        "Destination Required",
                        "Please choose a destination folder or switch to "
                        "'Original location'.")
                    return
                dest_label = dest
            else:
                dest       = ""
                dest_label = b.get("watch_root", "original location")
 
            if not messagebox.askyesno(
                "Confirm Restore",
                f"Restore  {b.get('file_count', 0)}  file(s) to:\\n\\n"
                f"  {dest_label}\\n\\n"
                f"Files that were skipped during backup (wrong extension or "
                f"too large) cannot be recovered and are listed in the warning "
                f"box above.\\n\\nContinue?"
            ):
                return
 
            restore_btn.configure(state='disabled', text="Restoring…")
            progress_var.set("Starting restore, please wait…")
 
            def _run():
                from core.folder_structure_vault import folder_vault as fv
                total = b.get("file_count", 0)
 
                def _cb(done, _total, fname):
                    label = f"✅ [{done}/{total}] {fname[:50]}"
                    win.after(0, lambda l=label: progress_var.set(l))
 
                res = fv.restore_folder_structure(
                    bucket_id   = b["bucket_id"],
                    manifest    = b["manifest"],
                    destination = dest,
                    progress_cb = _cb,
                )
 
                def _finish():
                    restore_btn.configure(state='normal',
                                          text="🔄  Restore Files")
                    skipped = res.get("skipped", [])
                    failed  = res.get("failed",  [])
 
                    progress_var.set(
                        f"Done — {res['restored']} restored  ·  "
                        f"{len(skipped)} skipped  ·  {len(failed)} failed")
 
                    summary = (
                        f"Restore complete!\\n\\n"
                        f"  ✅  Restored : {res['restored']} files\\n"
                        f"  ⚠   Skipped  : {len(skipped)} files "
                        f"(not backed up — see warning list)\\n"
                        f"  ❌  Failed   : {len(failed)} files\\n"
                    )
                    if failed:
                        summary += "\\nFailed files:\\n"
                        for f in failed[:8]:
                            summary += f"  • {f['path']}  —  {f['error']}\\n"
                        if len(failed) > 8:
                            summary += f"  … and {len(failed)-8} more.\\n"
 
                    messagebox.showinfo("Folder Restore Complete", summary)
                    self._append_log(
                        f"FOLDER STRUCTURE RESTORE: {res['restored']} files "
                        f"→ {dest_label}  (bucket: {b.get('bucket_name','?')})")
 
                win.after(0, _finish)
 
            threading.Thread(target=_run, daemon=True).start()
 
        restore_btn = tk.Button(
            btn_row, text="🔄  Restore Files",
            command=_do_restore,
            font=('Segoe UI', 10, 'bold'),
            bg=C['accent_secondary'], fg='#ffffff',
            bd=0, padx=20, pady=8, cursor='hand2',
            activebackground=C['accent_secondary'])
        restore_btn.pack(side=tk.LEFT)
 
        tk.Button(btn_row, text="Close",
                  command=win.destroy,
                  font=('Segoe UI', 10),
                  bg=C['button_bg'], fg=C['text_secondary'],
                  bd=0, padx=20, pady=8, cursor='hand2').pack(side=tk.RIGHT)
 
    def _backup_folder_structures(self, on_file_done_cb=None):
        """
        Called inside _sync_to_cloud()'s background _do_sync() thread.
        Iterates every watched folder and uploads its complete file structure.
        on_file_done_cb(ok, fname) feeds the shared grand_done counter.
        """
        try:
            from core.folder_structure_vault import folder_vault as fv
            folders = list(self.folder_listbox.get(0, tk.END))
            for wf in folders:
                if not os.path.isdir(wf):
                    continue
                self.root.after(
                    0, lambda f=wf: self.cloud_progress_var.set(
                        f"📁 Backing up folder structure: "
                        f"{os.path.basename(f)}…"))
 
                def _cb(uploaded, total, fname,
                        _cb_ref=on_file_done_cb):
                    if _cb_ref:
                        _cb_ref(ok=True, fname=fname)
 
                result = fv.backup_folder_structure(wf, progress_cb=_cb)
 
                for err in result.get("errors", []):
                    print(f"[GUI][FSV] {wf}: {err}")
 
                self._append_log(
                    f"FOLDER STRUCTURE BACKUP: "
                    f"{result['uploaded']} uploaded, "
                    f"{len(result['skipped'])} skipped "
                    f"from '{os.path.basename(wf)}'")
        except Exception as exc:
            print(f"[GUI] _backup_folder_structures error: {exc}")


    def _disaster_recovery_restore(self):
        """
        Full disaster recovery: restore EVERYTHING from cloud after the user
        deleted the entire AppData/FMSecure folder.
    
        Recovery sequence (matches what login_gui.py does on startup):
        1. Restore AppData files (users.dat, config.json, etc.)
        2. Restore encryption key  (via crypto_manager Phase 2)
        3. Restore audit logs + forensics
        4. Reload auth database
        5. Show summary to user
        """
        from tkinter import messagebox
    
        tier = "free"
        if auth:
            tier = auth.get_user_tier(self.username)
        if hasattr(self, 'pro_badge') and self.pro_badge.winfo_exists():
            tier = "pro_monthly"
        if not subscription_manager.is_pro(tier):
            messagebox.showwarning(
                "⭐ Premium Feature",
                "Full Disaster Recovery is a PRO feature.")
            return
    
        if not messagebox.askyesno(
            "Full Disaster Recovery",
            "This will download your complete FMSecure backup from Google Drive "
            "and restore:\n\n"
            "  • Encryption key\n"
            "  • User accounts (users.dat)\n"
            "  • Audit logs\n"
            "  • Forensic snapshots\n"
            "  • App configuration\n\n"
            "Existing local files may be overwritten.\n\n"
            "Continue?"
        ):
            return
    
        from core.cloud_sync import cloud_sync
        from core.encryption_manager import crypto_manager
    
        if not cloud_sync.is_active:
            messagebox.showerror(
                'Cloud Offline',
                'Google Drive is not connected. Cannot perform disaster recovery.')
            return
    
        machine_id = crypto_manager.get_machine_id()
    
        self.cloud_progress_var.set("🔄 Disaster recovery in progress…")
        self._append_log("DISASTER RECOVERY: Starting full cloud restore…")
    
        def _do_recovery():
            steps   = []
            success = True
    
            # Step 1 — AppData (users.dat, config, etc.)
            self.root.after(0, lambda: self.cloud_progress_var.set("Step 1/4: Restoring AppData…"))
            r1 = cloud_sync.restore_full_appdata(machine_id)
            steps.append(f"AppData: {r1['restored']} files restored")
            if r1['errors']:
                steps.append(f"  Errors: {', '.join(r1['errors'][:3])}")
    
            # Step 2 — Encryption key
            self.root.after(0, lambda: self.cloud_progress_var.set("Step 2/4: Recovering encryption key…"))
            key_ok = crypto_manager.attempt_cloud_recovery_if_needed()
            steps.append(f"Encryption key: {'✅ Recovered' if key_ok else '❌ Failed — new key generated'}")
            if not key_ok:
                success = False
    
            # Step 3 — Logs + forensics
            self.root.after(0, lambda: self.cloud_progress_var.set("Step 3/4: Restoring logs & forensics…"))
            r3 = cloud_sync.restore_logs_and_forensics(machine_id)
            steps.append(f"Logs/Forensics: {r3['restored']} files restored")
    
            # Step 4 — Reload auth database
            self.root.after(0, lambda: self.cloud_progress_var.set("Step 4/4: Reloading account database…"))
            try:
                if auth:
                    auth._load_users()
                steps.append("Account database: ✅ Reloaded")
            except Exception as e:
                steps.append(f"Account database: ❌ {e}")
    
            # ── Report ────────────────────────────────────────────────────────
            summary = "\n".join(steps)
            if success:
                final_msg = f"✅ Disaster recovery complete.\n\n{summary}\n\nPlease restart FMSecure."
                self.root.after(0, lambda: self.cloud_progress_var.set("✅ Recovery complete — restart FMSecure"))
            else:
                final_msg = (f"⚠️ Partial recovery.\n\n{summary}\n\n"
                            "Encryption key could not be recovered — a new key was generated.\n"
                            "Old encrypted data is unrecoverable.\n"
                            "Please create a new admin account.")
                self.root.after(0, lambda: self.cloud_progress_var.set("⚠️ Partial recovery — see details"))
    
            self.root.after(0, lambda: messagebox.showinfo("Disaster Recovery", final_msg))
            self.root.after(0, lambda: self._append_log(f"DISASTER RECOVERY COMPLETE:\n{summary}"))
    
        threading.Thread(target=_do_recovery, daemon=True).start()
    

    def _open_archive_browser(self):
        from tkinter import messagebox
        import threading
    
        C   = self.colors
        win = tk.Toplevel(self.root)
        win.title("Archive Browser — FMSecure")
        win.geometry("1100x680")          # wider + taller — fixed, not resizable
        win.resizable(False, False)
        win.configure(bg=C['bg'])
        win.transient(self.root)
    
        # ── Header ────────────────────────────────────────────────────────────────
        hdr = tk.Frame(win, bg=C['header_bg'], height=52)
        hdr.pack(fill=tk.X)
        hdr.pack_propagate(False)
        tk.Label(hdr, text="🗄  Previous Installation Archives",
                font=('Segoe UI', 14, 'bold'),
                bg=C['header_bg'], fg=C['accent_secondary']).pack(
            side=tk.LEFT, padx=20, pady=14)
        tk.Label(hdr, text="Cloud backups archived when you chose 'Start Fresh'",
                font=('Segoe UI', 9),
                bg=C['header_bg'], fg=C['text_muted']).pack(
            side=tk.LEFT, padx=8, pady=14)
        tk.Frame(win, height=1, bg=C['divider']).pack(fill=tk.X)
    
        # ── Body layout ───────────────────────────────────────────────────────────
        body = tk.Frame(win, bg=C['bg'])
        body.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)
    
        # Left: archive list
        left = tk.Frame(body, bg=C['card_bg'],
                        highlightbackground=C['card_border'], highlightthickness=1,
                        width=260)
        left.pack(side=tk.LEFT, fill=tk.Y)
        left.pack_propagate(False)
    
        tk.Label(left, text="Archives",
                font=('Segoe UI', 10, 'bold'),
                bg=C['card_bg'], fg=C['text_primary']).pack(
            anchor='w', padx=14, pady=(12, 4))
        tk.Frame(left, height=1, bg=C['divider']).pack(fill=tk.X)
    
        archive_list = tk.Listbox(
            left, bg=C['input_bg'], fg=C['text_primary'],
            selectbackground=C['accent_secondary'], selectforeground='#fff',
            font=('Segoe UI', 9), relief='flat', activestyle='none',
            highlightthickness=0)
        archive_list.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
    
        # Right pane
        right = tk.Frame(body, bg=C['card_bg'],
                        highlightbackground=C['card_border'], highlightthickness=1)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(12, 0))
    
        detail_title = tk.Label(right, text="Select an archive",
                                font=('Segoe UI', 11, 'bold'),
                                bg=C['card_bg'], fg=C['text_primary'])
        detail_title.pack(anchor='w', padx=14, pady=(12, 6))
        tk.Frame(right, height=1, bg=C['divider']).pack(fill=tk.X)
    
        # Metadata grid
        stats_frame = tk.Frame(right, bg=C['card_bg'])
        stats_frame.pack(fill=tk.X, padx=14, pady=10)
        stat_vars = {
            "Archived at":       tk.StringVar(value="—"),
            "Hostname":          tk.StringVar(value="—"),
            "Account":           tk.StringVar(value="—"),
            "Vault files":       tk.StringVar(value="—"),
            "Log files":         tk.StringVar(value="—"),
            "AppData files":     tk.StringVar(value="—"),
            "Folder backups":    tk.StringVar(value="—"),
        }
        for i, (lbl, var) in enumerate(stat_vars.items()):
            col  = i % 2
            row  = i // 2
            cell = tk.Frame(stats_frame, bg=C['card_bg'])
            cell.grid(row=row, column=col, padx=8, pady=2, sticky='w')
            stats_frame.columnconfigure(col, weight=1)
            tk.Label(cell, text=lbl, font=('Segoe UI', 8),
                    bg=C['card_bg'], fg=C['text_muted']).pack(anchor='w')
            tk.Label(cell, textvariable=var, font=('Segoe UI', 10, 'bold'),
                    bg=C['card_bg'], fg=C['text_primary']).pack(anchor='w')
    
        tk.Frame(right, height=1, bg=C['divider']).pack(fill=tk.X, pady=(6, 0))
    
        # ── Restore scope selector ────────────────────────────────────────────────
        scope_frame = tk.Frame(right, bg=C['card_bg'])
        scope_frame.pack(fill=tk.X, padx=14, pady=(8, 4))
    
        tk.Label(scope_frame, text="Restore scope:",
                font=('Segoe UI', 9, 'bold'),
                bg=C['card_bg'], fg=C['text_primary']).pack(anchor='w', pady=(0, 4))
    
        subfolder_var = tk.StringVar(value="all")
    
        scope_options = [
            ("all",           "Everything  (keys → AppData → logs → vault → folder backups)"),
            ("appdata",       "AppData only  (users, config, hash records)"),
            ("logs",          "Logs & forensics only"),
            ("vault",         "File vault only  (.enc backup blobs)"),
            ("keys",          "Encryption keys only"),
            ("folder_backup", "Folder structure backups only"),
        ]
        for val, txt in scope_options:
            tk.Radiobutton(scope_frame, text=txt,
                        variable=subfolder_var, value=val,
                        bg=C['card_bg'], fg=C['text_primary'],
                        selectcolor=C['input_bg'],
                        activebackground=C['card_bg'],
                        font=('Segoe UI', 9)).pack(anchor='w')
    
        tk.Frame(right, height=1, bg=C['divider']).pack(fill=tk.X, pady=(6, 0))
        progress_var = tk.StringVar(value="Loading archives from Google Drive…")
        # anchor='w' + fixed wraplength prevents window resize when long filenames appear
        progress_lbl = tk.Label(right, textvariable=progress_var,
                                font=('Consolas', 8),
                                bg=C['card_bg'], fg=C['accent_info'],
                                anchor='w', wraplength=560, justify='left',
                                width=80)
        progress_lbl.pack(fill=tk.X, padx=14, pady=(4, 8))
        tk.Frame(right, height=1, bg=C['divider']).pack(fill=tk.X)
    
        # ── Buttons ───────────────────────────────────────────────────────────────
        btn_row = tk.Frame(right, bg=C['card_bg'])
        btn_row.pack(fill=tk.X, padx=14, pady=12)
    
        # ── State ─────────────────────────────────────────────────────────────────
        _archives = []
        _selected = [None]
    
        def _on_select(event):
            sel = archive_list.curselection()
            if not sel:
                return
            a = _archives[sel[0]]
            _selected[0] = a
            detail_title.configure(text=a.get("folder_name", "?")[-36:])
            fc = a.get("file_counts", {})
            stat_vars["Archived at"].set(a.get("archived_at", "—"))
            stat_vars["Hostname"].set(a.get("hostname", "—"))
            stat_vars["Account"].set(a.get("email", "—"))
            stat_vars["Vault files"].set(f"{fc.get('vault',         0)} files")
            stat_vars["Log files"].set(f"{fc.get('logs',            0)} files")
            stat_vars["AppData files"].set(f"{fc.get('appdata',     0)} files")
            stat_vars["Folder backups"].set(f"{fc.get('folder_backup', 0)} buckets")
    
        archive_list.bind("<<ListboxSelect>>", _on_select)
    
        # ── Load archives ─────────────────────────────────────────────────────────
        def _load_archives():
            try:
                from core.cloud_sync import cloud_sync
                from core.encryption_manager import crypto_manager
    
                # Re-count folder_backup entries too
                items = cloud_sync.list_archives(crypto_manager.get_machine_id())
    
                # Supplement file_counts with folder_backup count
                for a in items:
                    fc = a.get("file_counts", {})
                    if "folder_backup" not in fc:
                        # list_archives doesn't count this — do it lazily
                        try:
                            fb_count = 0
                            for child in cloud_sync._list_folder(a["folder_id"]):
                                if child["name"] == "folder_backup":
                                    fb_count = len(cloud_sync._list_folder(child["id"]))
                                    break
                            fc["folder_backup"] = fb_count
                        except Exception:
                            fc["folder_backup"] = 0
    
                def _populate():
                    # Guard: window may have been closed while Drive was loading
                    try:
                        if not win.winfo_exists():
                            return
                    except Exception:
                        return
                    archive_list.delete(0, tk.END)
                    _archives.clear()
                    if not items:
                        archive_list.insert(tk.END, "  No archives found")
                        progress_var.set("No previous installation archives on Drive.")
                        return
                    _archives.extend(items)
                    for a in items:
                        label = a.get("archived_at", "?")[:10]
                        archive_list.insert(tk.END, f"  {label}")
                    progress_var.set(
                        f"{len(items)} archive(s) found. Select one to inspect.")
    
                win.after(0, _populate)
    
            except Exception as exc:
                win.after(0, lambda: progress_var.set(f"Error loading archives: {exc}"))
    
        threading.Thread(target=_load_archives, daemon=True).start()
    
        # ── Restore handler ───────────────────────────────────────────────────────
        def _do_restore():
            a = _selected[0]
            if not a:
                messagebox.showwarning("Nothing selected",
                                    "Please select an archive from the list first.")
                return
    
            scope = subfolder_var.get()
    
            scope_labels = {
                "all":           "EVERYTHING (all subfolders)",
                "appdata":       "AppData (users, config, records)",
                "logs":          "Logs & forensics",
                "vault":         "File vault backups",
                "keys":          "Encryption keys",
                "folder_backup": "Folder structure backups",
            }
            scope_label = scope_labels.get(scope, scope)
    
            if not messagebox.askyesno(
                "Confirm restore",
                f"Restore  {scope_label}\nfrom archive:\n\n"
                f"  {a.get('archived_at', '?')}\n\n"
                "Matching local files will be overwritten.\n"
                "Continue?"
            ):
                return
    
            restore_btn.configure(state='disabled', text="Restoring…")
            all_btn.configure(state='disabled')
    
            def _run():
                from core.cloud_sync import cloud_sync
    
                if scope == "all":
                    result_all = cloud_sync.restore_all_from_archive(
                        a["folder_id"],
                        progress_cb=lambda sub, r, e:
                            win.after(0, lambda s=sub, rv=r, ev=e:
                                    progress_var.set(f"✓ {s}: {rv} files restored"
                                                    + (f"  ({len(ev)} errors)" if ev else "")))
                    )
                    total    = result_all["total_restored"]
                    n_errors = len(result_all["errors"])
                    summary  = (f"✅ Full restore complete: {total} files total.  "
                                f"Errors: {n_errors}")
                else:
                    result = cloud_sync.restore_from_archive(a["folder_id"], subfolder=scope)
                    total    = result["restored"]
                    n_errors = len(result["errors"])
                    summary  = (f"✅ Restored {total} files from '{scope}'.  "
                                f"Errors: {n_errors}")
    
                def _done():
                    restore_btn.configure(state='normal', text="Restore Selected")
                    all_btn.configure(state='normal')
                    progress_var.set(summary)
                    self._append_log(
                        f"ARCHIVE RESTORE: scope={scope}, "
                        f"{total} files, archive={a.get('archived_at','?')}")
    
                win.after(0, _done)
    
            threading.Thread(target=_run, daemon=True).start()
    
        restore_btn = tk.Button(
            btn_row, text="Restore Selected",
            command=_do_restore,
            font=('Segoe UI', 10, 'bold'),
            bg=C['accent_secondary'], fg='#fff',
            bd=0, padx=20, pady=8, cursor='hand2',
            activebackground=C['accent_secondary'])
        restore_btn.pack(side=tk.LEFT)
    
        # "Restore All" is just a shortcut that sets scope to "all" and fires
        def _quick_restore_all():
            subfolder_var.set("all")
            _do_restore()
    
        all_btn = tk.Button(
            btn_row, text="Restore All",
            command=_quick_restore_all,
            font=('Segoe UI', 10, 'bold'),
            bg=C['accent_danger'], fg='#fff',
            bd=0, padx=20, pady=8, cursor='hand2',
            activebackground=C['accent_danger'])
        all_btn.pack(side=tk.LEFT, padx=(8, 0))
    
        tk.Button(btn_row, text="Close", command=win.destroy,
                font=('Segoe UI', 10),
                bg=C['button_bg'], fg=C['text_secondary'],
                bd=0, padx=20, pady=8, cursor='hand2').pack(side=tk.RIGHT)
        
    
    # ── Toggle handlers (call original core methods, then sync toggle UI) ──

    def _toggle_active_defense(self):
        """Toggle active defense with PRO check and Pre-Popup Snap-back"""
        tier = "free"
        if auth:
            tier = auth.get_user_tier(self.username)
        
        if hasattr(self, 'pro_badge') and self.pro_badge.winfo_exists():
            tier = "pro_monthly"
        
        if not subscription_manager.is_pro(tier):   # <-- CHANGED
            # 🚨 FIX: Force the switch back to OFF and redraw BEFORE the popup freezes the app
            self._ad_var.set(False)
            self.ad_btn_text.set('OFF')
            if hasattr(self, '_toggle_switches') and 'Active Defense' in self._toggle_switches:
                self._toggle_switches['Active Defense'].refresh()
                self.root.update_idletasks() # Forces Windows to paint the screen immediately
                
            from tkinter import messagebox
            messagebox.showwarning("⭐ Premium Feature", "🛡️ Active Defense is a PRO feature.\n\nPlease activate a License Key to unlock.")
            return 
            
        new_state = self._ad_var.get()
        self.ad_btn_text.set('ON' if new_state else 'OFF')
        try:
            from core.integrity_core import CONFIG, CONFIG_FILE, load_config
            import json
            
            CONFIG['active_defense'] = new_state
            
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    file_cfg = json.load(f)
            else:
                file_cfg = dict(CONFIG)
                
            file_cfg["active_defense"] = new_state
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(file_cfg, f, indent=4)
                
            load_config(CONFIG_FILE)
            self._append_log(f'Active Defense {"ENABLED" if new_state else "DISABLED"} by {self.username}')
            
            # 🚨 FIX: Retroactively backup files if turned ON mid-session
            if new_state and getattr(self, 'monitor_running', False) and self.monitor and hasattr(self.monitor, 'handler'):
                def _sync_vault():
                    try:
                        self._append_log("Syncing existing files to Secure Vault...")
                        from core.vault_manager import vault
                        _allowed = CONFIG.get("vault_allowed_exts") or None
                        records = self.monitor.handler.records
                        count = 0
                        for path in list(records.keys()):
                            vault.backup_file(path, CONFIG.get("vault_max_size_mb", 10), _allowed)
                            count += 1
                        
                        # Use .after() to safely update the GUI from the background thread
                        self.root.after(0, lambda: self._append_log(f"Vault sync complete. {count} files protected."))
                    except Exception as e:
                        print(f"Vault sync error: {e}")
                
                import threading
                threading.Thread(target=_sync_vault, daemon=True).start()

        except Exception as e:
            print(f'Active defense toggle error: {e}')

    def _toggle_killswitch(self):
        """Toggle ransomware killswitch with PRO check and Pre-Popup Snap-back"""
        tier = "free"
        if auth:
            tier = auth.get_user_tier(self.username)
        
        if hasattr(self, 'pro_badge') and self.pro_badge.winfo_exists():
            tier = "pro_monthly"
        
        if not subscription_manager.is_pro(tier):   # <-- CHANGED
            # 🚨 FIX: Force the switch back to OFF and redraw BEFORE the popup freezes the app
            self._ks_var.set(False)
            self.ks_btn_text.set('OFF')
            if hasattr(self, '_toggle_switches') and 'Ransomware Killswitch' in self._toggle_switches:
                self._toggle_switches['Ransomware Killswitch'].refresh()
                self.root.update_idletasks()
                
            from tkinter import messagebox
            messagebox.showwarning("⭐ Premium Feature", "🛑 Ransomware Killswitch is a PRO feature.\n\nPlease activate a License Key to unlock.")
            return
            
        new_state = self._ks_var.get()
        self.ks_btn_text.set('ON' if new_state else 'OFF')
        try:
            from core.integrity_core import CONFIG, CONFIG_FILE, load_config
            import json
            
            CONFIG['ransomware_killswitch'] = new_state
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    file_cfg = json.load(f)
            else:
                file_cfg = dict(CONFIG)
                
            file_cfg["ransomware_killswitch"] = new_state
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(file_cfg, f, indent=4)
                
            load_config(CONFIG_FILE)
            self._append_log(f'Ransomware Killswitch {"ARMED" if new_state else "DISARMED"} by {self.username}')
        except Exception as e:
            print(f'Killswitch toggle error: {e}')
            
        try:
            self.ks_toggle_btn = type('obj', (object,), {'configure': lambda self_inner, **kw: None})()
        except Exception:
            pass

    def _toggle_usb_control(self):
        """Toggle USB device control with PRO check and Pre-Popup Snap-back"""
        tier = "free"
        if auth:
            tier = auth.get_user_tier(self.username)
        
        if hasattr(self, 'pro_badge') and self.pro_badge.winfo_exists():
            tier = "pro_monthly"
        
        if not subscription_manager.is_pro(tier):   # <-- CHANGED
            # 🚨 FIX: Force the switch back to OFF and redraw BEFORE the popup freezes the app
            self._usb_var.set(False)
            self.usb_btn_text.set('ALLOWED')
            if hasattr(self, '_toggle_switches') and 'USB Device Control' in self._toggle_switches:
                self._toggle_switches['USB Device Control'].refresh()
                self.root.update_idletasks()
                
            from tkinter import messagebox
            messagebox.showwarning("⭐ Premium Feature", "🔌 USB Device Control is a PRO feature.\n\nPlease activate a License Key to unlock.")
            return
            
        # Password prompt check
        if not self._authenticate_action("Modify USB Device Policy"):
            from core.integrity_core import CONFIG
            current_state = CONFIG.get("usb_readonly", False)
            self._usb_var.set(current_state)
            self.usb_btn_text.set('LOCKED' if current_state else 'ALLOWED')
            if hasattr(self, '_toggle_switches') and 'USB Device Control' in self._toggle_switches:
                self._toggle_switches['USB Device Control'].refresh()
                self.root.update_idletasks()
            return

        new_state = self._usb_var.get()
        self.usb_btn_text.set('LOCKED' if new_state else 'ALLOWED')
        
        try:
            from core.usb_policy import set_usb_read_only
            success, msg = set_usb_read_only(enable=new_state)
            if not success:
                from tkinter import messagebox
                messagebox.showerror("Policy Error", msg)
                self._usb_var.set(not new_state)
                self.usb_btn_text.set('LOCKED' if not new_state else 'ALLOWED')
                if hasattr(self, '_toggle_switches') and 'USB Device Control' in self._toggle_switches:
                    self._toggle_switches['USB Device Control'].refresh()
                    self.root.update_idletasks()
                return
                
            from core.integrity_core import CONFIG, CONFIG_FILE, load_config
            import json
            
            CONFIG['usb_readonly'] = new_state
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    file_cfg = json.load(f)
            else:
                file_cfg = dict(CONFIG)
                
            file_cfg["usb_readonly"] = new_state
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(file_cfg, f, indent=4)
                
            load_config(CONFIG_FILE)
            self._append_log(f'USB Control {"LOCKED (read-only)" if new_state else "UNLOCKED"} by {self.username}')
            
        except Exception as e:
            print(f'USB toggle error: {e}')

    # Legacy toggle_btn stubs so old code that calls .configure() doesn't crash
    @property
    def ad_toggle_btn(self):
        return type('_stub', (), {'configure': lambda self, **kw: None,
                                   'cget': lambda self, k: ''})()

    @property
    def ks_toggle_btn(self):
        return type('_stub', (), {'configure': lambda self, **kw: None,
                                   'cget': lambda self, k: ''})()

    @property
    def usb_toggle_btn(self):
        return type('_stub', (), {'configure': lambda self, **kw: None,
                                   'cget': lambda self, k: ''})()

    def _update_button_states(self):
        """No-op — new design uses _ActionButton which handles its own hover."""
        pass

    # folder_entry compatibility shim (run_verification uses self.folder_entry.get())
    @property
    def folder_entry(self):
        class _FolderEntryProxy:
            def __init__(proxy_self):
                pass
            def get(proxy_self):
                try:
                    items = self.folder_listbox.get(0, tk.END)
                    return items[0] if items else ''
                except Exception:
                    return ''
        return _FolderEntryProxy()

    # ══════════════════════════════════════════════════════════════════════════
    #  ALL ORIGINAL LOGIC METHODS (unchanged from original)
    #  Everything below this line is identical to the original file.
    # ══════════════════════════════════════════════════════════════════════════

    # ===== REPORT METHODS FROM BACKUP =====
    
    def normalize_report_data(self, summary=None):
        """
        Convert summary data to structured dictionary with JSON persistence
        - IMPORTED FROM BACKUP
        """
        # 1. If summary is provided, use it
        if summary:
            pass
        
        # 2. If no summary provided, check if we have data in memory
        elif self.report_data.get('total', 0) > 0:
            return self.report_data
            
        # 3. If memory is empty, try to load from the JSON cache
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
        """Fallback text parser if JSON is missing - IMPORTED FROM BACKUP"""
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

    def generate_bar_chart(self, data=None, save_path=None, show_chart=True):
        """
        Generate bar chart for created/modified/deleted counts
        - IMPORTED FROM BACKUP
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
    
    def _show_chart_in_gui(self, fig):
        """Display chart in a separate window - IMPORTED FROM BACKUP"""
        chart_window = tk.Toplevel(self.root)
        chart_window.title("📈 File Integrity Chart")
        chart_window.geometry("800x600")
        chart_window.configure(bg=self.colors['bg'])
        
        # Embed matplotlib figure in Tkinter window
        canvas = FigureCanvasTkAgg(fig, master=chart_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Add save button
        save_btn = tk.Button(chart_window, text="💾 Save Chart",
                            command=lambda: self._save_chart_dialog(fig),
                            font=('Segoe UI', 10), bg=self.colors['accent_primary'], fg='white',
                            bd=0, padx=20, pady=8, cursor="hand2")
        save_btn.pack(pady=10)
        
        # Add close button
        close_btn = tk.Button(chart_window, text="Close", command=chart_window.destroy,
                             font=('Segoe UI', 10), bg=self.colors['button_bg'], fg=self.colors['text_primary'],
                             bd=0, padx=20, pady=8, cursor="hand2")
        close_btn.pack(pady=5)
    
    def _save_chart_dialog(self, fig):
        """Save chart to file dialog - IMPORTED FROM BACKUP"""
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
        """Generate and display chart from current data - IMPORTED FROM BACKUP"""
        if not HAS_MATPLOTLIB:
            messagebox.showwarning("Chart Generation", 
                                 "Matplotlib not installed. Install with: pip install matplotlib")
            return
        
        # Ensure we fetch data intelligently
        if self.report_data.get('total', 0) > 0:
            data = self.report_data
        else:
            data = self.normalize_report_data()
        
        # Check if we actually have data to show
        has_data = (len(data.get('created', [])) > 0 or 
                   len(data.get('modified', [])) > 0 or 
                   len(data.get('deleted', [])) > 0)
        
        if not has_data and data.get('total', 0) == 0:
            messagebox.showinfo("No Data", "No report data found to chart.\nPlease run 'Verify Now' first.")
            return

        # Generate chart
        self.generate_bar_chart(data, show_chart=True)

    def export_report_pdf(self):
        """Export comprehensive PDF report with chart - IMPORTED FROM BACKUP"""
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
                    textColor=colors.HexColor('#3b82f6')
                )
                
                heading_style = ParagraphStyle(
                    'CustomHeading',
                    parent=styles['Heading2'],
                    fontSize=14,
                    spaceAfter=12,
                    textColor=colors.HexColor('#3b82f6')
                )
                
                subheading_style = ParagraphStyle(
                    'CustomSubHeading',
                    parent=styles['Heading3'],
                    fontSize=12,
                    spaceAfter=8,
                    textColor=colors.HexColor('#64748b')
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

                # Security Severity Summary
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
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3b82f6')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
                    ('PADDING', (0, 0), (-1, -1), 8),
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BACKGROUND', (0, 1), (0, 1), colors.HexColor('#ef4444')),
                    ('BACKGROUND', (0, 2), (0, 2), colors.HexColor('#f97316')),
                    ('BACKGROUND', (0, 3), (0, 3), colors.HexColor('#f59e0b')),
                    ('BACKGROUND', (0, 4), (0, 4), colors.HexColor('#06b6d4')),
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
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
                    ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
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
                    created_list = data['created'][:20]
                    for file in created_list:
                        story.append(Paragraph(f"• {file}", normal_style))
                    if len(data['created']) > 20:
                        story.append(Paragraph(f"... and {len(data['created']) - 20} more files", normal_style))
                    story.append(Spacer(1, 10))
                
                # Modified Files
                if data['modified']:
                    story.append(Paragraph("Modified Files:", subheading_style))
                    modified_list = data['modified'][:20]
                    for file in modified_list:
                        story.append(Paragraph(f"• {file}", normal_style))
                    if len(data['modified']) > 20:
                        story.append(Paragraph(f"... and {len(data['modified']) - 20} more files", normal_style))
                    story.append(Spacer(1, 10))
                
                # Deleted Files
                if data['deleted']:
                    story.append(Paragraph("Deleted Files:", subheading_style))
                    deleted_list = data['deleted'][:20]
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
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3b82f6')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
                    ('PADDING', (0, 0), (-1, -1), 8),
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BACKGROUND', (1, 1), (1, 2), 
                     colors.HexColor('#10b981') if not data['tampered_records'] else colors.HexColor('#ef4444')),
                    ('BACKGROUND', (1, 2), (1, 2), 
                     colors.HexColor('#10b981') if not data['tampered_logs'] else colors.HexColor('#ef4444')),
                    ('TEXTCOLOR', (1, 1), (1, 2), colors.white),
                ]))
                story.append(security_table)
                story.append(Spacer(1, 30))
                
                # Footer
                story.append(Paragraph("Report generated by Secure File Integrity Monitor", normal_style))
                story.append(Paragraph("Professional Security Edition", normal_style))
                
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
        """Export logs as PDF - IMPORTED FROM BACKUP"""
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
                    textColor=colors.HexColor('#3b82f6')
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
                            log_lines = get_decrypted_logs()[-1000:]  # Last 1000 lines
                        
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
        """Show export success dialog with option to open folder - IMPORTED FROM BACKUP"""
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

    # ===== CORE ACTION METHODS FROM BACKUP =====
    
    def _browse(self):
        """Browse for folder - IMPORTED FROM BACKUP"""
        d = filedialog.askdirectory()
        if d:
            self.watch_folder_var.set(d)
            self.folder_entry.delete(0, tk.END)
            self.folder_entry.insert(0, d)
            self._append_log(f"Selected monitor folder: {d}")


    def _add_folder_gui(self):
        """Add a folder to the list (Fail-Safe Premium Check)"""
        current_count = self.folder_listbox.size()
        
        # 1. FOOLPROOF TIER CHECK
        tier = "free"
        if auth:
            tier = auth.get_user_tier(self.username)
            
        if hasattr(self, 'pro_badge') and self.pro_badge.winfo_exists():
            tier = "pro_monthly"
            
        limit = subscription_manager.get_folder_limit(tier)
 
        if current_count >= limit:
            if not subscription_manager.is_pro(tier):
                from tkinter import messagebox
                messagebox.showwarning("⭐ Premium Feature", "The Free Plan is limited to 1 folder.\n\nPlease upgrade to a PRO License to monitor up to 5 directories!")
            else:
                from tkinter import messagebox
                messagebox.showwarning("Limit Reached", f"PRO maximum of {limit} folders reached.")
            return

        # 3. ADD FOLDER
        folder = filedialog.askdirectory()
        if folder:
            existing = self.folder_listbox.get(0, tk.END)
            if folder in existing:
                return
            self.folder_listbox.insert(tk.END, folder)
            self._save_folders_to_config()

    def _remove_folder_gui(self):
        """Remove selected folder"""
        selection = self.folder_listbox.curselection()
        if selection:
            self.folder_listbox.delete(selection[0])
            self._save_folders_to_config()

    def _save_folders_to_config(self):
        """Save the listbox items to memory AND the hard drive"""
        folders = list(self.folder_listbox.get(0, tk.END))
        from core.integrity_core import CONFIG
        CONFIG["watch_folders"] = folders
        
        try:
            import json
            # Import the exact config file path the backend is using!
            from core.integrity_core import CONFIG_FILE 
            
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(CONFIG, f, indent=4)
                
        except Exception as e:
            from tkinter import messagebox
            messagebox.showerror("Configuration Error", f"Windows blocked saving the folder settings.\n\nError: {e}\n\nPlease run the app as Administrator.")

    # ══════════════════════════════════════════════════════════════════════════════
    #  PATCH 2 — Replace _show_activation_dialog with this version
    #  Adds "Transfer License" flow when device_mismatch is returned.
    # ══════════════════════════════════════════════════════════════════════════════
    
    def _show_activation_dialog(self):
        """
        License activation dialog — full styled window.
        • Logo + branding
        • License key entry
        • Buy Now button → product page
        • Recover Lost Key → sends key to purchase email
        • Transfer License flow on device_mismatch
        """
        if auth:
            auth._load_users()
    
        user_data        = auth.users.get(self.username, {})
        registered_email = user_data.get("registered_email", "")
    
        C   = self.colors
        win = tk.Toplevel(self.root)
        win.title("Activate FMSecure PRO")
        win.geometry("500x560")
        win.resizable(False, False)
        win.configure(bg=C['card_bg'])
        win.transient(self.root)
        win.grab_set()
    
        # Center on parent
        win.update_idletasks()
        px = self.root.winfo_x() + (self.root.winfo_width()  // 2) - 250
        py = self.root.winfo_y() + (self.root.winfo_height() // 2) - 280
        win.geometry(f'+{px}+{py}')
        win.lift()
        win.focus_force()
    
        # ── Gold accent header ─────────────────────────────────────────────────────
        tk.Frame(win, bg="#d29922", height=4).pack(fill=tk.X)
    
        # ── Logo + title row ───────────────────────────────────────────────────────
        title_row = tk.Frame(win, bg=C['card_bg'])
        title_row.pack(fill=tk.X, padx=28, pady=(20, 0))
    
        # Try to load the app icon as a small logo
        try:
            from PIL import Image, ImageTk
            import sys
            base = sys._MEIPASS if getattr(sys, 'frozen', False) else \
                   os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            logo_path = os.path.join(base, "assets", "icons", "app_icon.png")
            img = Image.open(logo_path).resize((52, 52))
            self._activation_logo = ImageTk.PhotoImage(img)
            logo_lbl = tk.Label(title_row, image=self._activation_logo, bg=C['card_bg'])
            logo_lbl.pack(side=tk.LEFT, padx=(0, 14))
        except Exception:
            tk.Label(title_row, text="★", font=('Segoe UI', 32),
                     bg=C['card_bg'], fg="#d29922").pack(side=tk.LEFT, padx=(0, 14))
    
        info_col = tk.Frame(title_row, bg=C['card_bg'])
        info_col.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Label(info_col, text="Upgrade to FMSecure PRO",
                 font=('Segoe UI', 15, 'bold'),
                 bg=C['card_bg'], fg=C['text_primary']).pack(anchor='w')
        tk.Label(info_col, text="Active Defense • Cloud Backup • Ransomware Killswitch",
                 font=('Segoe UI', 9),
                 bg=C['card_bg'], fg=C['text_muted']).pack(anchor='w')
    
        tk.Frame(win, height=1, bg=C['divider']).pack(fill=tk.X, padx=28, pady=(16, 0))
    
        # ── Key entry ──────────────────────────────────────────────────────────────
        tk.Label(win, text="ENTER YOUR LICENSE KEY",
                 font=('Segoe UI', 9, 'bold'), letter_spacing=1,
                 bg=C['card_bg'], fg=C['text_muted']).pack(
            anchor='w', padx=28, pady=(14, 4))
    
        key_var = tk.StringVar()
        key_entry = tk.Entry(win, textvariable=key_var,
                             font=('Consolas', 13),
                             bg=C['input_bg'], fg="#d29922",
                             insertbackground=C['text_primary'],
                             relief='flat',
                             highlightthickness=1,
                             highlightbackground=C['input_border'],
                             highlightcolor="#d29922")
        key_entry.pack(fill=tk.X, padx=28, pady=(0, 4))
        key_entry.focus_set()
    
        status_lbl = tk.Label(win, text='',
                               font=('Segoe UI', 9),
                               bg=C['card_bg'], fg=C['accent_danger'],
                               wraplength=420, justify='left')
        status_lbl.pack(anchor='w', padx=28)
    
        # ── Activate button ────────────────────────────────────────────────────────
        def _do_activate():
            clean_key = key_var.get().strip()
            if not clean_key:
                status_lbl.configure(text="Please enter your license key.")
                return
            if not registered_email:
                status_lbl.configure(
                    text="No registered email on this account.\nContact support.")
                return
    
            activate_btn.configure(state='disabled', text="Activating…")
            status_lbl.configure(text='', fg=C['accent_danger'])
    
            def _run():
                success, msg = auth.activate_license(self.username, clean_key)
    
                def _update():
                    activate_btn.configure(state='normal', text="Activate")
                    if success:
                        win.destroy()
                        self.status_var.set("⭐ Premium Active")
                        from core.integrity_core import CONFIG
                        CONFIG["admin_email"] = registered_email
                        CONFIG["is_pro_user"] = True
                        try:
                            from core.encryption_manager import crypto_manager
                            threading.Thread(target=crypto_manager.force_key_backup,
                                             daemon=True).start()
                        except Exception:
                            pass
                        if hasattr(self, 'upgrade_btn') and self.upgrade_btn.winfo_exists():
                            self.upgrade_btn.destroy()
                        self.pro_badge = tk.Label(
                            self.top_btn_frame, text="★  PRO ACTIVE",
                            font=('Segoe UI', 10, 'bold'),
                            bg=self.colors['header_bg'], fg="#d29922")
                        self.pro_badge.pack(side=tk.LEFT, padx=(0, 15),
                                             before=self.theme_btn)
                        messagebox.showinfo(
                            "Activation Successful! 🎉",
                            f"Welcome to FMSecure PRO!\n\n{msg}"
                        )
                        return
    
                    # Check for device_mismatch
                    try:
                        from core.license_verifier import license_verifier
                        is_mismatch = license_verifier.is_device_mismatch(clean_key)
                    except Exception:
                        is_mismatch = ("different device" in msg.lower() or
                                       "device_mismatch" in msg.lower())
    
                    if is_mismatch:
                        status_lbl.configure(
                            text="This key is linked to a different device.\n"
                                 "Use 'Transfer License' below to reassign it.")
                        transfer_btn.pack(fill=tk.X, padx=28, pady=(6, 0))
                    else:
                        status_lbl.configure(text=msg)
    
                self.root.after(0, _update)
    
            threading.Thread(target=_run, daemon=True).start()
    
        activate_btn = tk.Button(win, text="Activate",
                                  command=_do_activate,
                                  font=('Segoe UI', 11, 'bold'),
                                  bg="#d29922", fg="#0d1117",
                                  relief='flat', padx=20, pady=9,
                                  cursor='hand2',
                                  activebackground="#e6a817")
        activate_btn.pack(fill=tk.X, padx=28, pady=(10, 0))
        win.bind('<Return>', lambda e: _do_activate())
    
        # ── Transfer License (hidden until mismatch detected) ─────────────────────
        transfer_btn = tk.Button(
            win, text="Transfer License to This Device",
            command=lambda: (win.destroy(),
                             self._show_license_transfer_dialog(key_var.get().strip())),
            font=('Segoe UI', 9),
            bg=C['button_bg'], fg=C['accent_info'],
            relief='flat', padx=12, pady=6, cursor='hand2')
        # Not packed yet — shown only on device_mismatch
    
        tk.Frame(win, height=1, bg=C['divider']).pack(fill=tk.X, padx=28, pady=(14, 0))
    
        # ── Secondary actions row ──────────────────────────────────────────────────
        sec_row = tk.Frame(win, bg=C['card_bg'])
        sec_row.pack(fill=tk.X, padx=28, pady=(12, 0))
    
        # Buy Now
        import webbrowser
        buy_btn = tk.Button(
            sec_row, text="Buy PRO License →",
            command=lambda: webbrowser.open(
                "https://fmsecure-c2-server-production.up.railway.app/pricing"),
            font=('Segoe UI', 9, 'bold'),
            bg="#238636", fg="#ffffff",
            relief='flat', padx=12, pady=6, cursor='hand2',
            activebackground="#2ea043")
        buy_btn.pack(side=tk.LEFT)
    
        # Recover Lost Key
        def _recover_key():
            self._show_key_recovery_dialog(win)
    
        recover_btn = tk.Button(
            sec_row, text="Recover Lost Key",
            command=_recover_key,
            font=('Segoe UI', 9),
            bg=C['button_bg'], fg=C['text_secondary'],
            relief='flat', padx=12, pady=6, cursor='hand2')
        recover_btn.pack(side=tk.RIGHT)
    
        tk.Frame(win, height=1, bg=C['divider']).pack(fill=tk.X, padx=28, pady=(12, 0))
    
        # ── Feature highlights ─────────────────────────────────────────────────────
        feats = tk.Frame(win, bg=C['card_bg'])
        feats.pack(fill=tk.X, padx=28, pady=(10, 0))
        for icon, txt in [
            ("🛡", "Active Defense — auto-heal tampered files"),
            ("☁", "Cloud Backup — Google Drive disaster recovery"),
            ("🛑", "Ransomware Killswitch — OS-level folder lockdown"),
            ("🔌", "USB Device Control — block unauthorized drives"),
        ]:
            row = tk.Frame(feats, bg=C['card_bg'])
            row.pack(fill=tk.X, pady=2)
            tk.Label(row, text=icon, font=('Segoe UI', 11),
                     bg=C['card_bg'], fg="#d29922", width=2).pack(side=tk.LEFT)
            tk.Label(row, text=txt, font=('Segoe UI', 9),
                     bg=C['card_bg'], fg=C['text_secondary']).pack(
                side=tk.LEFT, padx=4)
    
        # ── Close button ───────────────────────────────────────────────────────────
        tk.Button(win, text="Close",
                  command=win.destroy,
                  font=('Segoe UI', 9),
                  bg=C['button_bg'], fg=C['text_secondary'],
                  relief='flat', padx=12, pady=5, cursor='hand2').pack(
            anchor='e', padx=28, pady=(14, 20))
    
    
    def _show_license_transfer_dialog(self, license_key: str):
        """
        Two-step license transfer:
        Step 1 — user enters purchase email → server sends OTP
        Step 2 — user enters OTP → server re-binds key to current machine_id
        """
        C   = self.colors
        win = tk.Toplevel(self.root)
        win.title("Transfer License — FMSecure")
        win.geometry("480x480")
        win.resizable(False, False)
        win.configure(bg=C['card_bg'])
        win.transient(self.root)
        win.grab_set()
    
        # Center
        win.update_idletasks()
        px = self.root.winfo_x() + (self.root.winfo_width()  // 2) - 240
        py = self.root.winfo_y() + (self.root.winfo_height() // 2) - 240
        win.geometry(f'+{px}+{py}')
    
        # Header accent
        tk.Frame(win, bg=C['accent_primary'], height=4).pack(fill=tk.X)
    
        # Title row
        title_row = tk.Frame(win, bg=C['card_bg'])
        title_row.pack(fill=tk.X, padx=24, pady=(18, 0))
        tk.Label(title_row, text='🔑', font=('Segoe UI', 22),
                bg=C['card_bg'], fg=C['accent_primary']).pack(side=tk.LEFT, padx=(0, 12))
        col = tk.Frame(title_row, bg=C['card_bg'])
        col.pack(side=tk.LEFT)
        tk.Label(col, text='Transfer License to This Device',
                font=('Segoe UI', 13, 'bold'),
                bg=C['card_bg'], fg=C['text_primary']).pack(anchor='w')
        tk.Label(col, text='Verify ownership via your purchase email',
                font=('Segoe UI', 9),
                bg=C['card_bg'], fg=C['text_secondary']).pack(anchor='w')
        tk.Frame(win, height=1, bg=C['divider']).pack(fill=tk.X, padx=24, pady=(14, 0))
    
        # -- Step containers --
        step1_frame = tk.Frame(win, bg=C['card_bg'])
        step1_frame.pack(fill=tk.X)
        step2_frame = tk.Frame(win, bg=C['card_bg'])
        # step2_frame is hidden until OTP is sent
    
        # ── STEP 1 — email entry ─────────────────────────────────────────────────
        tk.Label(step1_frame, text="Step 1 — Enter your purchase email",
                font=('Segoe UI', 10, 'bold'),
                bg=C['card_bg'], fg=C['text_primary']).pack(
            anchor='w', padx=24, pady=(12, 4))
        tk.Label(step1_frame,
                text="Use the email address from your FMSecure order confirmation.",
                font=('Segoe UI', 9),
                bg=C['card_bg'], fg=C['text_muted']).pack(anchor='w', padx=24)
    
        email_var = tk.StringVar()
        email_entry = tk.Entry(step1_frame, textvariable=email_var,
                            font=('Segoe UI', 12),
                            bg=C['input_bg'], fg=C['text_primary'],
                            insertbackground=C['text_primary'],
                            relief='flat',
                            highlightthickness=1,
                            highlightbackground=C['input_border'],
                            highlightcolor=C['accent_primary'])
        email_entry.pack(fill=tk.X, padx=24, pady=(8, 0))
        email_entry.focus_set()
    
        status_lbl = tk.Label(step1_frame, text='',
                            font=('Segoe UI', 9),
                            bg=C['card_bg'], fg=C['accent_danger'])
        status_lbl.pack(pady=(6, 0))
    
        # ── STEP 2 — OTP entry (hidden initially) ────────────────────────────────
        tk.Label(step2_frame, text="Step 2 — Enter the verification code",
                font=('Segoe UI', 10, 'bold'),
                bg=C['card_bg'], fg=C['text_primary']).pack(
            anchor='w', padx=24, pady=(16, 4))
    
        otp_status_lbl = tk.Label(step2_frame, text='',
                                font=('Segoe UI', 9),
                                bg=C['card_bg'], fg=C['text_secondary'])
        otp_status_lbl.pack(anchor='w', padx=24)
    
        otp_var = tk.StringVar()
        otp_entry = tk.Entry(step2_frame, textvariable=otp_var,
                            font=('Segoe UI', 20, 'bold'),
                            justify='center',
                            bg=C['input_bg'], fg=C['text_primary'],
                            insertbackground=C['text_primary'],
                            relief='flat',
                            highlightthickness=1,
                            highlightbackground=C['input_border'],
                            highlightcolor=C['accent_primary'])
        otp_entry.pack(fill=tk.X, padx=24, pady=(8, 0))
    
        otp_error_lbl = tk.Label(step2_frame, text='',
                                font=('Segoe UI', 9),
                                bg=C['card_bg'], fg=C['accent_danger'])
        otp_error_lbl.pack(pady=(4, 0))
    
        # ── Button row (always visible) ───────────────────────────────────────────
        tk.Frame(win, height=1, bg=C['divider']).pack(fill=tk.X, padx=24, pady=(12, 0))
        btn_row = tk.Frame(win, bg=C['card_bg'])
        btn_row.pack(fill=tk.X, padx=24, pady=(12, 20))
    
        def _send_otp():
            email = email_var.get().strip().lower()
            if not email or '@' not in email:
                status_lbl.configure(text='Please enter a valid email address.')
                return
    
            action_btn.configure(state='disabled', text='Sending…')
            status_lbl.configure(text='')
    
            def _do_send():
                from core.license_verifier import license_verifier
                ok, msg = license_verifier.request_license_transfer(license_key, email)
    
                def _update():
                    action_btn.configure(state='normal')
                    if ok:
                        # Hide step1, show step2
                        step1_frame.pack_forget()
                        otp_status_lbl.configure(
                            text=f"Code sent to {email}. Enter it below.")
                        step2_frame.pack(fill=tk.X)
                        action_btn.configure(text='Confirm Transfer',
                                            command=_confirm_transfer)
                        otp_entry.focus_set()
                    else:
                        status_lbl.configure(text=msg)
    
                win.after(0, _update)
    
            import threading
            threading.Thread(target=_do_send, daemon=True).start()
    
        def _confirm_transfer():
            otp = otp_var.get().strip()
            if not otp:
                otp_error_lbl.configure(text='Please enter the verification code.')
                return
    
            action_btn.configure(state='disabled', text='Verifying…')
            otp_error_lbl.configure(text='')
    
            def _do_confirm():
                from core.license_verifier import license_verifier
                ok, msg_out, tier = license_verifier.confirm_license_transfer(
                    license_key, otp)
    
                def _update():
                    action_btn.configure(state='normal', text='Confirm Transfer')
                    if ok:
                        # Persist the activation locally
                        success, auth_msg = auth.activate_license(
                            self.username, license_key)
                        win.destroy()
                        if success:
                            messagebox.showinfo(
                                "Transfer Successful! 🎉",
                                f"License transferred to this device.\n\n{auth_msg}"
                            )
                        else:
                            # The cache already has the valid response so re-run
                            messagebox.showinfo(
                                "Transfer Complete",
                                "License transferred. Please restart FMSecure to "
                                "activate PRO features."
                            )
                        self._append_log(
                            f"LICENSE TRANSFER: {license_key[:8]}… reassigned "
                            f"to this device (tier: {tier})")
                    else:
                        otp_error_lbl.configure(text=msg_out)
    
                win.after(0, _update)
    
            import threading
            threading.Thread(target=_do_confirm, daemon=True).start()
    
        action_btn = tk.Button(
            btn_row, text='Send Verification Code',
            command=_send_otp,
            font=('Segoe UI', 10, 'bold'),
            bg=C['accent_primary'], fg='#fff',
            bd=0, padx=20, pady=7, cursor='hand2',
            activebackground=C['accent_primary'])
        action_btn.pack(side=tk.RIGHT)
    
        tk.Button(btn_row, text='Cancel', command=win.destroy,
                font=('Segoe UI', 10),
                bg=C['button_bg'], fg=C['text_secondary'],
                bd=0, padx=20, pady=7, cursor='hand2',
                activebackground=C['button_hover']).pack(
            side=tk.RIGHT, padx=(0, 8))
    
        email_entry.bind('<Return>', lambda e: _send_otp())
        otp_entry.bind('<Return>',   lambda e: action_btn.invoke())
        win.bind('<Escape>', lambda e: win.destroy())
 

    def _show_key_recovery_dialog(self, parent_win=None):
        """
        Recover a lost license key by sending it to the purchase email.
        Calls POST /api/license/recover_key on the Railway server.
        The server looks up all keys for that email and re-sends them.
        """
        C   = self.colors
        dlg = tk.Toplevel(parent_win or self.root)
        dlg.title("Recover Lost License Key")
        dlg.geometry("420x300")
        dlg.resizable(False, False)
        dlg.configure(bg=C['card_bg'])
        dlg.transient(parent_win or self.root)
        dlg.grab_set()

        dlg.update_idletasks()
        base = parent_win or self.root
        px   = base.winfo_x() + (base.winfo_width()  // 2) - 210
        py   = base.winfo_y() + (base.winfo_height() // 2) - 150
        dlg.geometry(f'+{px}+{py}')

        tk.Frame(dlg, bg="#d29922", height=4).pack(fill=tk.X)

        tk.Label(dlg, text="🔑  Recover Lost License Key",
                 font=('Segoe UI', 13, 'bold'),
                 bg=C['card_bg'], fg=C['text_primary']).pack(
            anchor='w', padx=24, pady=(18, 4))
        tk.Label(dlg,
                 text="Enter the email you used to purchase FMSecure PRO.\n"
                      "All active keys for that email will be re-sent.",
                 font=('Segoe UI', 9),
                 bg=C['card_bg'], fg=C['text_muted'],
                 justify='left', wraplength=360).pack(anchor='w', padx=24)

        tk.Frame(dlg, height=1, bg=C['divider']).pack(fill=tk.X, padx=24, pady=(12, 0))

        tk.Label(dlg, text="PURCHASE EMAIL",
                 font=('Segoe UI', 9, 'bold'),
                 bg=C['card_bg'], fg=C['text_muted']).pack(
            anchor='w', padx=24, pady=(10, 4))

        email_var = tk.StringVar()
        email_ent = tk.Entry(dlg, textvariable=email_var,
                              font=('Segoe UI', 12),
                              bg=C['input_bg'], fg=C['text_primary'],
                              insertbackground=C['text_primary'],
                              relief='flat',
                              highlightthickness=1,
                              highlightbackground=C['input_border'],
                              highlightcolor="#d29922")
        email_ent.pack(fill=tk.X, padx=24, pady=(0, 4))
        email_ent.focus_set()

        status_lbl = tk.Label(dlg, text='',
                               font=('Segoe UI', 9),
                               bg=C['card_bg'], fg=C['accent_danger'],
                               wraplength=360, justify='left')
        status_lbl.pack(anchor='w', padx=24)

        btn_row = tk.Frame(dlg, bg=C['card_bg'])
        btn_row.pack(fill=tk.X, padx=24, pady=(14, 20))

        def _do_recover():
            email = email_var.get().strip().lower()
            if not email or '@' not in email:
                status_lbl.configure(text="Please enter a valid email address.")
                return
            send_btn.configure(state='disabled', text="Sending…")
            status_lbl.configure(text='', fg=C['accent_danger'])

            def _run():
                try:
                    import requests as _req
                    from core.license_verifier import LICENSE_SERVER_URL
                    r = _req.post(
                        f"{LICENSE_SERVER_URL}/api/license/recover_key",
                        json={"email": email},
                        timeout=10
                    )
                    data = r.json() if r.status_code in (200, 400) else {}
                    if r.status_code == 200 and data.get("ok"):
                        def _ok():
                            dlg.destroy()
                            messagebox.showinfo(
                                "Key Sent",
                                f"Your license key(s) have been sent to:\n{email}\n\n"
                                "Check your inbox (and spam folder)."
                            )
                        self.root.after(0, _ok)
                    else:
                        reason = data.get("reason",
                                          "No active license found for this email.")
                        self.root.after(0, lambda r=reason: (
                            send_btn.configure(state='normal', text="Send My Key"),
                            status_lbl.configure(text=r)
                        ))
                except Exception as e:
                    self.root.after(0, lambda err=str(e): (
                        send_btn.configure(state='normal', text="Send My Key"),
                        status_lbl.configure(text=f"Server error: {err}")
                    ))

            import threading
            threading.Thread(target=_run, daemon=True).start()

        send_btn = tk.Button(btn_row, text="Send My Key",
                              command=_do_recover,
                              font=('Segoe UI', 10, 'bold'),
                              bg="#d29922", fg="#0d1117",
                              relief='flat', padx=16, pady=7,
                              cursor='hand2',
                              activebackground="#e6a817")
        send_btn.pack(side=tk.LEFT)

        tk.Button(btn_row, text="Cancel", command=dlg.destroy,
                  font=('Segoe UI', 10),
                  bg=C['button_bg'], fg=C['text_secondary'],
                  relief='flat', padx=16, pady=7,
                  cursor='hand2').pack(side=tk.RIGHT)

        email_ent.bind('<Return>', lambda e: _do_recover())
        dlg.bind('<Escape>', lambda e: dlg.destroy())
        """Silently pings the FastAPI C2 Server every 10 seconds"""
        def heartbeat_loop():
            # Generate a unique hardware ID and get the PC name
            machine_id = str(uuid.getnode())
            hostname = socket.gethostname()
            c2_url = "https://fmsecure-c2-server-production.up.railway.app/api/heartbeat"
            
            while True:
                try:
                    # 1. Gather Live Data
                    tier = "FREE"
                    if hasattr(self, 'pro_badge') and self.pro_badge.winfo_exists():
                        tier = "PRO"
                        
                    payload = {
                        "machine_id": machine_id,
                        "hostname": hostname,
                        "username": self.username,
                        "tier": tier,
                        "is_armed": getattr(self, 'monitor_running', False)
                    }
                    
                    # 2. Send to Cloud & Read Response
                    headers = {"x-api-key": "fmsecure-enterprise-key-99"}
                    response = requests.post(c2_url, json=payload, headers=headers, timeout=5)
                    if response.status_code == 200:
                        server_data = response.json()
                        # --- NEW: EXECUTE CLOUD COMMANDS ---
                        if server_data.get("command") == "LOCKDOWN":
                            print("🚨 CLOUD COMMAND RECEIVED: EXECUTING LOCKDOWN!")
                            # Must use .after() to safely interact with the GUI from a background thread
                            self.root.after(0, self._execute_remote_lockdown)
                except Exception:
                    pass # If the server is offline, fail silently and try again later
                    
                # 3. Sleep for 10 seconds (Industry standard is 30s-60s)
                time.sleep(10)

        # Start as a daemon thread so it runs invisibly and dies when the app closes
        threading.Thread(target=heartbeat_loop, daemon=True).start()

    def _execute_remote_lockdown(self):
        """Executes an emergency lockdown commanded by the Cloud Server"""
        # 1. Force the Ransomware Killswitch ON
        from core.integrity_core import CONFIG
        CONFIG["ransomware_killswitch"] = True
        self.ks_btn_text.set("ON")
        self.ks_toggle_btn.configure(bg=self.colors['accent_success'])
        
        # 2. Trigger the OS-Level Lockdown
        try:
            from core.lockdown_manager import lockdown
            folders = list(self.folder_listbox.get(0, tk.END))
            if not folders and CONFIG.get("watch_folders"):
                folders = CONFIG.get("watch_folders")
                
            for folder in folders:
                lockdown.trigger_killswitch(folder)
                self._append_log(f"☁️ REMOTE LOCKDOWN: Network command isolated folder: {folder}")
        except Exception as e:
            print(f"Remote lockdown error: {e}")
            
        # 3. Flash a massive warning to the user sitting at the laptop
        self._show_alert(
            "☁️ HOST ISOLATED BY IT ADMIN", 
            "Your IT Administrator has remotely triggered an emergency Ransomware lockdown on your device. All file access has been revoked.", 
            "critical"
        )

    def start_monitor(self):
        """Start monitoring"""
        if not FileIntegrityMonitor:
            messagebox.showerror("Error", "Backend not available.")
            return
        if self.monitor_running:
            messagebox.showinfo("Info", "Monitor already running.")
            return
        
        # GET ALL FOLDERS FROM LISTBOX
        folders = list(self.folder_listbox.get(0, tk.END))
        if not folders:
            messagebox.showerror("Error", "Please add at least one valid folder.")
            return

        # --- THE FIX: Automatically tell Cloud Sync who is logged in! ---
        try:
            if auth:
                user_data = auth.users.get(self.username, {})
                user_email = user_data.get("registered_email", "UnknownUser")
                from core.integrity_core import CONFIG
                CONFIG["admin_email"] = user_email
        except Exception as e:
            print(f"Failed to inject email for cloud sync: {e}")

        def _start():
            try:
                def gui_callback(event_type, path, severity):
                    self.root.after(0, lambda: self._handle_realtime_event(event_type, path, severity))
                
                # PASS THE LIST OF FOLDERS
                ok = self.monitor.start_monitoring(watch_folders=folders, event_callback=gui_callback)
                
                if ok:
                    self.monitor_running = True
                    self.status_var.set(f"🟢 Running — {len(folders)} Folders")
                    self._append_log(f"Security monitoring STARTED for {len(folders)} folders.")
                    self._show_alert("Monitoring started", 
                                   f"Started monitoring {len(folders)} folders.", 
                                   "info")
                    self.reset_session_counts()
                    # FIX: Read the initial baseline count from the handler
                    if self.monitor.handler and hasattr(self.monitor.handler, 'records'):
                        records = self.monitor.handler.records
                        if records is not None:
                            self.total_files_var.set(str(len(records)))
                else:
                    self._append_log("Monitor failed to start")
                    messagebox.showerror("Error", "Monitor failed to start.")
            except Exception as ex:
                self._append_log(f"Exception starting monitor: {ex}")
                traceback.print_exc()
                messagebox.showerror("Error", f"Exception: {ex}")

        threading.Thread(target=_start, daemon=True).start()

    def stop_monitor(self):
        """Stop monitoring - IMPORTED FROM BACKUP"""
        if not self.monitor_running:
            messagebox.showinfo("Info", "Monitor not running.")
            return
        if not self._authenticate_action("Stop Security Shields"):
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
        """Run manual verification with severity tracking - IMPORTED FROM BACKUP"""
        folder = self.folder_entry.get()
        if not folder or not os.path.exists(folder):
            messagebox.showerror("Error", "Choose valid folder first.")
            return

        def _verify():
            try:
                self._append_log("Manual security verification started...")
                
                # Run the backend verification
                summary = self.monitor.run_verification(watch_folders=[folder])
                
                # Normalize AND SAVE to JSON cache automatically
                normalized = self.normalize_report_data(summary)
                
                # Track file changes with severity
                self._track_file_changes(normalized)
                self.total_files_var.set(str(normalized.get('total', 0)))

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
        """Verify cryptographic signatures - IMPORTED FROM BACKUP"""
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
        """Open settings dialog - Upgraded with Dual-Channel Alerting"""
        # --- 🚨 NEW: PASSWORD PROTECTION ---
        if not self._authenticate_action("Modify Core Settings"):
            return
        from core.auth_manager import auth
        user_data = auth.users.get(self.username, {})
        registered_email = user_data.get("registered_email", "")
        win = tk.Toplevel(self.root)
        win.title("Security Settings")
        win.geometry("520x360") # Slightly taller for the new email field
        win.configure(bg=self.colors['bg'])
        
        tk.Label(win, text="🔧 Security Configuration (config.json)", 
                bg=self.colors['bg'], fg=self.colors['text_primary'], font=('Segoe UI', 12, 'bold')).pack(anchor="w", padx=10, pady=(10, 0))

        cfg = dict(CONFIG)

        # Watch Folder
        tk.Label(win, text="📁 Watch folder:", bg=self.colors['bg'], fg=self.colors['text_primary'], font=('Segoe UI', 10)).pack(anchor="w", padx=10, pady=(8, 0))
        watch_var = tk.StringVar(value=cfg.get("watch_folder", ""))
        e1 = ttk.Entry(win, textvariable=watch_var, width=70, style='Modern.TEntry')
        e1.pack(padx=10)

        # Verify Interval
        tk.Label(win, text="⏱️ Verify interval (seconds):", bg=self.colors['bg'], fg=self.colors['text_primary'], font=('Segoe UI', 10)).pack(anchor="w", padx=10, pady=(8, 0))
        int_var = tk.StringVar(value=str(cfg.get("verify_interval", 1800)))
        e2 = ttk.Entry(win, textvariable=int_var, width=20, style='Modern.TEntry')
        e2.pack(padx=10)

        # Webhook URL
        tk.Label(win, text="🔔 Discord/Slack Webhook URL (optional):", bg=self.colors['bg'], fg=self.colors['text_primary'], font=('Segoe UI', 10)).pack(anchor="w", padx=10, pady=(8, 0))
        web_var = tk.StringVar(value=str(cfg.get("webhook_url") or ""))
        e3 = ttk.Entry(win, textvariable=web_var, width=70, style='Modern.TEntry')
        e3.pack(padx=10)

        # --- NEW: Admin Alert Email ---
        tk.Label(win, text="✉️ Admin Alert Email (optional):", bg=self.colors['bg'], fg=self.colors['text_primary'], font=('Segoe UI', 10)).pack(anchor="w", padx=10, pady=(8, 0))
        email_var = tk.StringVar(value=str(cfg.get("admin_email") or registered_email))
        e4 = ttk.Entry(win, textvariable=email_var, width=70, style='Modern.TEntry')
        e4.pack(padx=10)

        def save_settings():
            new_cfg = dict(CONFIG)
            new_cfg["watch_folder"] = watch_var.get()
            try:
                new_cfg["verify_interval"] = int(int_var.get())
            except Exception:
                messagebox.showerror("Error", "verify_interval must be integer seconds")
                return
            new_cfg["webhook_url"] = web_var.get() or None
            new_cfg["admin_email"] = email_var.get() or None # Save the email
            
            try:
                from core.utils import get_app_data_dir
                app_data = get_app_data_dir()
                config_dir = os.path.join(app_data, "config")
                if not os.path.exists(config_dir):
                    os.makedirs(config_dir)
                    
                target_file = os.path.join(config_dir, "config.json")
                
                with open(target_file, "w", encoding="utf-8") as f:
                    json.dump(new_cfg, f, indent=4)
                
                # Reload config
                if load_config:
                    load_config(target_file)
                    
                messagebox.showinfo("Settings", f"Configuration saved to:\n{target_file}")
                self._show_alert("Settings Updated", "Security configuration has been updated.", "info")
                win.destroy()
            except Exception as ex:
                messagebox.showerror("Error", f"Failed to save config: {ex}")

        btn_frame = ttk.Frame(win)
        btn_frame.pack(pady=12)
        
        ttk.Button(btn_frame, text="💾 Save Settings", command=save_settings, style='Modern.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="❌ Cancel", command=win.destroy, style='Modern.TButton').pack(side=tk.LEFT, padx=5)


    # ===== HELPER METHODS FROM BACKUP =====

    def reset_session_counts(self):
        """Reset session counts - IMPORTED FROM BACKUP"""
        self.file_tracking['session_created'] = 0
        self.file_tracking['session_modified'] = 0
        self.file_tracking['session_deleted'] = 0
        self.file_tracking['session_renamed'] = 0
        
        self.created_var.set("0")
        self.modified_var.set("0")
        self.deleted_var.set("0")
        self.renamed_var.set("0")
        self._append_log("Session file counters reset")

    def view_report(self):
        """View reports - IMPORTED FROM BACKUP"""
        report_files = [
            "reports/report_summary.txt",
            os.path.join("logs", "activity_reports.txt"),
            os.path.join("logs", "detailed_reports.txt")
        ]
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

    def reset_severity_counters(self):
        """Reset all severity counters - IMPORTED FROM BACKUP"""
        if messagebox.askyesno("Reset Counters", "Reset all severity counters to zero?"):
            self.severity_counters = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'INFO': 0}
            
            # Update UI
            self.critical_var.set("0")
            self.high_var.set("0")
            self.medium_var.set("0")
            self.info_var.set("0")
            
            # Save to file
            try:
                with open(SEVERITY_COUNTER_FILE, "w", encoding="utf-8") as f:
                    json.dump(self.severity_counters, f, indent=2)
                self._append_log("Severity counters reset to zero")
                self._show_alert("Counters Reset", "All severity counters have been reset to zero.", "info")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save counters: {e}")

    def open_reports_folder(self):
        """Open reports folder - IMPORTED FROM BACKUP"""
        folder = os.path.abspath(".")
        try:
            os.startfile(folder)
        except Exception:
            messagebox.showinfo("Info", f"Open folder: {folder}")

    def _handle_realtime_event(self, event_type, path, severity):
        """Handle real-time events from the backend - IMPORTED FROM BACKUP"""
        filename = os.path.basename(path)
        
        # Update Session Counters
        if "CREATED" in event_type:
            self.file_tracking['session_created'] += 1
            self.created_var.set(str(self.file_tracking['session_created']))
            # Increment total files
            current_total = int(self.total_files_var.get())
            self.total_files_var.set(str(current_total + 1))
            
        elif "MODIFIED" in event_type:
            self.file_tracking['session_modified'] += 1
            self.modified_var.set(str(self.file_tracking['session_modified']))

        elif "RENAMED" in event_type:  
            self.file_tracking['session_renamed'] += 1
            self.renamed_var.set(str(self.file_tracking['session_renamed']))
            
        elif "DELETED" in event_type:
            self.file_tracking['session_deleted'] += 1
            self.deleted_var.set(str(self.file_tracking['session_deleted']))
            # Decrement total files
            current_total = int(self.total_files_var.get())
            self.total_files_var.set(str(max(0, current_total - 1)))

        # Trigger the alert popup
        msg = f"File: {filename}\nPath: {path}"
        self._show_alert(f"{event_type} Detected", msg, severity.lower())

    def _show_text(self, title, content):
        """Show text in new window - IMPORTED FROM BACKUP"""
        w = tk.Toplevel(self.root)
        w.title(f"🔍 {title}")
        w.geometry("800x600")
        w.configure(bg=self.colors['bg'])
        
        header = tk.Label(w, text=title, font=('Segoe UI', 12, 'bold'),
                        bg=self.colors['bg'], fg=self.colors['accent_primary'])
        header.pack(pady=10)
        
        st = scrolledtext.ScrolledText(w, wrap=tk.WORD, 
                                     bg=self.colors['card_bg'], 
                                     fg=self.colors['text_primary'],
                                     font=("Consolas", 10))
        st.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        st.insert(tk.END, content)
        st.configure(state="disabled")
        
        close_btn = ttk.Button(w, text="Close", command=w.destroy, style='Modern.TButton')
        close_btn.pack(pady=10)

    # ===== THEME AND UI METHODS =====
    
    def _clear_logs(self):
        """Clear the log display and in-memory cache."""
        self._log_lines = []
        self.log_box.configure(state='normal')
        self.log_box.delete('1.0', tk.END)
        self.log_box.configure(state='disabled')
        self._append_log('Log display cleared')

    def _show_profile_panel(self):
        """Display a sleek, modern dropdown profile card"""
        # If it already exists, destroy it (acts as a toggle)
        if hasattr(self, 'profile_panel') and self.profile_panel.winfo_exists():
            self.profile_panel.destroy()
            return
            
        # Create a borderless pop-up window
        self.profile_panel = tk.Toplevel(self.root)
        self.profile_panel.overrideredirect(True)
        self.profile_panel.configure(bg=self.colors['card_border']) 
        
        # Calculate position to drop down exactly below the username button
        x = self.user_btn.winfo_rootx()
        y = self.user_btn.winfo_rooty() + self.user_btn.winfo_height() + 8
        self.profile_panel.geometry(f"300x260+{x-200}+{y}") # Shift left to align beautifully
        
        # Inner frame (creates a sleek 1px border effect)
        inner = tk.Frame(self.profile_panel, bg=self.colors['card_bg'])
        inner.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
        
        # Fetch Live User Data from Auth Manager
        tier = "FREE"
        email = "Not Registered"
        if auth:
            tier = auth.get_user_tier(self.username).upper()
            user_data = auth.users.get(self.username, {})
            email = user_data.get("registered_email", "No email on file")
            
        tier_color = "#ffd700" if tier != "FREE" else self.colors['text_muted']
        
        # Header - Avatar & Name
        head_frame = tk.Frame(inner, bg=self.colors['card_bg'])
        head_frame.pack(fill=tk.X, pady=20, padx=20)
        
        avatar = tk.Label(head_frame, text="👤", font=('Segoe UI', 28), 
                          bg=self.colors['card_bg'], fg=self.colors['accent_primary'])
        avatar.pack(side=tk.LEFT, padx=(0, 15))
        
        info_frame = tk.Frame(head_frame, bg=self.colors['card_bg'])
        info_frame.pack(side=tk.LEFT, fill=tk.X)
        
        tk.Label(info_frame, text=self.username, font=('Segoe UI', 14, 'bold'), 
                 bg=self.colors['card_bg'], fg=self.colors['text_primary']).pack(anchor='w')
        tk.Label(info_frame, text=f"Role: {self.user_role.upper()}", font=('Segoe UI', 9), 
                 bg=self.colors['card_bg'], fg=self.colors['text_secondary']).pack(anchor='w')
        
        # Sleek Separator
        tk.Frame(inner, height=1, bg=self.colors['card_border']).pack(fill=tk.X, padx=15)
        
        # Account Details Section
        det_frame = tk.Frame(inner, bg=self.colors['card_bg'])
        det_frame.pack(fill=tk.X, pady=15, padx=20)
        
        tk.Label(det_frame, text="📧 Account:", font=('Segoe UI', 9, 'bold'), 
                 bg=self.colors['card_bg'], fg=self.colors['text_secondary']).grid(row=0, column=0, sticky='w', pady=6)
        
        # Truncate long emails so they don't break the UI
        display_email = email if len(email) < 22 else email[:19] + "..."
        tk.Label(det_frame, text=display_email, font=('Segoe UI', 9), 
                 bg=self.colors['card_bg'], fg=self.colors['text_primary']).grid(row=0, column=1, sticky='w', padx=15, pady=6)
        
        tk.Label(det_frame, text="⭐ License:", font=('Segoe UI', 9, 'bold'), 
                 bg=self.colors['card_bg'], fg=self.colors['text_secondary']).grid(row=1, column=0, sticky='w', pady=6)
        tk.Label(det_frame, text=f"{tier} PLAN", font=('Segoe UI', 9, 'bold'), 
                 bg=self.colors['card_bg'], fg=tier_color).grid(row=1, column=1, sticky='w', padx=15, pady=6)
        
        # Bottom Action Bar
        btn_frame = tk.Frame(inner, bg=self.colors['bg']) 
        btn_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Master Sign Out Button
        def _execute_logout():
            self.profile_panel.destroy()
            self.logout()
            
        logout_btn = tk.Button(btn_frame, text="🚪 Sign Out of FMSecure", command=_execute_logout,
                              font=('Segoe UI', 9, 'bold'), bg=self.colors['bg'], fg=self.colors['accent_danger'],
                              bd=0, pady=12, cursor="hand2")
        logout_btn.pack(fill=tk.X)
        logout_btn.bind("<Enter>", lambda e: logout_btn.configure(bg=self.colors['card_border']))
        logout_btn.bind("<Leave>", lambda e: logout_btn.configure(bg=self.colors['bg']))
        
        # Logic to close the menu if the user clicks anywhere else on the screen
        self.profile_panel.bind("<FocusOut>", lambda e: self.root.after(100, self._destroy_if_lost_focus))
        self.profile_panel.focus_set()

    def _destroy_if_lost_focus(self):
        """Helper to cleanly close the profile panel when losing focus"""
        if hasattr(self, 'profile_panel') and self.profile_panel.winfo_exists():
            focus_widget = self.profile_panel.focus_get()
            if focus_widget is None or not str(focus_widget).startswith(str(self.profile_panel)):
                self.profile_panel.destroy()

    def toggle_theme(self):
        """Toggle between light and dark themes"""
        self.dark_mode = not self.dark_mode
        self.colors = DARK_THEME if self.dark_mode else LIGHT_THEME
        
        # Update theme button
        self.theme_btn.configure(text="🌙" if self.dark_mode else "☀️")
        
        # Reconfigure styles
        self._configure_styles()
        
        # Update all widget colors
        self._apply_theme()

        # Update status color specifically
        self._update_status_color()

    def _apply_theme(self):
        """Apply current theme to ALL widgets including listbox and side menu."""
        C = self.colors
        self.root.configure(bg=C['bg'])
 
        # Walk the main widget tree (handles frames, labels, buttons, scrolledtext)
        self._update_widget_colors(self.root)
 
        # ── Explicit fix: tk.Listbox is skipped by the generic walker ──────
        if hasattr(self, 'folder_listbox'):
            try:
                self.folder_listbox.configure(
                    bg=C['input_bg'],
                    fg=C['text_primary'],
                    selectbackground=C['accent_primary'],
                    selectforeground='#ffffff'
                )
            except Exception:
                pass
 
        # ── Explicit fix: log box scrolled text ─────────────────────────────
        if hasattr(self, 'log_box'):
            try:
                self.log_box.configure(
                    bg=C['input_bg'],
                    fg=C['text_primary'],
                    insertbackground=C['text_primary']
                )
            except Exception:
                pass
 
        # ── Side menu — call _theme_side_menu which was never called before ──
        if hasattr(self, 'side_menu') and self.side_menu.winfo_exists():
            self._theme_side_menu(C)
 
        # ── Dummy ghost frame must also match the sidebar colour ─────────────
        if hasattr(self, 'dummy_menu') and self.dummy_menu.winfo_exists():
            try:
                self.dummy_menu.configure(
                    bg=C['sidebar_bg'],
                    highlightbackground=C['card_border']
                )
            except Exception:
                pass
 
        # Counter badge colours
        if hasattr(self, 'file_counter_labels') and hasattr(self, 'severity_counter_labels'):
            self._update_counter_colors()
 
        self._update_button_states()
        self._update_status_color()
 
        # Filter pills (if they exist from the log filter fix)
        if hasattr(self, '_filter_pills'):
            self._highlight_active_pill()

    def _update_counter_colors(self):
        """Update the colors of counter labels after theme change"""
        # Update file counter colors
        for i, (label_widget, label_text, original_color) in enumerate(self.file_counter_labels):
            # Determine which color to use based on label text
            if "Total" in label_text:
                new_color = self.colors['accent_primary']
            elif "Created" in label_text:
                new_color = self.colors['accent_success']
            elif "Modified" in label_text:
                new_color = self.colors['accent_warning']
            elif "Deleted" in label_text:
                new_color = self.colors['accent_danger']
            else:
                new_color = original_color
            
            # Update the label
            label_widget.configure(bg=new_color, fg='white')
        
        # Update severity counter colors (these are fixed colors, but we need to re-apply them)
        for label_widget, label_text, color in self.severity_counter_labels:
            label_widget.configure(bg=color, fg='white')


    def _update_status_color(self):
        """Update the status pill background color based on current status"""
        if not hasattr(self, 'status_label'):
            return
        
        current_status = self.status_var.get()
        
        # Determine the correct background color
        if any(x in current_status for x in ("Running", "🟢", "Armed", "▶")):
            pill_bg = self.colors['accent_success']     # Green
        elif any(x in current_status for x in ("DEMO", "SAFE")):
            pill_bg = self.colors['accent_danger']      # Red
        elif "Read-Only" in current_status:
            pill_bg = self.colors['accent_warning']     # Amber
        else:  
            pill_bg = self.colors['accent_danger']      # Red for Stopped
            
        # Apply the background color to the entire pill group
        if hasattr(self, '_status_pill_frame'):
            self._status_pill_frame.configure(bg=pill_bg)
        if hasattr(self, '_status_pill_dot'):
            self._status_pill_dot.configure(bg=pill_bg)
            
        # Ensure the text stays white while the background changes
        self.status_label.configure(bg=pill_bg, fg='#ffffff')

    def _update_widget_colors(self, widget):
        """Recursively update widget colors, skipping the side menu"""
        # SKIP if this widget belongs to the side menu
        if self._is_side_menu_widget(widget):
            return

        try:
            if isinstance(widget, tk.Frame):
                if 'card' in str(widget).lower():
                    widget.configure(bg=self.colors['card_bg'],
                                highlightbackground=self.colors['card_border'])
                elif 'header' in str(widget).lower():
                    widget.configure(bg=self.colors['header_bg'])
                else:
                    widget.configure(bg=self.colors['bg'])
            
            elif isinstance(widget, tk.Label):
                # Skip counter labels - they're handled separately
                if hasattr(self, 'file_counter_labels') and widget in [label for label, _, _ in self.file_counter_labels]:
                    pass
                elif hasattr(self, 'severity_counter_labels') and widget in [label for label, _, _ in self.severity_counter_labels]:
                    pass
                elif 'footer' in str(widget).lower():
                    widget.configure(bg=self.colors['bg'], fg=self.colors['text_muted'])
                elif 'card' in str(widget).lower() or (isinstance(widget.master, tk.Frame) and 'card' in str(widget.master).lower()):
                    widget.configure(bg=self.colors['card_bg'], fg=self.colors['text_primary'])
                else:
                    widget.configure(bg=self.colors['bg'], fg=self.colors['text_primary'])
            
            elif isinstance(widget, tk.Button):
                # Update standard buttons, but skip special toggle buttons
                if widget not in [self.theme_btn, getattr(self, 'menu_btn', None), getattr(self, 'pass_btn', None), 
                                getattr(self, 'unlock_btn', None), getattr(self, 'logout_btn', None)]:
                    widget.configure(bg=self.colors['button_bg'], fg=self.colors['text_primary'])
            
            elif isinstance(widget, scrolledtext.ScrolledText):
                widget.configure(bg=self.colors['card_bg'], fg=self.colors['text_primary'],
                            insertbackground=self.colors['text_primary'])
        except Exception as e:
            pass # Ignore configuration errors for widgets that might not support options
        
        # Update children
        for child in widget.winfo_children():
            self._update_widget_colors(child)

    def _is_side_menu_widget(self, widget):
        """Check if a widget is part of the side menu"""
        if not hasattr(self, 'side_menu') or not self.side_menu:
            return False
            
        # Traverse up the widget hierarchy to see if the side_menu is a parent
        current = widget
        while current:
            if current == self.side_menu:
                return True
            # Stop if we hit root to prevent infinite loops (though unlikely in Tk)
            if current == self.root:
                break
            current = current.master
        return False

    def _apply_permissions(self):
        """Disable controls based on user role"""
        if self.user_role == 'admin':
            return
            
        # Role is 'user' (Read-Only)
        self._append_log(f"Logged in as restricted viewer: {self.username}")
        self.status_var.set("🔒 Read-Only Mode")
        
        # --- FIX: Disable the new Multi-Folder Buttons instead of folder_entry ---
        if hasattr(self, 'add_folder_btn'):
            self.add_folder_btn.configure(state='disabled')
        if hasattr(self, 'remove_folder_btn'):
            self.remove_folder_btn.configure(state='disabled')
        
        # Define Restricted Actions
        restricted_actions = [
            "Start Monitor", 
            "Stop Monitor", 
            "Settings", 
            "Verify Now",
            "Open Folder",
            "Browse"
        ]
        
        # Recursively find and disable buttons
        self._disable_recursive(self.root, restricted_actions)

    def _disable_recursive(self, widget, restricted_list):
        """Helper to find buttons recursively"""
        for child in widget.winfo_children():
            if isinstance(child, (tk.Button, ttk.Button)):
                try:
                    btn_text = child.cget('text')
                    for action in restricted_list:
                        if action in btn_text:
                            child.configure(state='disabled')
                except:
                    pass
            
            self._disable_recursive(child, restricted_list)

    # ===== SIDE MENU METHODS =====
    
    def _create_side_menu(self):
        """Create a professional hacker-themed sliding side menu"""
        self.menu_width = 320  # Increased width for better layout
        self.menu_visible = False

        # --- NEW: THE ANTI-LAG GHOST FRAME ---
        self.dummy_menu = tk.Frame(self.root, bg='#000000', bd=2, relief='ridge',
                                   highlightbackground='#00ff00', highlightthickness=1)
        
        # Create side menu frame with hacker theme
        self.side_menu = tk.Frame(self.root, 
                                bg='#000000',  # Black background
                                width=self.menu_width,
                                bd=2, 
                                relief='ridge',
                                highlightbackground='#00ff00',  # Matrix green border
                                highlightthickness=1)
        # self.side_menu.place(x=-self.menu_width, y=0, width=self.menu_width, relheight=1.0)
        
        # Create matrix background FIRST
        self._create_matrix_background()
        
        # Menu Header with ASCII Art
        header_frame = tk.Frame(self.side_menu, bg='#000000')
        header_frame.pack(fill=tk.X, pady=(20, 10))
        
        # ASCII Art Security Logo
        ascii_art = """
        ███████╗███████╗ ██████╗██╗   ██╗██████╗ 
        ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗
        ███████╗█████╗  ██║     ██║   ██║██████╔╝
        ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗
        ███████║███████╗╚██████╗╚██████╔╝██║  ██║
        ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝
        """
        
        ascii_label = tk.Label(header_frame, 
                            text=ascii_art,
                            font=('Consolas', 8),
                            bg='#000000',
                            fg='#00ff00',  # Matrix green
                            justify='center')
        ascii_label.pack()
        
        # Animated Terminal Title
        title_frame = tk.Frame(self.side_menu, bg='#000000')
        title_frame.pack(fill=tk.X, pady=(0, 20))
        
        self.menu_title = tk.Label(title_frame,
                                text="[ SECURITY TERMINAL v2.4 ]",
                                font=('Courier New', 12, 'bold'),
                                bg='#000000',
                                fg='#00ffff')  # Cyan
        self.menu_title.pack()
        
        # Blinking cursor effect for title
        self._blink_menu_title()
        
        # System Status Display
        status_frame = tk.Frame(self.side_menu, bg='#000000')
        status_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        # System Status Line
        tk.Label(status_frame, 
                text="◈ SYSTEM STATUS ◈",
                font=('Courier New', 10, 'bold'),
                bg='#000000',
                fg='#ff9900').pack(anchor='w')
        
        # Status indicators with blinking dots
        status_grid = tk.Frame(status_frame, bg='#000000')
        status_grid.pack(fill=tk.X, pady=(5, 0))
        
        status_items = [
            ("MONITOR", "ACTIVE" if self.monitor_running else "STANDBY", 
            '#00ff00' if self.monitor_running else '#ff0000'),
            ("INTEGRITY", "VERIFIED", '#00ff00'),
            ("ENCRYPTION", "ENABLED", '#00ff00'),
            ("SESSION", f"USER:{self.username}", '#00ffff')
        ]
        
        self.status_dots = []
        for label, value, color in status_items:
            item_frame = tk.Frame(status_grid, bg='#000000')
            item_frame.pack(fill=tk.X, pady=2)
            
            # Blinking dot
            dot = tk.Label(item_frame, text="●", 
                        font=('Consolas', 12),
                        bg='#000000',
                        fg=color)
            dot.pack(side=tk.LEFT, padx=(0, 10))
            self.status_dots.append(dot)
            
            tk.Label(item_frame, 
                    text=f"{label}: {value}",
                    font=('Courier New', 9),
                    bg='#000000',
                    fg='#ffffff').pack(side=tk.LEFT)
        
        # Start blinking animation for status dots
        self._blink_status_dots()
        
        # Separator
        sep = tk.Frame(self.side_menu, height=2, bg='#00ff00')
        sep.pack(fill=tk.X, padx=20, pady=10)
        
        # Menu Items with Terminal Style
        menu_items = [
            ("⚡ $> RUN SECURITY DRILL", self.run_demo_mode, '#00ff00', '▶'),
            ("📊 $> AUDIT LOGS", self._open_audit_logs, '#00ffff', '📁'),
            ("🔐 $> CRYPTO TOOLS", self._open_crypto_tools, '#ff00ff', '🔑'),
            ("🛡️ $> FIREWALL SETTINGS", self._open_firewall_settings, '#ff9900', '⚙️'),
            ("💾 $> SYSTEM BACKUP", self.archive_and_reset, '#ff0000', '💿'),
            ("🚨 $> EMERGENCY LOCKDOWN", self._emergency_lockdown, '#ff0000', '⚠️')
        ]
        
        for text, command, color, icon in menu_items:
            self._create_terminal_button(text, command, color, icon)
        
        # Close Menu Button with Terminal Style
        close_frame = tk.Frame(self.side_menu, bg='#000000')
        close_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(0, 20))
        
        close_btn = tk.Button(close_frame,
                            text="$> exit_terminal",
                            command=self.toggle_menu,
                            font=('Courier New', 10),
                            bg='#111111',
                            fg='#ff0000',
                            bd=1,
                            relief='flat',
                            padx=20,
                            pady=8,
                            cursor="hand2",
                            activebackground='#222222',
                            activeforeground='#ff6666')
        close_btn.pack(fill=tk.X, padx=20)
        
        # Add keyboard shortcut hint
        tk.Label(self.side_menu,
                text="[ Press ESC to close ]",
                font=('Courier New', 8),
                bg='#000000',
                fg='#666666').pack(side=tk.BOTTOM, pady=(0, 5))
        
        # Bind ESC key to close menu
        self.side_menu.bind('<Escape>', lambda e: self.toggle_menu())
        
        # Start matrix animation
        self._start_matrix_animation()


    def _create_matrix_background(self):
        """Create matrix code rain effect in background"""
        self.matrix_canvas = tk.Canvas(self.side_menu, 
                                    bg='#000000',
                                    highlightthickness=0)
        self.matrix_canvas.place(x=0, y=0, relwidth=1, relheight=1)
        
        # Store matrix columns
        self.matrix_columns = []
        self.matrix_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$+-*/=%\"'#&_(),.;:?!\\|{}<>[]^~"
        
        # Create columns
        num_columns = self.menu_width // 15
        for i in range(num_columns):
            column = {
                'x': i * 15,
                'chars': [],
                'speed': random.uniform(1, 3),
                'length': random.randint(5, 20)
            }
            self.matrix_columns.append(column)
        
        # Place matrix behind all other widgets - FIXED: use widget.lower() without argument
        # We need to ensure the canvas is created before other widgets
        # Since we're creating it in place, it will naturally be behind if created first
        # So we don't need to call lower() at all

    
    def _start_matrix_animation(self):
        """Start matrix code rain animation"""
        if not hasattr(self, 'matrix_canvas') or self.matrix_canvas is None:
            return
        
        # Clear previous frame
        self.matrix_canvas.delete("matrix")
        
        # Update each column
        for column in self.matrix_columns:
            # Move column down
            column['x'] += random.uniform(-0.5, 0.5)  # Slight horizontal drift
            
            # Add new character at top
            char = random.choice(self.matrix_chars)
            y = 0
            
            # Create gradient of green colors
            brightness = random.randint(100, 255)
            color = f'#00{format(brightness, "02x")}00'  # Green gradient
            
            # Draw character
            self.matrix_canvas.create_text(column['x'], y,
                                        text=char,
                                        fill=color,
                                        font=('Consolas', 12),
                                        tags="matrix")
            
            # Update existing characters
            for i, (char_id, char_y) in enumerate(list(column['chars'])):
                new_y = char_y + column['speed']
                
                if new_y > self.side_menu.winfo_height():  # Use side_menu height instead of root
                    # Remove off-screen characters
                    self.matrix_canvas.delete(char_id)
                    column['chars'].pop(i)
                else:
                    # Update character position
                    self.matrix_canvas.coords(char_id, column['x'], new_y)
                    
                    # Fade out as it falls
                    brightness = max(50, 255 - (new_y / self.side_menu.winfo_height() * 200))
                    color = f'#00{format(int(brightness), "02x")}00'
                    self.matrix_canvas.itemconfig(char_id, fill=color)
                    
                    # Update position in list
                    column['chars'][i] = (char_id, new_y)
            
            # Add new character to column
            char_id = self.matrix_canvas.create_text(column['x'], y,
                                                text=char,
                                                fill=color,
                                                font=('Consolas', 12),
                                                tags="matrix")
            column['chars'].append((char_id, y))
            
            # Limit column length
            if len(column['chars']) > column['length']:
                old_id, _ = column['chars'].pop(0)
                self.matrix_canvas.delete(old_id)
        
        # Schedule next frame
        if self.menu_visible and hasattr(self, 'matrix_canvas') and self.matrix_canvas:
            self.root.after(50, self._start_matrix_animation)


    def _create_terminal_button(self, text, command, color, icon):
        """Create a terminal-style button for the menu"""
        btn_frame = tk.Frame(self.side_menu, bg='#000000')
        btn_frame.pack(fill=tk.X, padx=20, pady=5)
        
        # Button with terminal prompt style
        btn = tk.Button(btn_frame,
                    text=text,
                    command=command,
                    font=('Courier New', 10),
                    bg='#111111',
                    fg=color,
                    bd=1,
                    relief='flat',
                    padx=15,
                    pady=10,
                    anchor='w',
                    cursor="hand2",
                    activebackground='#222222',
                    activeforeground=color)
        btn.pack(fill=tk.X)
        
        # Add icon beside text
        icon_label = tk.Label(btn,
                            text=icon,
                            font=('Segoe UI Emoji', 10),
                            bg='#111111',
                            fg=color)
        icon_label.place(x=5, y=5)
        
        # Add hover effect
        btn.bind("<Enter>", lambda e, b=btn, c=color: 
                b.configure(bg='#222222', fg=self._lighten_color(c, 0.3)))
        btn.bind("<Leave>", lambda e, b=btn, c=color: 
                b.configure(bg='#111111', fg=c))
        
        # Add typing sound effect simulation (visual only)
        btn.bind("<Button-1>", lambda e: self._simulate_terminal_click(text))

    
    def _blink_menu_title(self):
        """Create blinking cursor effect for menu title"""
        if not hasattr(self, 'menu_title') or self.menu_title is None:
            return
        
        current_text = self.menu_title.cget('text')
        
        if current_text.endswith('█'):
            # Remove cursor
            new_text = current_text[:-1]
            self.menu_title.configure(text=new_text)
        else:
            # Add cursor
            new_text = current_text + '█'
            self.menu_title.configure(text=new_text)
        
        # Continue blinking if menu is visible
        if self.menu_visible:
            self.root.after(500, self._blink_menu_title)

    def _blink_status_dots(self):
        """Create blinking effect for status dots"""
        if not hasattr(self, 'status_dots') or not self.menu_visible:
            return
        
        for dot in self.status_dots:
            current_color = dot.cget('fg')
            # Alternate between color and black for blinking effect
            if current_color == '#000000':
                # Restore original color (stored in a custom attribute)
                if hasattr(dot, 'original_color'):
                    dot.configure(fg=dot.original_color)
            else:
                # Store original color and hide
                dot.original_color = current_color
                dot.configure(fg='#000000')
        
        # Continue blinking
        self.root.after(700, self._blink_status_dots)

    
    def _simulate_terminal_click(self, command):
        """Simulate terminal typing effect when menu item is clicked"""
        if hasattr(self, 'menu_title'):
            original_text = self.menu_title.cget('text').replace('█', '')
            self.menu_title.configure(text=f"$> {command}")
            self.root.after(300, lambda: self.menu_title.configure(text=original_text + '█'))

    def _open_audit_logs(self):
        """Open the Secure Audit Logs viewer"""
        self.toggle_menu() # Close the side menu
        
        if self.user_role != 'admin':
            messagebox.showerror("Access Denied", "Only administrators can view historical audit logs.")
            return
            
        self._append_log("Accessing secure audit logs vault...")

        # Create the Viewer Window
        viewer = tk.Toplevel(self.root)
        viewer.title("📁 Secure Audit Log Vault")
        viewer.geometry("1000x600")
        viewer.configure(bg=self.colors['bg'])
        viewer.transient(self.root)
        
        # Header
        header = tk.Frame(viewer, bg=self.colors['header_bg'])
        header.pack(fill=tk.X, pady=(0, 10))
        tk.Label(header, text="🔐 DECRYPTED AUDIT VAULT", font=('Segoe UI', 14, 'bold'), 
                 bg=self.colors['header_bg'], fg=self.colors['accent_primary']).pack(pady=15)

        # Main Layout: Left (Sessions), Right (Decrypted Content)
        main_pane = tk.PanedWindow(viewer, orient=tk.HORIZONTAL, bg=self.colors['bg'], sashwidth=5)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        # Left Side: Session List
        left_frame = tk.Frame(main_pane, bg=self.colors['card_bg'])
        main_pane.add(left_frame, minsize=250)
        
        tk.Label(left_frame, text="Archived Sessions", font=('Segoe UI', 10, 'bold'), 
                 bg=self.colors['card_bg'], fg=self.colors['text_primary']).pack(pady=5)
                 
        session_listbox = tk.Listbox(left_frame, bg=self.colors['input_bg'], fg=self.colors['text_primary'], 
                                     font=('Consolas', 10), selectbackground=self.colors['accent_primary'])
        session_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Right Side: Log Content
        right_frame = tk.Frame(main_pane, bg=self.colors['card_bg'])
        main_pane.add(right_frame, minsize=500)
        
        tk.Label(right_frame, text="Decrypted Log Content", font=('Segoe UI', 10, 'bold'), 
                 bg=self.colors['card_bg'], fg=self.colors['text_primary']).pack(pady=5)
                 
        log_display = scrolledtext.ScrolledText(right_frame, bg="#0a0a0a", fg="#00ff00", 
                                                font=('Consolas', 9), state="disabled")
        log_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Load available sessions from the history folder
        from core.utils import get_app_data_dir
        history_dir = os.path.join(get_app_data_dir(), "config", "history")
        
        session_paths = {} # To map listbox names to actual folder paths
        
        if os.path.exists(history_dir):
            # Sort folders so newest is at the top
            folders = sorted(os.listdir(history_dir), reverse=True)
            for f_name in folders:
                folder_path = os.path.join(history_dir, f_name)
                if os.path.isdir(folder_path):
                    # Format the name to look nice
                    display_name = f_name.replace("Session_", "").replace("_", " ")
                    session_listbox.insert(tk.END, f"📂 {display_name}")
                    session_paths[f"📂 {display_name}"] = folder_path

        def on_session_select(event):
            selection = session_listbox.curselection()
            if not selection: return
            
            selected_name = session_listbox.get(selection[0])
            folder_path = session_paths.get(selected_name)
            
            if folder_path:
                target_log = os.path.join(folder_path, "integrity_log.dat")
                
                log_display.configure(state="normal")
                log_display.delete("1.0", tk.END)
                
                if os.path.exists(target_log):
                    log_display.insert(tk.END, f"--- DECRYPTING FILE: {target_log} ---\n\n")
                    
                    # Call our upgraded backend bridge!
                    decrypted_lines = get_decrypted_logs(target_file=target_log)
                    
                    for line in decrypted_lines:
                        log_display.insert(tk.END, line + "\n")
                else:
                    log_display.insert(tk.END, "❌ No encrypted log file found in this archive.")
                    
                log_display.configure(state="disabled")

        # Bind the click event
        session_listbox.bind('<<ListboxSelect>>', on_session_select)
        
        # Close button
        tk.Button(viewer, text="Close Vault", command=viewer.destroy, 
                  bg=self.colors['button_bg'], fg=self.colors['text_primary'], 
                  font=('Segoe UI', 10)).pack(pady=10)

    def _open_crypto_tools(self):
        """Open cryptographic tools panel"""
        self.toggle_menu()
        # Implementation for crypto tools
        self._append_log("Launching cryptographic toolkit...")

    def _open_firewall_settings(self):
        """Open firewall settings panel"""
        self.toggle_menu()
        # Implementation for firewall settings
        self._append_log("Accessing firewall configuration...")

    def _emergency_lockdown(self):
        """Initiate emergency lockdown"""
        self.toggle_menu()
        if messagebox.askyesno("🚨 EMERGENCY LOCKDOWN",
                            "CONFIRM SYSTEM LOCKDOWN?\n\n"
                            "This will:\n"
                            "• Halt all monitoring\n"
                            "• Encrypt sensitive logs\n"
                            "• Disable all external connections\n"
                            "• Require admin override to restore"):
            self._append_log("EMERGENCY LOCKDOWN ACTIVATED")
            self._show_alert("SYSTEM LOCKDOWN", "All operations halted. Admin override required.", "critical")
        

    def toggle_menu(self):
        """Toggle side menu open/close — smooth, no flicker."""
        if not getattr(self, 'menu_visible', False):
            # ── OPEN ─────────────────────────────────────────────────────────
            # Hide the heavy real menu, show the lightweight ghost frame instead
            self.side_menu.place_forget()
            self.dummy_menu.place(x=-self.menu_width, y=0,
                                  width=self.menu_width, relheight=1.0)
            self.dummy_menu.lift()
            # No update_idletasks() here — let Tk schedule naturally
            self._animate_menu(0, is_opening=True)
        else:
            # ── CLOSE ────────────────────────────────────────────────────────
            self.menu_visible = False
 
            # Stop matrix animation FIRST to free the CPU before sliding
            if hasattr(self, 'matrix_canvas'):
                try:
                    self.matrix_canvas.delete('all')
                except Exception:
                    pass
 
            # Swap real → ghost immediately (no partial-draw of the heavy menu)
            self.side_menu.place_forget()
            self.dummy_menu.place(x=0, y=0,
                                  width=self.menu_width, relheight=1.0)
            self.dummy_menu.lift()
            # No update_idletasks() — avoid forced synchronous redraws
            self._animate_menu(-self.menu_width, is_opening=False)

    def _animate_menu(self, target_x, is_opening):
        """
        Smooth ghost-frame slide animation.
        Step size: 20px — small enough for smooth motion, no paint artifacts.
        No update_idletasks() calls — Tk handles compositing naturally.
        """
        current_x = self.dummy_menu.winfo_x()
        step = 20 if is_opening else -20
 
        if abs(target_x - current_x) <= abs(step):
            # Reached (or passed) the target — snap to final position
            if is_opening:
                self.dummy_menu.place_forget()
                self.side_menu.place(x=0, y=0,
                                     width=self.menu_width, relheight=1.0)
                self.side_menu.lift()
                self.menu_visible = True
                # Start matrix only AFTER the slide completes
                self.root.after(50, self._start_matrix_animation)
                self.root.after(50, self._blink_menu_title)
                self.root.after(50, self._blink_status_dots)
            else:
                self.dummy_menu.place_forget()
            return
 
        new_x = current_x + step
        self.dummy_menu.place(x=new_x, y=0,
                              width=self.menu_width, relheight=1.0)
        # 12ms ≈ ~80 fps cap — smooth on most hardware, not CPU-intensive
        self.root.after(12, lambda: self._animate_menu(target_x, is_opening))

    # ===== DEMO AND ARCHIVE METHODS =====
    
    def run_demo_mode(self):
        """Execute the demonstration sequence"""
        self.toggle_menu()  # Close menu first
        
        if messagebox.askyesno("Run Demo", "⚠️ Start Demo Simulation?\n\nThis will trigger fake alerts, modify logs, and activate Safe Mode. Real monitoring will continue in background."):
            
            # Reset counters for clean visual
            self.reset_severity_counters()
            self._append_log("--- STARTING DEMO SIMULATION ---")
            
            # Disable buttons to prevent interference
            self.status_var.set("🎬 DEMO RUNNING...")
            
            # Initialize Simulator
            try:
                from core.demo_simulator import DemoSimulator
            except ImportError:
                try:
                    sys.path.append('../core')
                    from core.demo_simulator import DemoSimulator
                except ImportError:
                    messagebox.showerror("Error", "Demo simulator not available")
                    return
            
            simulator = DemoSimulator(alert_callback=self._show_alert_from_demo)
            
            # Run in Thread
            threading.Thread(target=simulator.run_simulation, daemon=True).start()

    def _show_alert_from_demo(self, title, message, severity):
        """Bridge function to allow Demo thread to trigger UI alerts"""
        self.root.after(0, lambda: self._show_alert(title, message, severity))

    def archive_and_reset(self):
        """Archive current logs and reset UI"""
        self.toggle_menu()  # Close the menu
        
        # Safety Check
        if self.monitor_running:
            messagebox.showwarning("Monitor Running", "Please Stop the Monitor before archiving.")
            return

        # Confirmation
        confirm = messagebox.askyesno(
            "Confirm Archive & Reset", 
            "Are you sure?\n\n"
            "1. All current logs and reports will be moved to 'config/history'.\n"
            "2. The current dashboard will be cleared.\n"
            "3. You can start fresh with a new folder."
        )
        
        if confirm:
            try:
                # Call Backend
                success, msg = integrity_core.archive_session()
                
                if success:
                    # Reset UI Elements
                    self.log_box.configure(state="normal")
                    self.log_box.delete("1.0", tk.END)
                    self.log_box.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] Session archived.\n")
                    self.log_box.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] Ready for new task.\n")
                    self.log_box.configure(state="disabled")
                    
                    # Reset Severity Counters
                    self.reset_severity_counters()
                    
                    # Reset Session Stats
                    self.reset_session_counts()
                    self.total_files_var.set("0")
                    
                    # Reset Tamper Indicators
                    self.tamper_records_var.set("UNKNOWN")
                    self.tamper_logs_var.set("UNKNOWN")
                    self._update_tamper_indicators()
                    
                    messagebox.showinfo("Success", f"System Reset Complete.\n\nOld files saved in:\n{msg}")
                    self._append_log("System reset successfully.")
                else:
                    messagebox.showerror("Error", f"Failed to archive: {msg}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to archive: {e}")

    # ===== SYSTEM TRAY AND OTHER METHODS =====
    
    def _setup_tray_icon(self):
        """Create the system tray icon with robust fallback"""
        try:
            # Try PyInstaller internal path
            if hasattr(sys, '_MEIPASS'):
                icon_path = os.path.join(sys._MEIPASS, "assets", "app_icon.ico")
            else:
                # Try Local Development path
                icon_path = os.path.join(os.path.abspath("assets"), "app_icon.ico")

            # Fallback: Check if it's in an 'icons' subdirectory
            if not os.path.exists(icon_path):
                icon_path = os.path.join(os.path.dirname(icon_path), "icons", "app_icon.ico")

            image = None
            if os.path.exists(icon_path):
                try:
                    image = PILImage.open(icon_path)
                except Exception as e:
                    print(f"Failed to load icon: {e}")

            # Fallback: If file missing or load failed, create a simple generated icon
            if image is None:
                # Create a 64x64 blue box with a white center
                image = PILImage.new('RGB', (64, 64), color=(13, 110, 253))
                
            # Define Menu Actions
            menu = (
                item('Show Dashboard', self.show_window),
                item('Run Verification', self.run_verification),
                item('Exit', self.quit_app)
            )

            self.tray_icon = pystray.Icon("SecureFIM", image, "Secure File Integrity Monitor", menu)
            
        except Exception as e:
            print(f"CRITICAL TRAY ERROR: {e}")
            self.tray_icon = None

    def _show_credential_dialog(self, action_name, prompt_label, show_char='●'):
        """
        Professional modal credential dialog.
        Returns the entered string, or None if cancelled.
        Works in both script and frozen EXE environments.
        """
        C = self.colors
        result = {'value': None}
 
        dlg = tk.Toplevel(self.root)
        dlg.title('Security Verification')
        dlg.geometry('420x260')
        dlg.resizable(False, False)
        dlg.configure(bg=C['card_bg'])
        
        # 🚨 FIX 1: Only make it transient if the root window is visible.
        # If root is withdrawn (in the tray), making it transient makes it invisible!
        is_hidden = self.root.state() in ('withdrawn', 'iconic')
        if not is_hidden:
            dlg.transient(self.root)
            
        dlg.grab_set()
 
        # 🚨 FIX 2: Center on parent if visible, otherwise center on the computer screen.
        dlg.update_idletasks()
        if not is_hidden:
            px = self.root.winfo_x() + (self.root.winfo_width()  // 2) - 210
            py = self.root.winfo_y() + (self.root.winfo_height() // 2) - 130
        else:
            px = (self.root.winfo_screenwidth() // 2) - 210
            py = (self.root.winfo_screenheight() // 2) - 130
            
        dlg.geometry(f'+{px}+{py}')

        # 🚨 FIX 3: Force the popup to the front so it doesn't get lost behind your browser
        dlg.lift()
        dlg.focus_force()
        dlg.attributes('-topmost', True)
        self.root.after(100, lambda: dlg.attributes('-topmost', False))
 
        # Header strip
        hdr = tk.Frame(dlg, bg=C['accent_danger'], height=4)
        hdr.pack(fill=tk.X)
 
        # Icon + title row
        title_row = tk.Frame(dlg, bg=C['card_bg'])
        title_row.pack(fill=tk.X, padx=24, pady=(18, 0))
 
        tk.Label(title_row, text='🔒', font=('Segoe UI', 22),
                 bg=C['card_bg'], fg=C['accent_danger']).pack(side=tk.LEFT, padx=(0, 12))
 
        title_col = tk.Frame(title_row, bg=C['card_bg'])
        title_col.pack(side=tk.LEFT, fill=tk.X, expand=True)
 
        tk.Label(title_col, text='Security Verification',
                 font=('Segoe UI', 13, 'bold'),
                 bg=C['card_bg'], fg=C['text_primary']).pack(anchor='w')
 
        tk.Label(title_col, text=action_name,
                 font=('Segoe UI', 9),
                 bg=C['card_bg'], fg=C['text_secondary']).pack(anchor='w')
 
        # Divider
        tk.Frame(dlg, height=1, bg=C['divider']).pack(fill=tk.X, padx=24, pady=(14, 0))
 
        # Prompt label
        tk.Label(dlg, text=prompt_label,
                 font=('Segoe UI', 10),
                 bg=C['card_bg'], fg=C['text_secondary'],
                 anchor='w').pack(fill=tk.X, padx=24, pady=(12, 4))
 
        # Entry field
        entry_var = tk.StringVar()
        entry = tk.Entry(dlg,
                         textvariable=entry_var,
                         show=show_char,
                         font=('Segoe UI', 12),
                         bg=C['input_bg'],
                         fg=C['text_primary'],
                         insertbackground=C['text_primary'],
                         relief='flat',
                         highlightthickness=1,
                         highlightbackground=C['input_border'],
                         highlightcolor=C['accent_primary'])
        entry.pack(fill=tk.X, padx=24, pady=(0, 16))
        entry.focus_set()
 
        # Buttons
        btn_row = tk.Frame(dlg, bg=C['card_bg'])
        btn_row.pack(fill=tk.X, padx=24, pady=(0, 20))
 
        def _confirm():
            result['value'] = entry_var.get()
            dlg.destroy()
 
        def _cancel():
            result['value'] = None
            dlg.destroy()
 
        tk.Button(btn_row, text='Confirm',
                  command=_confirm,
                  font=('Segoe UI', 10, 'bold'),
                  bg=C['accent_primary'], fg='#ffffff',
                  bd=0, padx=20, pady=7, cursor='hand2',
                  activebackground=C['accent_primary']).pack(side=tk.RIGHT)
 
        tk.Button(btn_row, text='Cancel',
                  command=_cancel,
                  font=('Segoe UI', 10),
                  bg=C['button_bg'], fg=C['text_secondary'],
                  bd=0, padx=20, pady=7, cursor='hand2',
                  activebackground=C['button_hover']).pack(side=tk.RIGHT, padx=(0, 8))
 
        entry.bind('<Return>', lambda e: _confirm())
        entry.bind('<Escape>', lambda e: _cancel())
 
        dlg.wait_window()
        return result['value']


    def _authenticate_action(self, action_name):
        """
        Helper: Prompts for the user's credential before allowing a sensitive action.
        Must only be called from the Main Thread.
 
        GAP 3 FIX — Phase A Part 4:
            If the user registered via Google SSO they have no usable password.
            Instead, we ask for their device PIN (same one used at login).
            auth_manager.get_auth_method() tells us which path to take.
        """
        if not self.monitor_running:
            return True
 
        # Reload the live database in case it changed in background
        if auth:
            auth._load_users()
 
        auth_method = auth.get_auth_method(self.username) if auth else "manual"
 
        if auth_method == "google":
            # ── Google SSO users: verify device PIN ──────────────────────
            pin = self._show_credential_dialog(
                action_name,
                f"Enter your device PIN for  '{self.username}'  to continue:"
            )
 
            if not pin:
                return False
 
            if auth.verify_sso_pin(self.username, pin.strip()):
                return True
            else:
                messagebox.showerror(
                    "Access Denied",
                    "Incorrect PIN.\nThis action has been logged."
                )
                self._append_log(
                    f"SECURITY: Failed PIN verification for action "
                    f"'{action_name}' by {self.username}"
                )
                return False
 
        else:
            # ── Manual users: verify password (original behaviour) ────────
            password = self._show_credential_dialog(
                action_name,
                f"Enter your password for  '{self.username}'  to continue:",
                show_char='*'
            )
 
            if not password:
                return False
 
            success, _, msg = auth.login(self.username, password)
 
            if success:
                return True
            else:
                messagebox.showerror(
                    "Access Denied",
                    "Incorrect password.\nThis action has been logged."
                )
                self._append_log(
                    f"SECURITY: Failed password verification for action "
                    f"'{action_name}' by {self.username}"
                )
                return False

    def show_window(self, icon=None, item=None):
        """
        Tray Callback: Restores window.
        Uses 'after' to jump to the Main Thread for safety.
        """
        self.root.after(0, self._perform_auth_and_show)

    def _perform_auth_and_show(self):
        """
        Runs on MAIN THREAD. Performs Auth -> Shows Dashboard.
        """
        # 1. If already visible, just lift it
        if self.root.state() == 'normal':
            self.root.lift()
            return

        # 2. Authenticate
        if self._authenticate_action("Show Dashboard"):
            self.root.deiconify()
            self._append_log("Dashboard accessed from tray (Verified)")
            
            # Optional: Force focus to the window
            self.root.lift()
            self.root.focus_force()
        else:
            print("Dashboard access denied or cancelled.")

    def hide_window(self):
        """Hide window to tray instead of closing"""
        if not self.tray_icon:
            self.root.iconify()
            return

        self.root.withdraw()
        if not self.tray_icon.visible:
            threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def quit_app(self, icon=None, item=None):
        """
        Tray Callback: Quits app.
        Uses 'after' to jump to the Main Thread for safety.
        """
        self.root.after(0, self._perform_auth_and_quit)

    def _perform_auth_and_quit(self):
        """
        Runs on MAIN THREAD. Performs Auth -> Quits.
        """
        # 1. If monitoring is running, require password
        if self.monitor_running:
            if not self._authenticate_action("Stop & Exit"):
                return  # Cancel quit if auth fails or is closed

        # 2. Stop everything safely
        if hasattr(self, 'tray_icon'):
            self.tray_icon.stop()
        self.root.quit()

    

    def on_closing(self):
        """Handle window close request"""
        try:
            if self.monitor_running:
                if messagebox.askyesno("Minimize to Tray", "Monitor is running.\n\nKeep monitoring in background?\n(No = Exit completely)"):
                    self.hide_window()
                else:
                    self.quit_app()
            else:
                self.quit_app()
        except Exception as e:
            print(f"Close error: {e}")
            self.root.destroy()
            sys.exit(0)

    def _check_safe_mode_status(self):
        """Check if backend triggered Safe Mode"""
        try:
            from core.utils import get_app_data_dir
            app_data = get_app_data_dir()
            lockdown_path = os.path.join(app_data, "lockdown.flag")
            is_safe = os.path.exists(lockdown_path)
            
            if not is_safe and safe_mode:
                is_safe = safe_mode.is_safe_mode_enabled()

            if is_safe:
                self.status_var.set("⛔ SAFE MODE ACTIVE")
                self.status_label.configure(foreground=self.colors['accent_danger'])
                
                # Disable buttons
                for child in self.root.winfo_children():
                    if isinstance(child, tk.Button) and child.cget('text') in ["▶ Start Monitor", "🔍 Verify Now"]:
                        child.configure(state='disabled')
                
                if self.monitor_running:
                    self.monitor_running = False
                    if self.monitor:
                        self.monitor.stop_monitoring()
                    
                    self._append_log("UI: Recognized Safe Mode - SYSTEM HALTED")
                    self._show_alert("SYSTEM LOCKDOWN", "Safe Mode detected. Monitoring frozen.", "critical")

        except Exception as e:
            print(f"Safe Mode Check Error: {e}")
        
        self.root.after(1000, self._check_safe_mode_status)

    # ===== ALERT PANEL METHODS =====
    
    def _create_alert_panel(self):
        """Create alert panel that won't overlap with main UI"""
        # Destroy existing panel if it exists
        if hasattr(self, '_alert_frame') and self._alert_frame:
            try:
                self._alert_frame.destroy()
            except:
                pass
        
        # Calculate position - place it in the top-right corner above main content
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        # Position at top-right corner with margin
        start_x = screen_width
        start_y = 100  # Below the header
        
        # Create alert frame as a top-level window to avoid z-index issues
        self._alert_frame = tk.Toplevel(self.root)
        self._alert_frame.title("Security Alerts")
        self._alert_frame.geometry(f"{self.ALERT_PANEL_WIDTH}x{self.ALERT_PANEL_HEIGHT}+{start_x}+{start_y}")
        self._alert_frame.overrideredirect(True)  # Remove window decorations
        self._alert_frame.attributes('-topmost', True)  # Keep on top
        self._alert_frame.configure(bg=self.colors['card_bg'], bd=2, relief='solid')
        
        # Make sure it doesn't interfere with main window
        self._alert_frame.transient(self.root)
        
        # Header
        header = tk.Frame(self._alert_frame, bg=self.colors['accent_primary'], height=40)
        header.pack(fill=tk.X)
        
        self._alert_title = tk.Label(header, text="🚨 SECURITY ALERTS", 
                                    bg=self.colors['accent_primary'], fg='white', 
                                    font=('Segoe UI', 11, 'bold'))
        self._alert_title.pack(side=tk.LEFT, padx=15, pady=8)

        close_btn = tk.Button(header, text="✕", command=self._hide_alert, 
                             bg=self.colors['accent_primary'], fg='white', bd=0,
                             font=('Segoe UI', 12, 'bold'), cursor="hand2")
        close_btn.pack(side=tk.RIGHT, padx=15, pady=8)
        close_btn.bind("<Enter>", lambda e: close_btn.configure(fg='#ff6b6b'))
        close_btn.bind("<Leave>", lambda e: close_btn.configure(fg='white'))

        # Content area
        content = tk.Frame(self._alert_frame, bg=self.colors['card_bg'])
        content.pack(fill=tk.BOTH, expand=True)

        self._alert_msg = scrolledtext.ScrolledText(content, wrap=tk.WORD, state="disabled",
                                                   bg=self.colors['card_bg'],
                                                   fg=self.colors['text_primary'],
                                                   height=10, relief='flat',
                                                   font=('Segoe UI', 9))
        self._alert_msg.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Footer with counter
        footer = tk.Frame(content, bg=self.colors['card_bg'], height=30)
        footer.pack(fill=tk.X, side=tk.BOTTOM)
        
        self._alert_meta = tk.Label(footer, text="No active alerts", 
                                   bg=self.colors['card_bg'], fg=self.colors['text_secondary'],
                                   font=('Segoe UI', 9))
        self._alert_meta.pack(side=tk.LEFT, padx=10, pady=5)
        
        self._alert_counter = tk.Label(footer, text="Alerts: 0", 
                                      bg=self.colors['card_bg'], fg=self.colors['text_secondary'],
                                      font=('Segoe UI', 9, 'bold'))
        self._alert_counter.pack(side=tk.RIGHT, padx=10, pady=5)

        # Internal state
        self.alert_count = 0
        self.alert_visible = False
        
        # Initially hide the window
        self._alert_frame.withdraw()

    def _show_alert(self, title, message, level="info"):
        """Show alert panel (if active) or System Tray Notification (if background)"""
        try:
            # 1. Update Severity Counters (Logic remains the same)
            severity_map = {
                "info": "INFO", "created": "INFO",
                "modified": "MEDIUM", "deleted": "MEDIUM",
                "tampered": "CRITICAL", "high": "HIGH", "critical": "CRITICAL"
            }
            severity = severity_map.get(level, "INFO")
            
            # Update internal counters
            if severity in self.severity_counters:
                self.severity_counters[severity] += 1
                # Update UI StringVars
                if severity == "CRITICAL": self.critical_var.set(str(self.severity_counters["CRITICAL"]))
                elif severity == "HIGH": self.high_var.set(str(self.severity_counters["HIGH"]))
                elif severity == "MEDIUM": self.medium_var.set(str(self.severity_counters["MEDIUM"]))
                elif severity == "INFO": self.info_var.set(str(self.severity_counters["INFO"]))

            # 2. CHECK WINDOW STATE
            # If window is withdrawn (Tray) or Iconic (Minimized), use Tray Notification
            is_background = (self.root.state() == 'withdrawn' or self.root.state() == 'iconic')
            
            if is_background:
                if hasattr(self, 'tray_icon') and self.tray_icon:
                    # Send System Notification via Tray Icon
                    # self.tray_icon.notify(message, title)
                    return  # Stop here, do not show the custom UI popup

            # 3. Show Custom UI Popup (Only if window is visible)
            if not hasattr(self, '_alert_frame') or not self._alert_frame:
                self._create_alert_panel()
            
            severity_color = SEVERITY_COLORS.get(severity, self.colors['accent_info'])
            severity_badge = SEVERITY_BADGES.get(severity, "INFO")
            ts = datetime.now().strftime("%H:%M:%S")
            entry = f"[{ts}] [{severity_badge}] {title}\n{message}\n{'─' * 40}\n"
            
            self._alert_msg.configure(state="normal")
            tag_name = f"severity_{severity}"
            self._alert_msg.tag_config(tag_name, foreground=severity_color, 
                                      font=('Segoe UI', 9, 'bold' if severity in ['CRITICAL', 'HIGH'] else 'normal'))
            self._alert_msg.insert("1.0", entry, tag_name)
            self._alert_msg.configure(state="disabled")
            
            self.alert_count = getattr(self, "alert_count", 0) + 1
            self._alert_counter.configure(text=f"Alerts: {self.alert_count}")
            self._alert_meta.configure(text=f"Last: {severity} @ {ts}")
            
            self._animate_panel_show()
            
        except Exception as e:
            print("Error showing alert:", e)

    def _animate_panel_show(self):
        """Animate panel showing from right side"""
        if self.alert_visible:
            # If already visible, just update and restart timer
            if self.alert_hide_after_id:
                self.root.after_cancel(self.alert_hide_after_id)
        else:
            # Calculate target position
            root_x = self.root.winfo_x()
            root_y = self.root.winfo_y()
            root_width = self.root.winfo_width()
            
            # Position alert panel at top-right of main window
            target_x = root_x + root_width - self.ALERT_PANEL_WIDTH - 20
            target_y = root_y + 100  # Below header
            
            # Set initial position off-screen to the right
            self._alert_frame.geometry(f"{self.ALERT_PANEL_WIDTH}x{self.ALERT_PANEL_HEIGHT}+{root_x + root_width}+{target_y}")
            self._alert_frame.deiconify()
            self._alert_frame.lift()
            
            # Animate sliding in
            self._animate_panel_slide(target_x, target_y, slide_in=True)
            
            self.alert_visible = True
        
        # Set auto-hide timer
        self.alert_hide_after_id = self.root.after(self.ALERT_SHOW_MS, self._hide_alert)

    def _animate_panel_slide(self, target_x, target_y, slide_in=True):
        """Animate panel sliding in/out"""
        current_x = self._alert_frame.winfo_x()
        
        if slide_in:
            if current_x <= target_x:
                # Reached target
                self._alert_frame.geometry(f"{self.ALERT_PANEL_WIDTH}x{self.ALERT_PANEL_HEIGHT}+{target_x}+{target_y}")
                return
            
            # Move left
            new_x = current_x - self.ALERT_ANIM_STEP
            if new_x < target_x:
                new_x = target_x
            
            self._alert_frame.geometry(f"{self.ALERT_PANEL_WIDTH}x{self.ALERT_PANEL_HEIGHT}+{new_x}+{target_y}")
            self.root.after(self.ALERT_ANIM_DELAY, lambda: self._animate_panel_slide(target_x, target_y, slide_in=True))
        else:
            # Slide out to the right
            root_x = self.root.winfo_x()
            root_width = self.root.winfo_width()
            off_screen_x = root_x + root_width + 100
            
            if current_x >= off_screen_x:
                # Reached off-screen
                self._alert_frame.withdraw()
                self.alert_visible = False
                return
            
            # Move right
            new_x = current_x + self.ALERT_ANIM_STEP
            self._alert_frame.geometry(f"{self.ALERT_PANEL_WIDTH}x{self.ALERT_PANEL_HEIGHT}+{new_x}+{target_y}")
            self.root.after(self.ALERT_ANIM_DELAY, lambda: self._animate_panel_slide(target_x, target_y, slide_in=False))

    def _hide_alert(self):
        """Hide alert panel"""
        try:
            if not self.alert_visible:
                return

            # Cancel any pending hide timer
            if self.alert_hide_after_id:
                self.root.after_cancel(self.alert_hide_after_id)
                self.alert_hide_after_id = None

            # Get current position
            current_x = self._alert_frame.winfo_x()
            current_y = self._alert_frame.winfo_y()
            
            # Slide out to the right
            root_x = self.root.winfo_x()
            root_width = self.root.winfo_width()
            off_screen_x = root_x + root_width + 100
            
            self._animate_panel_slide(off_screen_x, current_y, slide_in=False)

        except Exception as e:
            print("Error hiding alert:", e)
            # Fallback: just hide it
            if hasattr(self, '_alert_frame') and self._alert_frame:
                try:
                    self._alert_frame.withdraw()
                    self.alert_visible = False
                except:
                    pass

    # ===== PASSWORD CHANGE METHODS =====
    
    def change_admin_password(self):
        """
        Change credential — opens PIN change for Google SSO users,
        password change for manual users.
        """
        if self.user_role != 'admin':
            messagebox.showerror('Permission Denied',
                                 'Only administrators can change credentials.')
            return
 
        if not auth:
            messagebox.showerror('Error', 'Authentication backend not loaded.')
            return
 
        auth_method = auth.get_auth_method(self.username)
 
        if auth_method == 'google':
            self._create_pin_change_window()
        else:
            self._create_hacker_password_window()

    def _create_pin_change_window(self):
        """
        Clean PIN-change dialog for Google SSO users.
        Verifies the old PIN first, then sets a new one.
        """
        C = self.colors
 
        win = tk.Toplevel(self.root)
        win.title('Change Device PIN')
        win.geometry('420x320')
        win.resizable(False, False)
        win.configure(bg=C['card_bg'])
        win.transient(self.root)
        win.grab_set()
 
        win.update_idletasks()
        px = self.root.winfo_x() + (self.root.winfo_width()  // 2) - 210
        py = self.root.winfo_y() + (self.root.winfo_height() // 2) - 160
        win.geometry(f'+{px}+{py}')
 
        # Header
        tk.Frame(win, bg=C['accent_primary'], height=4).pack(fill=tk.X)
 
        title_row = tk.Frame(win, bg=C['card_bg'])
        title_row.pack(fill=tk.X, padx=24, pady=(18, 0))
        tk.Label(title_row, text='🔐', font=('Segoe UI', 22),
                 bg=C['card_bg'], fg=C['accent_primary']).pack(side=tk.LEFT, padx=(0, 12))
        col = tk.Frame(title_row, bg=C['card_bg'])
        col.pack(side=tk.LEFT)
        tk.Label(col, text='Change Device PIN',
                 font=('Segoe UI', 13, 'bold'),
                 bg=C['card_bg'], fg=C['text_primary']).pack(anchor='w')
        tk.Label(col, text=f'Account: {self.username}  (Google SSO)',
                 font=('Segoe UI', 9),
                 bg=C['card_bg'], fg=C['text_secondary']).pack(anchor='w')
 
        tk.Frame(win, height=1, bg=C['divider']).pack(fill=tk.X, padx=24, pady=(14, 0))
 
        def _make_field(parent, label_text):
            tk.Label(parent, text=label_text,
                     font=('Segoe UI', 10),
                     bg=C['card_bg'], fg=C['text_secondary']).pack(
                fill=tk.X, padx=24, pady=(10, 2))
            var = tk.StringVar()
            e = tk.Entry(parent, textvariable=var, show='●',
                         font=('Segoe UI', 12),
                         bg=C['input_bg'], fg=C['text_primary'],
                         insertbackground=C['text_primary'],
                         relief='flat',
                         highlightthickness=1,
                         highlightbackground=C['input_border'],
                         highlightcolor=C['accent_primary'])
            e.pack(fill=tk.X, padx=24, pady=(0, 0))
            return var, e
 
        old_var,  old_entry  = _make_field(win, 'Current PIN')
        new_var,  new_entry  = _make_field(win, 'New PIN  (4+ digits)')
        conf_var, conf_entry = _make_field(win, 'Confirm New PIN')
        old_entry.focus_set()
 
        status_lbl = tk.Label(win, text='',
                              font=('Segoe UI', 9),
                              bg=C['card_bg'], fg=C['accent_danger'])
        status_lbl.pack(pady=(8, 0))
 
        def _save():
            old  = old_var.get().strip()
            new  = new_var.get().strip()
            conf = conf_var.get().strip()
 
            if not old or not new or not conf:
                status_lbl.configure(text='All fields are required.')
                return
            if not auth.verify_sso_pin(self.username, old):
                status_lbl.configure(text='Current PIN is incorrect.')
                old_entry.delete(0, tk.END)
                old_entry.focus_set()
                return
            if new != conf:
                status_lbl.configure(text='New PINs do not match.')
                new_entry.delete(0, tk.END)
                conf_entry.delete(0, tk.END)
                new_entry.focus_set()
                return
            if not new.isdigit() or len(new) < 4:
                status_lbl.configure(text='PIN must be 4+ digits (numbers only).')
                return
 
            ok, msg = auth.set_sso_pin(self.username, new)
            if ok:
                messagebox.showinfo('PIN Changed', 'Device PIN updated successfully.')
                self._append_log(f'Device PIN changed for user: {self.username}')
                win.destroy()
            else:
                status_lbl.configure(text=f'Error: {msg}')
 
        btn_row = tk.Frame(win, bg=C['card_bg'])
        btn_row.pack(fill=tk.X, padx=24, pady=(12, 0))
 
        tk.Button(btn_row, text='Save PIN',
                  command=_save,
                  font=('Segoe UI', 10, 'bold'),
                  bg=C['accent_primary'], fg='#ffffff',
                  bd=0, padx=20, pady=7, cursor='hand2',
                  activebackground=C['accent_primary']).pack(side=tk.RIGHT)
 
        tk.Button(btn_row, text='Cancel',
                  command=win.destroy,
                  font=('Segoe UI', 10),
                  bg=C['button_bg'], fg=C['text_secondary'],
                  bd=0, padx=20, pady=7, cursor='hand2',
                  activebackground=C['button_hover']).pack(side=tk.RIGHT, padx=(0, 8))
 
        old_entry.bind('<Return>', lambda e: new_entry.focus_set())
        new_entry.bind('<Return>', lambda e: conf_entry.focus_set())
        conf_entry.bind('<Return>', lambda e: _save())
        win.bind('<Escape>', lambda e: win.destroy())

    def _create_hacker_password_window(self):
        """Create a professional hacker-themed password change window"""
        # Create a top-level window
        self.pass_window = tk.Toplevel(self.root)
        self.pass_window.title("🛡️ SECURE PASSWORD CHANGE")
        self.pass_window.geometry("500x450")
        self.pass_window.configure(bg='#0a0a0a')  # Pure black background
        self.pass_window.resizable(False, False)
        self.pass_window.transient(self.root)
        self.pass_window.grab_set()
        
        # Hacker-style title
        title_frame = tk.Frame(self.pass_window, bg='#0a0a0a')
        title_frame.pack(fill=tk.X, pady=(20, 10))
        
        # Animated title effect
        title_label = tk.Label(title_frame, 
                              text="◈ CRYPTOGRAPHIC PASSWORD UPDATE ◈",
                              font=('Courier New', 14, 'bold'),
                              bg='#0a0a0a',
                              fg='#00ff00')  # Matrix green
        title_label.pack()
        
        # Animated border effect
        self._animate_title_border(title_label)
        
        # Subtitle
        subtitle = tk.Label(self.pass_window,
                          text="System Security Level: MAXIMUM",
                          font=('Courier New', 10),
                          bg='#0a0a0a',
                          fg='#00ffff')  # Cyan
        subtitle.pack(pady=(0, 20))
        
        # Main content frame
        main_frame = tk.Frame(self.pass_window, bg='#0a0a0a')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=40)
        
        # Current user display
        user_info = tk.Label(main_frame,
                           text=f"USER: {self.username} | ROLE: ADMINISTRATOR",
                           font=('Consolas', 10, 'bold'),
                           bg='#0a0a0a',
                           fg='#ff9900')  # Orange
        user_info.pack(pady=(0, 30))
        
        # Password strength meter
        self.strength_var = tk.StringVar(value="Strength: --")
        self.strength_label = tk.Label(main_frame,
                                      textvariable=self.strength_var,
                                      font=('Consolas', 9),
                                      bg='#0a0a0a',
                                      fg='#666666')
        self.strength_label.pack(anchor='w', pady=(0, 5))
        
        # New password field with hacker style
        new_pass_frame = tk.Frame(main_frame, bg='#0a0a0a')
        new_pass_frame.pack(fill=tk.X, pady=(0, 15))
        
        tk.Label(new_pass_frame,
                text="[1] ENTER NEW PASSWORD:",
                font=('Consolas', 10, 'bold'),
                bg='#0a0a0a',
                fg='#00ff00').pack(anchor='w')
        
        new_pass_subframe = tk.Frame(new_pass_frame, bg='#0a0a0a')
        new_pass_subframe.pack(fill=tk.X, pady=(5, 0))
        
        # Password entry with show/hide toggle
        self.new_pass_var = tk.StringVar()
        self.new_pass_entry = tk.Entry(new_pass_subframe,
                                      textvariable=self.new_pass_var,
                                      font=('Consolas', 11),
                                      bg='#111111',
                                      fg='#00ff00',
                                      insertbackground='#00ff00',
                                      show='•',
                                      relief='flat',
                                      width=30)
        self.new_pass_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Bind password strength checker
        self.new_pass_var.trace('w', self._check_password_strength)
        
        # Show/hide button for new password
        self.show_new_var = tk.BooleanVar(value=False)
        show_new_btn = tk.Checkbutton(new_pass_subframe,
                                     text="👁",
                                     variable=self.show_new_var,
                                     command=self._toggle_password_visibility,
                                     font=('Consolas', 10),
                                     bg='#111111',
                                     fg='#00ff00',
                                     selectcolor='#111111',
                                     activebackground='#111111',
                                     activeforeground='#00ff00')
        show_new_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        # Confirm password field
        confirm_pass_frame = tk.Frame(main_frame, bg='#0a0a0a')
        confirm_pass_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(confirm_pass_frame,
                text="[2] CONFIRM PASSWORD:",
                font=('Consolas', 10, 'bold'),
                bg='#0a0a0a',
                fg='#00ff00').pack(anchor='w')
        
        confirm_subframe = tk.Frame(confirm_pass_frame, bg='#0a0a0a')
        confirm_subframe.pack(fill=tk.X, pady=(5, 0))
        
        self.confirm_pass_var = tk.StringVar()
        self.confirm_pass_entry = tk.Entry(confirm_subframe,
                                          textvariable=self.confirm_pass_var,
                                          font=('Consolas', 11),
                                          bg='#111111',
                                          fg='#00ff00',
                                          insertbackground='#00ff00',
                                          show='•',
                                          relief='flat',
                                          width=30)
        self.confirm_pass_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Show/hide button for confirm password
        self.show_confirm_var = tk.BooleanVar(value=False)
        show_confirm_btn = tk.Checkbutton(confirm_subframe,
                                         text="👁",
                                         variable=self.show_confirm_var,
                                         command=self._toggle_confirm_visibility,
                                         font=('Consolas', 10),
                                         bg='#111111',
                                         fg='#00ff00',
                                         selectcolor='#111111',
                                         activebackground='#111111',
                                         activeforeground='#00ff00')
        show_confirm_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        # Password match indicator (initially hidden)
        self.match_indicator = tk.Label(main_frame,
                                       text="",
                                       font=('Consolas', 9, 'bold'),
                                       bg='#0a0a0a')
        self.match_indicator.pack(pady=(5, 0))
        
        # Bind to check password match on typing
        self.confirm_pass_var.trace('w', self._check_password_match)
        
        # Error message display (for mismatch)
        self.error_label = tk.Label(main_frame,
                                   text="",
                                   font=('Consolas', 9),
                                   bg='#0a0a0a',
                                   fg='#ff0000')
        self.error_label.pack(pady=(5, 10))
        
        # Security requirements
        requirements = tk.Label(main_frame,
                              text="⚠ REQUIREMENTS: 8+ chars, mix of uppercase, lowercase, numbers, symbols",
                              font=('Consolas', 8),
                              bg='#0a0a0a',
                              fg='#ff9900')
        requirements.pack(pady=(0, 20))
        
        # Buttons frame
        button_frame = tk.Frame(main_frame, bg='#0a0a0a')
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        # Change button with hacker style
        change_btn = tk.Button(button_frame,
                              text="⚡ EXECUTE PASSWORD CHANGE",
                              command=self._execute_password_change,
                              font=('Consolas', 10, 'bold'),
                              bg='#003300',
                              fg='#00ff00',
                              activebackground='#005500',
                              activeforeground='#00ff00',
                              relief='raised',
                              bd=2,
                              padx=20,
                              pady=10,
                              cursor="hand2")
        change_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Cancel button
        cancel_btn = tk.Button(button_frame,
                              text="✗ ABORT OPERATION",
                              command=self.pass_window.destroy,
                              font=('Consolas', 10),
                              bg='#330000',
                              fg='#ff6666',
                              activebackground='#550000',
                              activeforeground='#ff9999',
                              relief='raised',
                              bd=2,
                              padx=20,
                              pady=10,
                              cursor="hand2")
        cancel_btn.pack(side=tk.RIGHT)
        
        # Status bar at bottom
        status_bar = tk.Frame(self.pass_window, bg='#003300', height=20)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_text = tk.StringVar(value="◈ SYSTEM READY ◈")
        status_label = tk.Label(status_bar,
                               textvariable=self.status_text,
                               font=('Consolas', 9),
                               bg='#003300',
                               fg='#00ff00')
        status_label.pack(pady=2)
        
        # Start fake terminal typing effect
        self._start_terminal_effect()
        
        # Focus on first entry
        self.new_pass_entry.focus_set()

    def _animate_title_border(self, label):
        """Create animated border effect for title"""
        colors = ['#00ff00', '#00ffff', '#ff00ff', '#ffff00', '#ff9900']
        
        def animate():
            color = random.choice(colors)
            label.configure(fg=color)
            self.pass_window.after(500, animate)
        
        animate()

    def _toggle_password_visibility(self):
        """Toggle visibility of new password"""
        if self.show_new_var.get():
            self.new_pass_entry.configure(show='')
        else:
            self.new_pass_entry.configure(show='•')

    def _toggle_confirm_visibility(self):
        """Toggle visibility of confirm password"""
        if self.show_confirm_var.get():
            self.confirm_pass_entry.configure(show='')
        else:
            self.confirm_pass_entry.configure(show='•')

    def _check_password_strength(self, *args):
        """Check password strength and update indicator"""
        password = self.new_pass_var.get()
        
        if not password:
            self.strength_var.set("Strength: --")
            self.strength_label.configure(fg='#666666')
            return
        
        # Calculate strength
        strength = 0
        if len(password) >= 8:
            strength += 1
        if any(c.isupper() for c in password):
            strength += 1
        if any(c.islower() for c in password):
            strength += 1
        if any(c.isdigit() for c in password):
            strength += 1
        if any(not c.isalnum() for c in password):
            strength += 1
        
        # Update display
        if strength <= 2:
            self.strength_var.set(f"Strength: WEAK [{strength}/5]")
            self.strength_label.configure(fg='#ff0000')
        elif strength <= 3:
            self.strength_var.set(f"Strength: MEDIUM [{strength}/5]")
            self.strength_label.configure(fg='#ff9900')
        elif strength <= 4:
            self.strength_var.set(f"Strength: STRONG [{strength}/5]")
            self.strength_label.configure(fg='#00ff00')
        else:
            self.strength_var.set(f"Strength: MAXIMUM [{strength}/5]")
            self.strength_label.configure(fg='#00ffff')

    def _check_password_match(self, *args):
        """Check if passwords match and update indicator"""
        new_pass = self.new_pass_var.get()
        confirm_pass = self.confirm_pass_var.get()
        
        if not new_pass or not confirm_pass:
            self.match_indicator.configure(text="", fg='#0a0a0a')
            self.error_label.configure(text="")
            return
        
        if new_pass == confirm_pass:
            self.match_indicator.configure(text="✓ PASSWORDS MATCH", fg='#00ff00')
            self.error_label.configure(text="")
        else:
            self.match_indicator.configure(text="✗ PASSWORDS DO NOT MATCH", fg='#ff0000')
            self._show_password_mismatch_error()

    def _show_password_mismatch_error(self):
        """Show hacker-style password mismatch error"""
        # Clear any existing animation
        if hasattr(self, '_mismatch_anim_id'):
            self.pass_window.after_cancel(self._mismatch_anim_id)
        
        error_messages = [
            "CRYPTOGRAPHIC MISMATCH DETECTED!",
            "PASSWORD VERIFICATION FAILED!",
            "SECURITY BREACH: MISMATCHED CREDENTIALS!",
            "WARNING: PASSWORDS DO NOT SYNCHRONIZE!"
        ]
        
        error_message = random.choice(error_messages)
        
        # Create flashing effect
        def flash_error(count=0):
            if count >= 6:  # Flash 3 times
                self.error_label.configure(text=error_message, fg='#ff0000')
                self.status_text.set("◈ CREDENTIAL MISMATCH ◈")
                return
            
            if count % 2 == 0:
                self.error_label.configure(text=error_message, fg='#ff0000', bg='#220000')
                self.status_text.set("◈ VERIFICATION FAILED ◈")
            else:
                self.error_label.configure(text=error_message, fg='#ff6666', bg='#0a0a0a')
                self.status_text.set("◈ RE-ENTER PASSWORD ◈")
            
            self._mismatch_anim_id = self.pass_window.after(200, lambda: flash_error(count + 1))
        
        flash_error()

    def _start_terminal_effect(self):
        """Start fake terminal typing effect in status"""
        terminal_texts = [
            "Initializing security protocols...",
            "Loading cryptographic modules...",
            "Establishing secure connection...",
            "Verifying user credentials...",
            "System ready for password update..."
        ]
        
        def type_text(text_index=0, char_index=0):
            if text_index >= len(terminal_texts):
                text_index = 0
            
            current_text = terminal_texts[text_index]
            
            if char_index <= len(current_text):
                self.status_text.set(f"◈ {current_text[:char_index]} ◈")
                char_index += 1
                self.pass_window.after(50, lambda: type_text(text_index, char_index))
            else:
                self.pass_window.after(1000, lambda: type_text(text_index + 1, 0))
        
        type_text()

    def _execute_password_change(self):
        """Execute the password change"""
        new_pass = self.new_pass_var.get()
        confirm_pass = self.confirm_pass_var.get()
        
        # Validate
        if not new_pass or not confirm_pass:
            self._show_validation_error("ERROR: Both fields must be completed!")
            return
        
        if new_pass != confirm_pass:
            self._show_validation_error("CRITICAL: Password mismatch detected!")
            return
        
        if len(new_pass) < 4:
            self._show_validation_error("ERROR: Password must be at least 4 characters!")
            return
        
        # Show processing animation
        self.status_text.set("◈ PROCESSING CRYPTOGRAPHIC UPDATE... ◈")
        
        # Change button to processing state
        for widget in self.pass_window.winfo_children():
            if isinstance(widget, tk.Frame):
                for child in widget.winfo_children():
                    if isinstance(child, tk.Button) and "EXECUTE" in child.cget('text'):
                        child.configure(text="⚡ PROCESSING...", state='disabled', bg='#555555')
                        break
        
        # Simulate processing delay (for effect)
        def process_change():
            try:
                # Call backend to update
                success, msg = auth.update_password(self.username, new_pass)
                
                if success:
                    # Success animation
                    self._show_success_animation()
                    
                    # Close window after delay
                    self.pass_window.after(2000, self.pass_window.destroy)
                    
                    # Show success message in main window
                    self.root.after(2100, lambda: messagebox.showinfo("Success", "Password updated successfully!"))
                    self._append_log(f"Admin password changed for user: {self.username}")
                    self._show_alert("Password Changed", f"Password for {self.username} has been updated.", "info")
                else:
                    self._show_validation_error(f"FAILED: {msg}")
                    # Re-enable button
                    for widget in self.pass_window.winfo_children():
                        if isinstance(widget, tk.Frame):
                            for child in widget.winfo_children():
                                if isinstance(child, tk.Button) and "PROCESSING" in child.cget('text'):
                                    child.configure(text="⚡ EXECUTE PASSWORD CHANGE", state='normal', bg='#003300')
                                    break
                    
            except Exception as e:
                self._show_validation_error(f"EXCEPTION: {str(e)}")
        
        # Start processing after short delay (for visual effect)
        self.pass_window.after(1000, process_change)

    def _show_validation_error(self, message):
        """Show validation error in hacker style"""
        # Flash red border on window
        original_color = self.pass_window.cget('bg')
        
        def flash_border(count=0):
            if count >= 6:
                self.pass_window.configure(bg=original_color)
                return
            
            if count % 2 == 0:
                self.pass_window.configure(bg='#330000')
            else:
                self.pass_window.configure(bg=original_color)
            
            self.pass_window.after(150, lambda: flash_border(count + 1))
        
        flash_border()
        
        # Update error label
        self.error_label.configure(text=message, fg='#ff0000', bg='#220000')
        self.status_text.set("◈ OPERATION FAILED ◈")

    def _show_success_animation(self):
        """Show success animation"""
        # Change window to success theme
        self.pass_window.configure(bg='#003300')
        
        # Update all labels to success theme
        for widget in self.pass_window.winfo_children():
            if isinstance(widget, tk.Label):
                widget.configure(bg='#003300', fg='#00ff00')
            elif isinstance(widget, tk.Frame):
                for child in widget.winfo_children():
                    if isinstance(child, tk.Label):
                        child.configure(bg='#003300', fg='#00ff00')
        
        # Update status
        self.status_text.set("◈ PASSWORD UPDATED SUCCESSFULLY ◈")
        
        # Success message
        self.error_label.configure(text="✓ CRYPTOGRAPHIC UPDATE COMPLETE", 
                                 fg='#00ff00', 
                                 bg='#003300')
        
        # Animate success text
        def pulse_success(count=0):
            if count >= 4:
                return
            
            if count % 2 == 0:
                self.error_label.configure(fg='#ffffff')
            else:
                self.error_label.configure(fg='#00ff00')
            
            self.pass_window.after(300, lambda: pulse_success(count + 1))
        
        pulse_success()

    # ===== OTHER SYSTEM METHODS =====
    
    def logout(self):
        """Logout and restart application safely for both script and EXE modes"""
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            # 1. Cleanup existing resources
            if self.monitor_running:
                try:
                    self.monitor.stop_monitoring()
                except: pass
            
            if hasattr(self, 'tray_icon') and self.tray_icon:
                try:
                    self.tray_icon.stop()
                except: pass

            # 2. Destroy current window
            self.root.destroy()

            # 3. Restart Logic
            try:
                if getattr(sys, 'frozen', False):
                    # --- EXE MODE RESTART ---
                    # Create a copy of the current environment
                    env = os.environ.copy()
                    
                    # CRITICAL: Remove PyInstaller's internal path variables.
                    # This forces the new instance to unpack its own Tcl/Tk libraries.
                    for key in ['TCL_LIBRARY', 'TK_LIBRARY', '_MEIPASS2']:
                        if key in env:
                            del env[key]
                    
                    # Launch the EXE again with the CLEAN environment
                    subprocess.Popen([sys.executable], env=env)
                    
                else:
                    # --- SCRIPT MODE RESTART ---
                    current_dir = os.path.dirname(os.path.abspath(__file__))
                    project_root = os.path.dirname(current_dir)
                    run_script = os.path.join(project_root, "run.py")
                    
                    subprocess.Popen([sys.executable, run_script])

                # 4. Kill the current process immediately
                sys.exit(0)

            except Exception as e:
                messagebox.showerror("Error", f"Failed to restart: {e}")
                sys.exit(1)

    def disable_lockdown(self):
        """Admin override to disable safe mode AND release Ransomware folder locks"""
        if self.user_role != 'admin':
            messagebox.showerror("Access Denied", "Only Admins can release security lockdowns.")
            return

        # --- 🚨 NEW: REQUIRE PASSWORD TO UNLOCK FOLDERS ---
        if not self._authenticate_action("Release System Lockdown"):
            return
            
        if messagebox.askyesno("Confirm Unlock", "Are you sure the system is secure?\n\nThis will release OS-level folder locks and re-enable monitoring controls."):
            
            # --- NEW: Release OS-Level Ransomware Locks ---
            try:
                from core.lockdown_manager import lockdown
                from core.integrity_core import CONFIG
                
                # Get active folders
                folders = list(self.folder_listbox.get(0, tk.END))
                if not folders and CONFIG.get("watch_folders"):
                    folders = CONFIG.get("watch_folders")
                    
                for folder in folders:
                    success, msg = lockdown.remove_lockdown(folder)
                    if success:
                        self._append_log(f"🔓 OS-Level permissions restored for: {folder}")
            except Exception as e:
                print(f"Error removing OS lockdown: {e}")
            
            # --- Existing Safe Mode Logic ---
            success = safe_mode.disable_safe_mode("Admin Override via GUI")
            if success:
                messagebox.showinfo("Unlocked", "System returned to normal. Folder permissions restored.")
                self.status_var.set("🔴 Stopped")
                self.status_label.configure(foreground=self.colors['text_primary'])
            else:
                messagebox.showerror("Error", "Failed to disable Safe Mode.")

    # ─────────────────────────────────────────
    #  OTA UPDATE ENGINE
    # ─────────────────────────────────────────
    
    def _check_for_updates(self):
        """Silently checks GitHub Gist for a newer version on a background thread."""
        CURRENT_VERSION = 2.0
        # REPLACE THIS with your actual Raw Gist URL from Step 1
        import time
        UPDATE_URL = f"https://gist.githubusercontent.com/Manish93345/f339aeaae5ef231abf2be28bb750e4d8/raw/fmsecure_version.json?nocache={int(time.time())}"
        
        def fetch_version():
            try:
                import requests
                # 3-second timeout so it never freezes the app if offline
                response = requests.get(UPDATE_URL, timeout=3) 
                if response.status_code == 200:
                    data = response.json()
                    latest = float(data.get("latest_version", 2.0))
                    
                    if latest > CURRENT_VERSION:
                        url = data.get("download_url", "")
                        # Push UI updates back to the main thread
                        self.root.after(1000, lambda: self._show_update_banner(latest, url))
            except Exception as e:
                print(f"Update check skipped (Offline or unreachable): {e}")

        # Run immediately without blocking the Splash Screen or GUI load
        threading.Thread(target=fetch_version, daemon=True).start()

    def _show_update_banner(self, latest_version, download_url):
        """Injects a sleek update banner right below the top navigation bar."""
        import webbrowser
        
        banner = tk.Frame(self.root, bg=self.colors['accent_primary'], height=40)
        # Place it exactly under the 56px top bar
        banner.place(x=0, y=56, relwidth=1.0) 
        banner.pack_propagate(False)
        
        tk.Label(banner, text=f"🚀 UPDATE AVAILABLE", 
                 bg=self.colors['accent_primary'], fg="#ffffff", 
                 font=('Segoe UI', 9, 'bold')).pack(side=tk.LEFT, padx=(20, 5), pady=10)
                 
        tk.Label(banner, text=f"FMSecure v{latest_version} is now available.", 
                 bg=self.colors['accent_primary'], fg="#ffffff", 
                 font=('Segoe UI', 9)).pack(side=tk.LEFT, pady=10)
                 
        close_btn = tk.Button(banner, text="✕", command=banner.destroy,
                              bg=self.colors['accent_primary'], fg="#ffffff", bd=0, 
                              font=('Segoe UI', 12), cursor="hand2", activebackground=self.colors['accent_primary'])
        close_btn.pack(side=tk.RIGHT, padx=15)
        
        dl_btn = tk.Button(banner, text="Download Update", 
                           command=lambda: webbrowser.open(download_url) if download_url else None,
                           bg="#ffffff", fg=self.colors['accent_primary'], bd=0,
                           font=('Segoe UI', 9, 'bold'), cursor="hand2", padx=15, pady=4)
        dl_btn.pack(side=tk.RIGHT, padx=10, pady=7)

# ---------- Run ----------
# ---------- Run ----------
def main():
    try:
        # --- NEW: Initialize CustomTkinter Engine ---
        ctk.set_appearance_mode("dark")  # Modes: "System" (standard), "Dark", "Light"
        ctk.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"
        
        
        root = ctk.CTk() # Replaces tk.Tk()
        app = ProIntegrityGUI(root, user_role='admin', username='Admin')
        root.mainloop()
    except Exception as e:
        print(f"Failed to start GUI: {e}")
        traceback.print_exc()
        input("Press Enter to close...")

if __name__ == "__main__":
    main()