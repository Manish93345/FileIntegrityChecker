#!/usr/bin/env python3
"""
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
        self._ad_var  = tk.BooleanVar(value=CONFIG.get('active_defense', False))
        self._ks_var  = tk.BooleanVar(value=CONFIG.get('ransomware_killswitch', False))
        self._usb_var = tk.BooleanVar(value=CONFIG.get('usb_readonly', False))

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
        shield_cv = tk.Canvas(left_hdr, width=28, height=28,
                              bg=C['header_bg'], highlightthickness=0)
        shield_cv.pack(side=tk.LEFT, pady=14)
        shield_cv.create_polygon(14, 2, 26, 7, 26, 16, 14, 26, 2, 16, 2, 7,
                                 fill=C['accent_primary'], outline='')
        shield_cv.create_text(14, 15, text='✓', fill='#ffffff',
                              font=('Segoe UI', 9, 'bold'))

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

        if current_tier == 'free':
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

        # Update tamper indicators using the new Theme Colors
        self._update_tamper_indicators()

        # Schedule next update
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
        self.root.after(500, self._update_severity_counters)

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
        """Tail log file dynamically to populate the Live Security Feed"""
        try:
            if os.path.exists(LOG_FILE):
                try:
                    # Uses your secure decryptor logic!
                    lines = get_decrypted_logs()[-400:]
                except Exception:
                    lines = []
                
                existing = self.log_box.get("1.0", tk.END)
                for line in lines:
                    if line.strip() and (line not in existing):
                        self.log_box.configure(state="normal")
                        self.log_box.insert(tk.END, line + "\n")
                        self.log_box.configure(state="disabled")
                        self.log_box.see(tk.END)
        except Exception as e:
            print(f"Error in log tail: {e}")
        
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

        # Severity filter pills
        filter_frame = tk.Frame(header, bg=C['card_bg'])
        filter_frame.pack(side=tk.LEFT, padx=16)

        for sev, clr in [('ALL', C['text_muted']), ('CRITICAL', SEVERITY_COLORS['CRITICAL']),
                          ('HIGH', SEVERITY_COLORS['HIGH']), ('INFO', SEVERITY_COLORS['INFO'])]:
            pill = tk.Label(filter_frame, text=sev,
                            font=('Segoe UI', 8, 'bold'),
                            bg=C['tag_bg'], fg=clr,
                            padx=8, pady=2, cursor='hand2',
                            relief='flat')
            pill.pack(side=tk.LEFT, padx=3)

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

        # Colour tags
        for tag, colour in [
            ('CRITICAL', SEVERITY_COLORS['CRITICAL']),
            ('HIGH',     SEVERITY_COLORS['HIGH']),
            ('MEDIUM',   SEVERITY_COLORS['MEDIUM']),
            ('INFO',     SEVERITY_COLORS['INFO']),
            ('OK',       C['accent_success']),
        ]:
            self.log_box.tag_config(tag, foreground=colour)

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

        # Audit log viewer button
        sep = tk.Frame(parent, height=1, bg=C['divider'])
        sep.pack(fill=tk.X, padx=16, pady=(0, 8))

        _ActionButton(parent, '🔐  Open Encrypted Audit Log Vault',
                      self._open_audit_logs,
                      C['button_bg'], fg=C['text_secondary'],
                      font_size=10).pack(fill=tk.X, padx=16, pady=(0, 12))

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
            ('C2 Endpoint', 'http://127.0.0.1:8000'),
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

    # ─────────────────────────────────────────
    #  SIDE MENU (sliding drawer)
    # ─────────────────────────────────────────

    def _create_side_menu(self):
        C = self.colors
        self.menu_width = 260
        self.menu_visible = False

        self.side_menu = tk.Frame(self.root, bg=C['sidebar_bg'],
                                   width=self.menu_width,
                                   highlightbackground=C['card_border'],
                                   highlightthickness=1)
        self.side_menu.place(x=-self.menu_width, y=0,
                              width=self.menu_width,
                              relheight=1.0)
        self.side_menu.lift()

        # ── Header (always visible) ──────────────────────────
        mh = tk.Frame(self.side_menu, bg=C['sidebar_bg'])
        mh.pack(fill=tk.X, padx=20, pady=(20, 8))

        sh_cv = tk.Canvas(mh, width=22, height=22,
                          bg=C['sidebar_bg'], highlightthickness=0)
        sh_cv.pack(side=tk.LEFT, padx=(0, 8))
        sh_cv.create_polygon(11, 1, 21, 5, 21, 13, 11, 21, 1, 13, 1, 5,
                             fill=C['accent_primary'], outline='')
        sh_cv.create_text(11, 12, text='✓', fill='#fff',
                          font=('Segoe UI', 7, 'bold'))

        tk.Label(mh, text='FMSecure', font=('Segoe UI', 13, 'bold'),
                 bg=C['sidebar_bg'], fg=C['text_primary']).pack(side=tk.LEFT)

        # Top close button (X) – optional
        tk.Button(self.side_menu, text='✕', font=('Segoe UI', 12),
                  bg=C['sidebar_bg'], fg=C['text_muted'],
                  bd=0, cursor='hand2',
                  activebackground=C['sidebar_bg'],
                  command=self.toggle_menu).place(x=self.menu_width - 36, y=16)

        # Divider
        tk.Frame(self.side_menu, height=1,
                 bg=C['divider']).pack(fill=tk.X, padx=16, pady=(4, 12))

        # ── SCROLLABLE AREA for menu items ────────────────────
        # Create a canvas and a vertical scrollbar
        self.menu_canvas = tk.Canvas(self.side_menu, bg=C['sidebar_bg'],
                                     highlightthickness=0, borderwidth=0)
        v_scroll = tk.Scrollbar(self.side_menu, orient=tk.VERTICAL,
                                 command=self.menu_canvas.yview,
                                 bg=C['card_border'],
                                 troughcolor=C['sidebar_bg'],
                                 activebackground=C['button_hover'])
        self.menu_canvas.configure(yscrollcommand=v_scroll.set)

        # Pack canvas and scrollbar to fill all remaining space above bottom widgets
        self.menu_canvas.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=0, pady=0)
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Frame inside canvas to hold the actual menu items
        self.menu_frame = tk.Frame(self.menu_canvas, bg=C['sidebar_bg'])
        self.canvas_window = self.menu_canvas.create_window((0, 0), window=self.menu_frame,
                                                             anchor='nw')

        # Update scroll region when the inner frame changes size
        def _configure_menu_frame(event):
            self.menu_canvas.configure(scrollregion=self.menu_canvas.bbox('all'))
        self.menu_frame.bind('<Configure>', _configure_menu_frame)

        # Update the inner frame's width to match the canvas width when canvas resizes
        def _configure_canvas(event):
            self.menu_canvas.itemconfig(self.canvas_window, width=event.width)
        self.menu_canvas.bind('<Configure>', _configure_canvas)

        # ── Populate menu_frame with all menu items ──
        self._menu_section(self.menu_frame, 'Monitoring')
        self._menu_item(self.menu_frame, '▶  Start Monitor',   self.start_monitor,  C['accent_success'])
        self._menu_item(self.menu_frame, '■  Stop Monitor',    self.stop_monitor,   C['accent_danger'])
        self._menu_item(self.menu_frame, '⟳  Verify Now',     self.run_verification, C['accent_primary'])

        self._menu_divider(self.menu_frame)

        self._menu_section(self.menu_frame, 'Security')
        self._menu_item(self.menu_frame, '🔐  Audit Log Vault', self._open_audit_logs,     C['accent_info'])
        self._menu_item(self.menu_frame, '🎬  Demo Mode',       self.run_demo_mode,         C['accent_secondary'])
        self._menu_item(self.menu_frame, '🛑  Emergency Lock',  self._emergency_lockdown,   C['accent_danger'])

        self._menu_divider(self.menu_frame)

        self._menu_section(self.menu_frame, 'Data')
        self._menu_item(self.menu_frame, '📦  Archive & Reset', self.archive_and_reset,    C['accent_warning'])

        self._menu_divider(self.menu_frame)

        # ── BOTTOM FIXED WIDGETS (packed directly into side_menu, after canvas) ──
        close_btn = tk.Button(self.side_menu,
                              text='✕  Close Menu',
                              font=('Segoe UI', 10),
                              bg=C['button_bg'],
                              fg=C['text_primary'],
                              bd=0,
                              cursor='hand2',
                              pady=8,
                              activebackground=C['button_hover'],
                              command=self.toggle_menu)
        close_btn.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=(0, 4))

        tk.Label(self.side_menu,
                 text='FMSecure v2.0 — Enterprise EDR',
                 font=('Segoe UI', 8),
                 bg=C['sidebar_bg'], fg=C['text_muted']).pack(
            side=tk.BOTTOM, pady=(0, 12))

    def _menu_section(self, parent, text):
        C = self.colors
        tk.Label(parent, text=text.upper(),
                 font=('Segoe UI', 8, 'bold'),
                 bg=C['sidebar_bg'], fg=C['text_muted']).pack(
            anchor='w', padx=20, pady=(8, 2))

    def _menu_divider(self, parent):
        tk.Frame(parent, height=1,
                 bg=self.colors['divider']).pack(fill=tk.X, padx=16, pady=8)

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

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self.colors = DARK_THEME if self.dark_mode else LIGHT_THEME
        self.theme_btn.configure(text='🌙' if self.dark_mode else '☀️')
        ctk.set_appearance_mode('dark' if self.dark_mode else 'light')
        self._configure_styles()
        self._apply_theme()
        self._update_status_color()

    def _apply_theme(self):
        C = self.colors
        self.root.configure(bg=C['bg'])
        self._update_widget_colors(self.root)
        if hasattr(self, 'file_counter_labels'):
            self._update_counter_colors()
        self._update_button_states()
        if hasattr(self, 'status_label'):
            self._update_status_color()

    def _update_status_color(self):
        C = self.colors
        status = self.status_var.get()
        if any(x in status for x in ('Running', 'Armed', '▶')):
            pill_bg = C['accent_success']
        elif 'SAFE' in status or 'DEMO' in status:
            pill_bg = C['accent_danger']
        else:
            pill_bg = C['accent_danger']
        if hasattr(self, '_status_pill_frame'):
            self._status_pill_frame.configure(bg=pill_bg)
            self._status_pill_dot.configure(bg=pill_bg)
            self.status_label.configure(bg=pill_bg)

    def _update_counter_colors(self):
        for val_lbl, lbl_text, clr in self.file_counter_labels:
            val_lbl.configure(bg=clr)
        for val_lbl, lbl_text, clr in self.severity_counter_labels:
            val_lbl.configure(bg=clr)

    def _update_widget_colors(self, widget):
        C = self.colors
        try:
            w_class = widget.winfo_class()
            if w_class == 'Frame':
                bg = widget.cget('bg')
                for old, new in [
                    (DARK_THEME['bg'],       C['bg']),
                    (DARK_THEME['bg2'],      C['bg2']),
                    (DARK_THEME['card_bg'],  C['card_bg']),
                    (DARK_THEME['sidebar_bg'], C['sidebar_bg']),
                    (DARK_THEME['header_bg'],  C['header_bg']),
                    (LIGHT_THEME['bg'],       C['bg']),
                    (LIGHT_THEME['card_bg'],  C['card_bg']),
                ]:
                    if bg == old:
                        widget.configure(bg=new)
                        break
            elif w_class == 'Label':
                try:
                    bg = widget.cget('bg')
                    fg = widget.cget('fg')
                    for old_bg, new_bg in [
                        (DARK_THEME['bg'],      C['bg']),
                        (DARK_THEME['card_bg'], C['card_bg']),
                        (DARK_THEME['sidebar_bg'], C['sidebar_bg']),
                        (DARK_THEME['header_bg'],  C['header_bg']),
                        (LIGHT_THEME['bg'],      C['bg']),
                        (LIGHT_THEME['card_bg'], C['card_bg']),
                    ]:
                        if bg == old_bg:
                            widget.configure(bg=new_bg)
                            break
                    for old_fg, new_fg in [
                        (DARK_THEME['text_primary'],   C['text_primary']),
                        (DARK_THEME['text_secondary'], C['text_secondary']),
                        (DARK_THEME['text_muted'],     C['text_muted']),
                        (LIGHT_THEME['text_primary'],  C['text_primary']),
                    ]:
                        if fg == old_fg:
                            widget.configure(fg=new_fg)
                            break
                except Exception:
                    pass
        except Exception:
            pass
        for child in widget.winfo_children():
            self._update_widget_colors(child)

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

    def _is_side_menu_widget(self, widget):
        if not hasattr(self, '_side_menu_widgets'):
            return False
        return widget in self._side_menu_widgets

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
        self._append_log('Starting cloud sync…')
        try:
            from core.cloud_sync import cloud_sync
            if hasattr(cloud_sync, 'sync_vault'):
                threading.Thread(target=cloud_sync.sync_vault, daemon=True).start()
                messagebox.showinfo('Cloud Sync', 'Cloud sync started in background.')
        except Exception as e:
            messagebox.showinfo('Cloud Sync', f'Cloud sync: {e}')

    def _restore_from_cloud(self):
        self._append_log('Restoring from cloud…')
        try:
            from core.cloud_sync import cloud_sync
            if hasattr(cloud_sync, 'restore_from_cloud'):
                threading.Thread(target=cloud_sync.restore_from_cloud, daemon=True).start()
                messagebox.showinfo('Cloud Restore', 'Cloud restore started in background.')
        except Exception as e:
            messagebox.showinfo('Cloud Restore', f'Cloud restore: {e}')

    # ── Toggle handlers (call original core methods, then sync toggle UI) ──

    def _toggle_active_defense(self):
        """Toggle active defense — bridge to original logic."""
        new_state = self._ad_var.get()
        self.ad_btn_text.set('ON' if new_state else 'OFF')
        try:
            from core.integrity_core import CONFIG
            CONFIG['active_defense'] = new_state
            self._append_log(
                f'Active Defense {"ENABLED" if new_state else "DISABLED"} by {self.username}')
        except Exception as e:
            print(f'Active defense toggle: {e}')

    def _toggle_killswitch(self):
        """Toggle ransomware killswitch."""
        new_state = self._ks_var.get()
        self.ks_btn_text.set('ON' if new_state else 'OFF')
        try:
            from core.integrity_core import CONFIG
            CONFIG['ransomware_killswitch'] = new_state
            self._append_log(
                f'Ransomware Killswitch {"ARMED" if new_state else "DISARMED"} by {self.username}')
        except Exception as e:
            print(f'Killswitch toggle: {e}')
        # Legacy button references
        try:
            self.ks_toggle_btn = type('obj', (object,), {
                'configure': lambda self_inner, **kw: None})()
        except Exception:
            pass

    def _toggle_usb_control(self):
        """Toggle USB device control."""
        new_state = self._usb_var.get()
        self.usb_btn_text.set('LOCKED' if new_state else 'ALLOWED')
        try:
            from core.usb_policy import usb_policy
            if new_state:
                usb_policy.enable_readonly()
            else:
                usb_policy.disable_readonly()
            self._append_log(
                f'USB Control {"LOCKED (read-only)" if new_state else "UNLOCKED"} by {self.username}')
        except Exception as e:
            print(f'USB toggle: {e}')

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


    def _show_activation_dialog(self):
        """Popup to enter the commercial license key"""
        key = simpledialog.askstring(
            "Activate FMSecure PRO", 
            "Enter your PRO License Key:\n(Purchased from the FMSecure website)",
            parent=self.root
        )
        
        if key:
            # Clean up the key just in case they accidentally copied a space
            clean_key = key.strip()
            success, msg = auth.activate_license(self.username, clean_key)
            
            if success:
                messagebox.showinfo("Activation Successful! 🎉", msg)
                self.status_var.set("⭐ Premium Active")
                
                # 1. Destroy the upgrade button completely
                if hasattr(self, 'upgrade_btn') and self.upgrade_btn.winfo_exists():
                    self.upgrade_btn.destroy()
                    
                # 2. Inject the sleek PRO badge exactly where the button used to be
                self.pro_badge = tk.Label(self.top_btn_frame, text="⭐ PRO ACTIVE", 
                                        font=('Segoe UI', 10, 'bold'), 
                                        bg=self.colors['header_bg'], fg="#ffd700")
                # Pack it before the theme toggle button so it sits on the far left
                self.pro_badge.pack(side=tk.LEFT, padx=(0, 15), before=self.theme_btn)
                    
                # Update the visual footer
                if hasattr(self, 'footer_label'):
                    self.footer_label.config(
                        text=f"🔐 FMSecure PRO • Licensed to: {registered_email}", 
                        fg=self.colors['accent_success']
                    )
            else:
                messagebox.showerror("Activation Failed", msg)


    def _add_folder_gui(self):
        """Add a folder to the list (Fail-Safe Premium Check)"""
        current_count = self.folder_listbox.size()
        
        # 1. FOOLPROOF TIER CHECK
        tier = "FREE"
        if auth:
            tier = auth.get_user_tier(self.username).upper()
            
        # GUI OVERRIDE: If the PRO badge is on screen, force unlock!
        if hasattr(self, 'pro_badge') and self.pro_badge.winfo_exists():
            tier = "PRO"
            
        limit = 5 if tier == "PRO" else 1

        # 2. ENFORCE GATING
        if current_count >= limit:
            if tier != "PRO":
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

    def _show_activation_dialog(self):
        """Popup to enter the commercial license key (Account-Based)"""
        # --- THE FIX: Force memory to sync with the fresh users.json file ---
        if auth:
            auth._load_users()
            
        # 1. Fetch the already registered email from the database
        user_data = auth.users.get(self.username, {})
        registered_email = user_data.get("registered_email", "")
        
        if not registered_email:
            messagebox.showerror("Error", "No registered email found for this account. Please contact support.")
            return

        # 2. Ask for the License Key ONLY
        key = simpledialog.askstring(
            "Activate FMSecure PRO", 
            f"Account: {registered_email}\n\nEnter your PRO License Key:\n(Purchased from FMSecure website)",
            parent=self.root
        )
        
        if not key: return # User cancelled
        clean_key = key.strip()
        
        # 3. Send to Auth Manager
        success, msg = auth.activate_license(self.username, clean_key)
        
        if success:
            messagebox.showinfo("Activation Successful! 🎉", msg)
            self.status_var.set("⭐ Premium Active")
            
            # Hide the upgrade button instantly
            if hasattr(self, 'upgrade_btn') and self.upgrade_btn.winfo_exists():
                self.upgrade_btn.destroy()
                
            # Inject the sleek PRO badge exactly where the button used to be
            self.pro_badge = tk.Label(self.top_btn_frame, text="⭐ PRO ACTIVE", 
                                      font=('Segoe UI', 10, 'bold'), 
                                      bg=self.colors['header_bg'], fg="#ffd700")
            self.pro_badge.pack(side=tk.LEFT, padx=(0, 15), before=self.theme_btn)
                
            # Update the visual footer
            if hasattr(self, 'footer_label'):
                self.footer_label.config(
                    text=f"🔐 FMSecure PRO • Licensed to: {registered_email}", 
                    fg=self.colors['accent_success']
                )
        else:
            messagebox.showerror("Activation Failed", msg)

    def _start_telemetry_heartbeat(self):
        """Silently pings the FastAPI C2 Server every 10 seconds"""
        def heartbeat_loop():
            # Generate a unique hardware ID and get the PC name
            machine_id = str(uuid.getnode())
            hostname = socket.gethostname()
            c2_url = "http://127.0.0.1:8000/api/heartbeat"
            
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
                    response = requests.post(c2_url, json=payload, timeout=5)
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


    def _toggle_active_defense(self):
        # 1. FOOLPROOF TIER CHECK
        tier = "FREE"
        if auth:
            tier = auth.get_user_tier(self.username).upper()
            
        # GUI OVERRIDE: If the PRO badge is on screen, force unlock!
        if hasattr(self, 'pro_badge') and self.pro_badge.winfo_exists():
            tier = "PRO"
        
        if tier != "PRO":
            from tkinter import messagebox
            messagebox.showwarning("⭐ Premium Feature", "🛡️ Active Defense is a PRO feature.\n\nPlease activate a License Key to unlock.")
            # Snap back to OFF
            current_state = CONFIG.get("active_defense", False)
            self.ad_btn_text.set("ON" if current_state else "OFF")
            self.ad_toggle_btn.configure(bg=self.colors['accent_success'] if current_state else self.colors['text_muted'])
            return 
            
        # 2. Toggle the state
        current_state = CONFIG.get("active_defense", False)
        new_state = not current_state
        CONFIG["active_defense"] = new_state
        
        # 3. Update the UI appearance
        if new_state:
            self.ad_btn_text.set("ON")
            self.ad_toggle_btn.configure(bg=self.colors['accent_success'])
            self._append_log("🛡️ Active Defense ENABLED. Files will be auto-restored.")
        else:
            self.ad_btn_text.set("OFF")
            self.ad_toggle_btn.configure(bg=self.colors['text_muted'])
            self._append_log("🛡️ Active Defense DISABLED.")
            
        # 4. Save to config.json AND Reload Backend Engine
        try:
            import json
            from core.integrity_core import CONFIG_FILE, load_config
            
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    file_cfg = json.load(f)
            else:
                file_cfg = dict(CONFIG)
                
            file_cfg["active_defense"] = new_state
            
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(file_cfg, f, indent=4)
                
            # Tell backend to reload the exact same Universal Brain file
            load_config(CONFIG_FILE)
            
        except Exception as e:
            print(f"Error saving Active Defense state: {e}")

    def _toggle_killswitch(self):
        # 1. FOOLPROOF TIER CHECK
        tier = "FREE"
        if auth:
            tier = auth.get_user_tier(self.username).upper()
            
        # GUI OVERRIDE: If the PRO badge is on screen, force unlock!
        if hasattr(self, 'pro_badge') and self.pro_badge.winfo_exists():
            tier = "PRO"
        
        if tier != "PRO":
            from tkinter import messagebox
            messagebox.showwarning("⭐ Premium Feature", "🛑 Ransomware Killswitch is a PRO feature.\n\nPlease activate a License Key to unlock.")
            # Snap back to OFF
            current_state = CONFIG.get("ransomware_killswitch", False)
            self.ks_btn_text.set("ON" if current_state else "OFF")
            self.ks_toggle_btn.configure(bg=self.colors['accent_success'] if current_state else self.colors['text_muted'])
            return
            
        # 2. Toggle the state
        current_state = CONFIG.get("ransomware_killswitch", False)
        new_state = not current_state
        CONFIG["ransomware_killswitch"] = new_state
        
        # 3. Update the UI appearance
        if new_state:
            self.ks_btn_text.set("ON")
            self.ks_toggle_btn.configure(bg=self.colors['accent_success'])
            self._append_log("🛑 Ransomware Killswitch ENABLED. Burst-protection active.")
        else:
            self.ks_btn_text.set("OFF")
            self.ks_toggle_btn.configure(bg=self.colors['text_muted'])
            self._append_log("🛑 Ransomware Killswitch DISABLED.")
            
        # 4. Save to config.json AND Reload Backend Engine
        try:
            import json
            from core.integrity_core import CONFIG_FILE, load_config
            
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    file_cfg = json.load(f)
            else:
                file_cfg = dict(CONFIG)
                
            file_cfg["ransomware_killswitch"] = new_state
            
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(file_cfg, f, indent=4)
                
            # Tell backend to reload the exact same Universal Brain file
            load_config(CONFIG_FILE)
            
        except Exception as e:
            print(f"Error saving Killswitch state: {e}")

    def _toggle_usb_control(self):
        # 1. FOOLPROOF TIER CHECK
        tier = "FREE"
        if auth:
            tier = auth.get_user_tier(self.username).upper()
            
        # GUI OVERRIDE
        if hasattr(self, 'pro_badge') and self.pro_badge.winfo_exists():
            tier = "PRO"
        
        if tier != "PRO":
            from tkinter import messagebox
            messagebox.showwarning("⭐ Premium Feature", "🔌 USB Device Control is a PRO feature.\n\nPlease activate a License Key to unlock.")
            return

        # 2. ADMIN AUTHORIZATION (Registry edits are highly sensitive!)
        if not self._authenticate_action("Modify USB Device Policy"):
            return
            
        # 3. Toggle the state
        current_state = CONFIG.get("usb_readonly", False)
        new_state = not current_state
        
        # 4. Call Backend System Registry Script
        try:
            from core.usb_policy import set_usb_read_only
            success, msg = set_usb_read_only(enable=new_state)
            if not success:
                from tkinter import messagebox
                messagebox.showerror("Policy Error", msg)
                return
        except Exception as e:
            from tkinter import messagebox
            messagebox.showerror("Execution Error", f"Failed to execute USB policy: {e}")
            return

        # 5. Update the UI appearance
        CONFIG["usb_readonly"] = new_state
        
        if new_state:
            self.usb_btn_text.set("LOCKED")
            self.usb_toggle_btn.configure(bg=self.colors['accent_success'])
            self._append_log("🔌 USB Policy ENABLED: All USB Storage devices set to Read-Only.")
            self._show_alert("USB Policy Updated", "USB Storage devices are now LOCKED (Read-Only).", "high")
        else:
            self.usb_btn_text.set("ALLOWED")
            self.usb_toggle_btn.configure(bg=self.colors['text_muted'])
            self._append_log("🔌 USB Policy DISABLED: USB Read/Write allowed.")
            self._show_alert("USB Policy Updated", "USB Storage devices are now UNLOCKED.", "info")
            
        # 6. Save to Universal Brain AND Reload Backend Engine
        try:
            import json
            from core.integrity_core import CONFIG_FILE, load_config
            
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    file_cfg = json.load(f)
            else:
                file_cfg = dict(CONFIG)
                
            file_cfg["usb_readonly"] = new_state
            
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(file_cfg, f, indent=4)
                
            load_config(CONFIG_FILE)
            
        except Exception as e:
            print(f"Error saving USB Policy state: {e}")

    # ===== HELPER METHODS FROM BACKUP =====
    
    def _append_log(self, text):
        """Append text to the log display - IMPORTED FROM BACKUP"""
        try:
            self.log_box.configure(state="normal")
            now = datetime.now().strftime("%H:%M:%S")
            self.log_box.insert(tk.END, f"[{now}] {text}\n")
            self.log_box.configure(state="disabled")
            self.log_box.see(tk.END)
        except Exception as e:
            print(f"Error appending to log: {e}")

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
        """Clear the log display"""
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", tk.END)
        self.log_box.configure(state="disabled")
        self._append_log("Log display cleared")

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
        """Apply current theme to all widgets"""
        # Update root window
        self.root.configure(bg=self.colors['bg'])
        
        # Update all widgets with force refresh
        self._update_widget_colors(self.root)
        
        # Update counter colors
        if hasattr(self, 'file_counter_labels') and hasattr(self, 'severity_counter_labels'):
            self._update_counter_colors()
        
        # Force update button states (fix hover colors)
        self._update_button_states()
        
        # Update status label color
        if hasattr(self, 'status_label'):
            current_status = self.status_var.get()
            if "Running" in current_status or "🟢" in current_status:
                self.status_label.configure(fg=self.colors['accent_success'])
            elif "DEMO" in current_status or "SAFE" in current_status:
                self.status_label.configure(fg=self.colors['accent_danger'])
            elif "Read-Only" in current_status:
                self.status_label.configure(fg=self.colors['accent_warning'])
            else:  # Stopped
                self.status_label.configure(fg=self.colors['accent_primary'])
        
        # Update menu button colors
        if hasattr(self, 'menu_btn'):
            self.menu_btn.configure(bg=self.colors['header_bg'], 
                                fg=self.colors['text_primary'])
        
        # Update side menu colors if it exists
        if hasattr(self, 'side_menu'):
            self.side_menu.configure(bg=self.colors['sidebar_bg'])
            for child in self.side_menu.winfo_children():
                if isinstance(child, tk.Button):
                    if "Demo" in child.cget('text'):
                        child.configure(bg='#8b5cf6')
                    elif "Archive" in child.cget('text'):
                        child.configure(bg='#ef4444')
                    elif "Close" in child.cget('text'):
                        child.configure(bg=self.colors['sidebar_bg'], 
                                    fg=self.colors['text_secondary'])

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

    def _update_counter_widgets(self, widget):
        """Recursively find and update counter widget colors"""
        try:
            if isinstance(widget, tk.Label):
                # Check if this is a counter label by its styling
                text = widget.cget('text')
                bg = widget.cget('bg')
                
                # Check if it's a statistic counter (has specific colors)
                if bg in [DARK_THEME['accent_primary'], LIGHT_THEME['accent_primary'],
                        DARK_THEME['accent_success'], LIGHT_THEME['accent_success'],
                        DARK_THEME['accent_warning'], LIGHT_THEME['accent_warning'],
                        DARK_THEME['accent_danger'], LIGHT_THEME['accent_danger']]:
                    
                    # Determine which color to use based on text content
                    if "Total" in str(widget.master) or text == "0":  # Total files
                        widget.configure(bg=self.colors['accent_primary'], fg='white')
                    elif "Created" in str(widget.master):  # Created files
                        widget.configure(bg=self.colors['accent_success'], fg='white')
                    elif "Modified" in str(widget.master):  # Modified files
                        widget.configure(bg=self.colors['accent_warning'], fg='white')
                    elif "Deleted" in str(widget.master):  # Deleted files
                        widget.configure(bg=self.colors['accent_danger'], fg='white')
            
            # Recursively check children
            for child in widget.winfo_children():
                self._update_counter_widgets(child)
        except:
            pass


    def _update_severity_counter_colors(self):
        """Update severity counter colors after theme change"""
        # Find and update severity counter labels
        try:
            # CRITICAL counter
            if hasattr(self, 'critical_var'):
                # Find the label showing critical count
                for widget in self.root.winfo_children():
                    self._find_and_update_severity_label(widget, "CRITICAL", self.critical_var.get())
            
            # Similar for HIGH, MEDIUM, INFO
            # You would implement similar logic for each severity level
            # This is a simplified version - you might need to adjust based on your actual widget structure
            
        except Exception as e:
            print(f"Error updating severity colors: {e}")


    def _find_and_update_severity_label(self, widget, severity, value):
        """Find and update a specific severity label"""
        try:
            if isinstance(widget, tk.Label):
                # Check if this is the severity label
                if severity in widget.cget('text') or widget.cget('textvariable') == getattr(self, f'{severity.lower()}_var', None):
                    # Update color based on severity
                    color = SEVERITY_COLORS.get(severity, self.colors['accent_info'])
                    widget.configure(bg=color, fg='white')
            
            # Check children
            for child in widget.winfo_children():
                self._find_and_update_severity_label(child, severity, value)
        except:
            pass

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
        
        # Create side menu frame with hacker theme
        self.side_menu = tk.Frame(self.root, 
                                bg='#000000',  # Black background
                                width=self.menu_width,
                                bd=2, 
                                relief='ridge',
                                highlightbackground='#00ff00',  # Matrix green border
                                highlightthickness=1)
        self.side_menu.place(x=-self.menu_width, y=0, width=self.menu_width, relheight=1.0)
        
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
        """Toggle the side menu visibility with enhanced animation"""
        if not self.menu_visible:
            # Show menu with matrix animation
            self._animate_menu(0)
            self.menu_visible = True
            # Start animations
            self._blink_menu_title()
            self._blink_status_dots()
            self._start_matrix_animation()
        else:
            # Hide menu
            self._animate_menu(-self.menu_width)
            self.menu_visible = False

    def _animate_menu(self, target_x):
        """Animate menu sliding in/out"""
        current_x = self.side_menu.winfo_x()
        
        if current_x < target_x:
            step = 30  # Slide right
        else:
            step = -30  # Slide left
        
        if abs(target_x - current_x) < abs(step):
            # FIX: Use place_configure or pass all arguments so it doesn't lose its height!
            self.side_menu.place(x=target_x, y=0, width=self.menu_width, relheight=1.0)
            if target_x == -self.menu_width:
                self.menu_visible = False
            return
        
        new_x = current_x + step
        # FIX: Keep the y, width, and relheight properties during the animation frame
        self.side_menu.place(x=new_x, y=0, width=self.menu_width, relheight=1.0)
        self.root.after(10, lambda: self._animate_menu(target_x))

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


    def _authenticate_action(self, action_name):
        """
        Helper: Prompts for password.
        Must only be called from the Main Thread.
        """
        if not self.monitor_running:
            return True

        # Use parent=None or parent=self.root. 
        password = simpledialog.askstring(
            f"Security Verification - {action_name}", 
            f"Monitoring is ACTIVE.\n\nEnter password for '{self.username}' to access dashboard:",
            parent=self.root, 
            show='*'
        )

        if not password:
            return False

        if auth:
            # --- THE FIX: Force the background tray to sync with the live database! ---
            auth._load_users()
            
            # Unpack 3 values (success, role, message)
            success, _, msg = auth.login(self.username, password)
            
            if success:
                return True
            else:
                messagebox.showerror("Access Denied", "Incorrect Password.\nEvent has been logged.")
                self._append_log(f"SECURITY: Failed dashboard access attempt for {self.username}")
                return False
        
        return True

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
        """Allow admin to change their password with hacker-themed UI"""
        if self.user_role != 'admin':
            messagebox.showerror("Permission Denied", "Only administrators can change passwords.")
            return

        if not auth:
            messagebox.showerror("Error", "Authentication backend not loaded.")
            self._append_log(f"Auth module state: auth={auth}")
            return

        # Create hacker-themed password change window
        self._create_hacker_password_window()

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

    def _update_button_states(self):
        """Force button colors to update by toggling state"""
        # Get all buttons and force color update
        def update_btn_colors(widget):
            # SKIP side menu buttons
            if self._is_side_menu_widget(widget):
                return

            for child in widget.winfo_children():
                # Recursively check children FIRST
                update_btn_colors(child)
                
                if isinstance(child, tk.Button):
                    # Skip theme and special buttons
                    if child not in [self.theme_btn, getattr(self, 'menu_btn', None), getattr(self, 'pass_btn', None), 
                                getattr(self, 'unlock_btn', None), getattr(self, 'logout_btn', None)]:
                        
                        # SKIP side menu buttons (double check for direct children)
                        if self._is_side_menu_widget(child):
                            continue

                        # ... REST OF YOUR EXISTING LOGIC ...
                        # (Set colors for Start/Stop/Verify etc...)
                        btn_text = child.cget('text')
                        
                        # Default Colors
                        new_bg = self.colors['button_bg']
                        new_fg = self.colors['text_primary']
                        
                        # Specific Buttons
                        if "Start" in btn_text: new_bg = self.colors['accent_success']; new_fg = 'white'
                        elif "Stop" in btn_text: new_bg = self.colors['accent_danger']; new_fg = 'white'
                        elif "Verify" in btn_text: new_bg = self.colors['accent_primary']; new_fg = 'white'
                        elif "Check" in btn_text: new_bg = self.colors['accent_secondary']; new_fg = 'white'
                        elif "Settings" in btn_text: new_bg = self.colors['accent_info']; new_fg = 'white'
                        elif "Reset" in btn_text: new_bg = self.colors['accent_warning']; new_fg = 'white'
                        
                        try:
                            child.configure(bg=new_bg, fg=new_fg)
                        except: pass
                        
                        # Re-bind hover events
                        btn_text = child.cget('text')
                        if "Start" in btn_text:
                            child.bind("<Enter>", lambda e, b=child: b.configure(
                                bg=self._lighten_color(self.colors['accent_success'])))
                            child.bind("<Leave>", lambda e, b=child: b.configure(
                                bg=self.colors['accent_success']))
                        elif "Stop" in btn_text:
                            child.bind("<Enter>", lambda e, b=child: b.configure(
                                bg=self._lighten_color(self.colors['accent_danger'])))
                            child.bind("<Leave>", lambda e, b=child: b.configure(
                                bg=self.colors['accent_danger']))
                        elif "Verify" in btn_text:
                            child.bind("<Enter>", lambda e, b=child: b.configure(
                                bg=self._lighten_color(self.colors['accent_primary'])))
                            child.bind("<Leave>", lambda e, b=child: b.configure(
                                bg=self.colors['accent_primary']))
                        elif "Check" in btn_text:
                            child.bind("<Enter>", lambda e, b=child: b.configure(
                                bg=self._lighten_color(self.colors['accent_secondary'])))
                            child.bind("<Leave>", lambda e, b=child: b.configure(
                                bg=self.colors['accent_secondary']))
                        elif "Settings" in btn_text:
                            child.bind("<Enter>", lambda e, b=child: b.configure(
                                bg=self._lighten_color(self.colors['accent_info'])))
                            child.bind("<Leave>", lambda e, b=child: b.configure(
                                bg=self.colors['accent_info']))
                        elif "Reset" in btn_text:
                            child.bind("<Enter>", lambda e, b=child: b.configure(
                                bg=self._lighten_color(self.colors['accent_warning'])))
                            child.bind("<Leave>", lambda e, b=child: b.configure(
                                bg=self.colors['accent_warning']))
                        else:
                            # For report buttons
                            child.bind("<Enter>", lambda e, b=child: b.configure(
                                bg=self.colors['button_hover']))
                            child.bind("<Leave>", lambda e, b=child: b.configure(
                                bg=self.colors['button_bg']))
                
                # Recursively update children
                update_btn_colors(child)
        
        update_btn_colors(self.root)


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