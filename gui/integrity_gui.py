#!/usr/bin/env python3
"""
integrity_gui.py — Upgraded GUI for FileIntegrityChecker
Professional Security Monitor with Premium UI Design
"""
import random 
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox, simpledialog
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


APP_DATA = get_app_data_dir()
LOGS_DIR = os.path.join(APP_DATA, "logs")

try:
    from core import safe_mode
except ImportError:
    import sys
    import os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    core_dir = os.path.join(os.path.dirname(current_dir), 'core')
    if core_dir not in sys.path:
        sys.path.append(core_dir)
    import safe_mode

# Ensure logs dir exists
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
        import sys
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

# Import Auth for password changing
auth = None
try:
    # Try multiple possible locations for auth_manager
    try:
        from auth_manager import auth
    except ImportError:
        # Try core.auth_manager if structured differently
        from core.auth_manager import auth
except ImportError as e:
    print(f"⚠️ Auth Manager import failed: {e}")
    # Try to find auth_manager in the parent directory
    try:
        import sys
        import os
        # Add parent directory to path
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

# Premium color schemes
DARK_THEME = {
    'bg': '#0f172a',           # Dark navy background
    'card_bg': '#1e293b',      # Card background
    'card_border': '#334155',  # Card border
    'sidebar_bg': '#111827',   # Sidebar background
    'header_bg': '#1e293b',    # Header background
    'text_primary': '#f1f5f9', # Primary text
    'text_secondary': '#94a3b8', # Secondary text
    'text_muted': '#64748b',   # Muted text
    'accent_primary': '#3b82f6', # Primary accent (Blue)
    'accent_secondary': '#8b5cf6', # Secondary accent (Purple)
    'accent_success': '#10b981',  # Success (Green)
    'accent_warning': '#f59e0b',  # Warning (Amber)
    'accent_danger': '#ef4444',   # Danger (Red)
    'accent_info': '#06b6d4',     # Info (Cyan)
    'button_bg': '#334155',       # Button background
    'button_hover': '#475569',    # Button hover
    'button_active': '#3b82f6',   # Button active
    'input_bg': '#1e293b',        # Input background
    'input_border': '#475569',    # Input border
    'indicator_success': '#10b981',
    'indicator_warning': '#f59e0b',
    'indicator_danger': '#ef4444',
    'indicator_info': '#06b6d4',
    'chart_bg': '#1e293b',
    'chart_grid': '#334155',
    'chart_text': '#f1f5f9'
}

LIGHT_THEME = {
    'bg': '#f8fafc',           # Light background
    'card_bg': '#ffffff',      # Card background
    'card_border': '#e2e8f0',  # Card border
    'sidebar_bg': '#f1f5f9',   # Sidebar background
    'header_bg': '#ffffff',    # Header background
    'text_primary': '#1e293b', # Primary text
    'text_secondary': '#475569', # Secondary text
    'text_muted': '#64748b',   # Muted text
    'accent_primary': '#3b82f6', # Primary accent (Blue)
    'accent_secondary': '#8b5cf6', # Secondary accent (Purple)
    'accent_success': '#10b981',  # Success (Green)
    'accent_warning': '#f59e0b',  # Warning (Amber)
    'accent_danger': '#ef4444',   # Danger (Red)
    'accent_info': '#06b6d4',     # Info (Cyan)
    'button_bg': '#e2e8f0',       # Button background
    'button_hover': '#cbd5e1',    # Button hover
    'button_active': '#3b82f6',   # Button active
    'input_bg': '#ffffff',        # Input background
    'input_border': '#cbd5e1',    # Input border
    'indicator_success': '#10b981',
    'indicator_warning': '#f59e0b',
    'indicator_danger': '#ef4444',
    'indicator_info': '#06b6d4',
    'chart_bg': '#ffffff',
    'chart_grid': '#e2e8f0',
    'chart_text': '#1e293b'
}

# Severity colors with premium styling
SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",      # Red
    "HIGH": "#f97316",          # Orange
    "MEDIUM": "#f59e0b",        # Amber
    "INFO": "#06b6d4",          # Cyan
}

SEVERITY_EMOJIS = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "INFO": "🔵",
}

SEVERITY_BADGES = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "INFO": "INFO",
}

# Import charting libraries
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("Matplotlib not available - charts disabled")

# Import PDF libraries
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
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
    class ToolTip:
        """Simple tooltip for widgets"""
        def __init__(self, widget, text):
            self.widget = widget
            self.text = text
            self.tooltip = None
            self.widget.bind("<Enter>", self.show)
            self.widget.bind("<Leave>", self.hide)
        
        def show(self, event=None):
            """Show tooltip on hover"""
            if self.tooltip or not self.text:
                return
            # Calculate position
            x, y, _, _ = self.widget.bbox("insert")
            x += self.widget.winfo_rootx() + 25
            y += self.widget.winfo_rooty() + 25
            
            # Create tooltip window
            self.tooltip = tk.Toplevel(self.widget)
            self.tooltip.wm_overrideredirect(True)
            self.tooltip.wm_geometry(f"+{x}+{y}")
            
            # Create label
            label = tk.Label(self.tooltip, text=self.text, 
                        background="#ffffe0", relief="solid", borderwidth=1,
                        font=("Segoe UI", 9))
            label.pack()
            
        def hide(self, event=None):
            """Hide tooltip"""
            if self.tooltip:
                self.tooltip.destroy()
                self.tooltip = None
                
    def __init__(self, root, user_role='admin', username='admin'):
        self.root = root
        self.user_role = user_role
        self.username = username
        
        # Set window properties
        self.root.title(f"🛡️ File Integrity Monitor — Professional Edition")
        self.root.geometry("1400x900")
        self.root.minsize(1200, 800)
        
        # Theme management
        self.dark_mode = True  # Start with dark theme
        self.colors = DARK_THEME

        # Counter label storage
        self.file_counter_labels = []
        self.severity_counter_labels = []
        
        # Alert panel configuration - FIXED POSITIONING
        self.ALERT_PANEL_WIDTH = 350  # Reduced width to avoid overlap
        self.ALERT_PANEL_HEIGHT = 300  # Reduced height
        self.ALERT_ANIM_STEP = 25
        self.ALERT_ANIM_DELAY = 10
        self.ALERT_SHOW_MS = 5000
        self.alert_visible = False
        self.alert_hide_after_id = None
        
        # Report tracking - ADDED FROM BACKUP
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
        
        # Chart configuration - ADDED FROM BACKUP
        self.chart_colors = {
            'created': '#10b981',  # Green
            'modified': '#f59e0b',  # Amber
            'deleted': '#ef4444',   # Red
            'total': '#3b82f6'      # Blue
        }

        # Severity counters - ADDED FROM BACKUP
        self.severity_counters = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'INFO': 0
        }

        # UI variables for severity counters - ADDED FROM BACKUP
        self.critical_var = tk.StringVar(value="0")
        self.high_var = tk.StringVar(value="0")
        self.medium_var = tk.StringVar(value="0")
        self.info_var = tk.StringVar(value="0")

        # Ensure config is loaded
        cfg_ok = True
        try:
            if load_config:
                load_config(None)
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

        # UI variables - ADDED MISSING VARIABLES FROM BACKUP
        self.watch_folder_var = tk.StringVar(value=os.path.abspath(CONFIG.get("watch_folder", os.getcwd())))
        self.status_var = tk.StringVar(value="🔴 Stopped")
        self.total_files_var = tk.StringVar(value="0")
        self.created_var = tk.StringVar(value="0")
        self.modified_var = tk.StringVar(value="0")
        self.deleted_var = tk.StringVar(value="0")
        self.tamper_records_var = tk.StringVar(value="UNKNOWN")
        self.tamper_logs_var = tk.StringVar(value="UNKNOWN")
        self.webhook_var = tk.StringVar(value=str(CONFIG.get("webhook_url", "")))

        # Initialize file tracking - ADDED FROM BACKUP
        self.file_tracking = {
            'last_total': 0,
            'session_created': 0,
            'session_modified': 0,
            'session_deleted': 0,
            'current_files': set()
        }

        # Configure styles first_apply_theme
        self._configure_styles()
        
        # Build UI
        self._build_widgets()
        self._create_side_menu()
        self._apply_permissions()
        
        # Create alert panel (initially hidden)
        self._create_alert_panel()

        # Start background update loops - ADDED FROM BACKUP
        self._update_dashboard()
        self._update_severity_counters()
        self._tail_log_loop()

        

        # Start Safe Mode Watcher
        self._check_safe_mode_status()

        # Initialize Tray
        self._setup_tray_icon()
        
        # Intercept "X" button
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)



    def _configure_styles(self):
        """Configure modern ttk styles"""
        try:
            self.style = ttk.Style()
            self.style.theme_use('clam')
        except:
            self.style = ttk.Style()

        # Configure custom styles
        self.style.configure('Modern.TButton',
                           background=self.colors['button_bg'],
                           foreground=self.colors['text_primary'],
                           borderwidth=1,
                           relief='flat',
                           font=('Segoe UI', 10, 'normal'),
                           padding=(15, 8))
        
        self.style.map('Modern.TButton',
                      background=[('active', self.colors['button_hover']),
                                 ('pressed', self.colors['button_active'])],
                      foreground=[('active', self.colors['text_primary']),
                                 ('pressed', '#ffffff')])
        
        self.style.configure('Modern.TEntry',
                           fieldbackground=self.colors['input_bg'],
                           foreground=self.colors['text_primary'],
                           borderwidth=1,
                           insertcolor=self.colors['text_primary'])
        
        self.style.configure('Modern.TLabelframe',
                           background=self.colors['bg'],
                           foreground=self.colors['text_primary'],
                           bordercolor=self.colors['card_border'],
                           relief='solid',
                           borderwidth=1)
        
        self.style.configure('Modern.TLabelframe.Label',
                           background=self.colors['bg'],
                           foreground=self.colors['text_primary'],
                           font=('Segoe UI', 11, 'bold'))

    def _lighten_color(self, color, factor=0.2):
        """Lighten a hex color by factor"""
        try:
            import colorsys
            # Convert hex to RGB
            color = color.lstrip('#')
            rgb = tuple(int(color[i:i+2], 16) for i in (0, 2, 4))
            
            # Convert to HSL
            h, l, s = colorsys.rgb_to_hls(rgb[0]/255, rgb[1]/255, rgb[2]/255)
            
            # Lighten
            l = min(1, l + factor)
            
            # Convert back to RGB
            r, g, b = colorsys.hls_to_rgb(h, l, s)
            
            # Convert to hex
            return f'#{int(r*255):02x}{int(g*255):02x}{int(b*255):02x}'
        except:
            # Fallback: return original color
            return color

    def _build_widgets(self):
        """Build the premium UI with modern design"""
        # Configure root window
        self.root.configure(bg=self.colors['bg'])
        
        # Main container
        main_container = tk.Frame(self.root, bg=self.colors['bg'])
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Header Section
        header_frame = tk.Frame(main_container, bg=self.colors['header_bg'], height=80)
        header_frame.pack(fill=tk.X, pady=(0, 20))
        header_frame.pack_propagate(False)
        # Upgrade Button (Only show if Free)
        # current_tier = auth.get_user_tier(self.username)
        # if current_tier == "free":
        #     self.upgrade_btn = tk.Button(btn_frame, text="⭐ Upgrade", 
        #                                command=self._show_activation_dialog,
        #                                font=('Segoe UI', 10, 'bold'), 
        #                                bg="#ffd700", fg="black") # Gold color
        #     self.upgrade_btn.pack(side=tk.LEFT, padx=10)
        
        # Menu Button
        self.menu_btn = tk.Button(header_frame, text="☰", 
                         command=self.toggle_menu,
                         font=('Segoe UI', 16), 
                         bg=self.colors['header_bg'], 
                         fg=self.colors['text_primary'],
                         bd=0, 
                         padx=15,
                         cursor="hand2")
        self.menu_btn.pack(side=tk.LEFT, padx=(20, 0))
        
        # Logo and Title
        title_frame = tk.Frame(header_frame, bg=self.colors['header_bg'])
        title_frame.pack(side=tk.LEFT, padx=(10, 0), pady=20)
        
        tk.Label(title_frame, text="🛡️", font=('Segoe UI', 28), 
                bg=self.colors['header_bg'], fg=self.colors['accent_primary']).pack(side=tk.LEFT)
        
        title_text = tk.Label(title_frame, text="File Integrity Monitor", 
                             font=('Segoe UI', 20, 'bold'), 
                             bg=self.colors['header_bg'], fg=self.colors['text_primary'])
        title_text.pack(side=tk.LEFT, padx=(10, 0))
        
        subtitle = tk.Label(title_frame, text="Professional Security Edition", 
                           font=('Segoe UI', 11), 
                           bg=self.colors['header_bg'], fg=self.colors['text_secondary'])
        subtitle.pack(side=tk.LEFT, padx=(10, 0))

        # User info and controls
        control_frame = tk.Frame(header_frame, bg=self.colors['header_bg'])
        control_frame.pack(side=tk.RIGHT, padx=30, pady=20)
        
        # User info
        user_label = tk.Label(control_frame, text=f"👤 {self.username}",
                             font=('Segoe UI', 10, 'bold'),
                             bg=self.colors['header_bg'], fg=self.colors['text_secondary'])
        user_label.pack(side=tk.RIGHT, padx=(10, 0))
        
        # Control buttons
        btn_frame = tk.Frame(control_frame, bg=self.colors['header_bg'])
        btn_frame.pack(side=tk.RIGHT)

        self.top_btn_frame = btn_frame


        # --- NEW: PRO UPGRADE BUTTON ---
        # Check their tier dynamically based on their license key
        current_tier = auth.get_user_tier(self.username)
        
        if current_tier == "free":
            self.upgrade_btn = tk.Button(btn_frame, text="⭐ Upgrade to PRO", 
                                       command=self._show_activation_dialog,
                                       font=('Segoe UI', 10, 'bold'), 
                                       bg="#ffd700", fg="#000000", 
                                       bd=0, padx=15, pady=2, cursor="hand2")
            self.upgrade_btn.pack(side=tk.LEFT, padx=(0, 15))
            self.upgrade_btn.bind("<Enter>", lambda e: self.upgrade_btn.configure(bg="#ffea00"))
            self.upgrade_btn.bind("<Leave>", lambda e: self.upgrade_btn.configure(bg="#ffd700"))
        else:
            # If they are already premium, show a sleek gold text badge instead of a button
            self.pro_badge = tk.Label(btn_frame, text="⭐ PRO ACTIVE", 
                                      font=('Segoe UI', 10, 'bold'), 
                                      bg=self.colors['header_bg'], fg="#ffd700")
            self.pro_badge.pack(side=tk.LEFT, padx=(0, 15))
        
        # Theme toggle
        self.theme_btn = tk.Button(btn_frame, text="🌙" if self.dark_mode else "☀️", 
                                  command=self.toggle_theme,
                                  font=('Segoe UI', 12), bg=self.colors['button_bg'], 
                                  fg=self.colors['text_primary'], bd=0, padx=10,
                                  cursor="hand2")
        self.theme_btn.pack(side=tk.LEFT, padx=2)
        self.ToolTip(self.theme_btn, "Toggle Theme")
        
        # Admin controls
        if self.user_role == 'admin':
            self.pass_btn = tk.Button(btn_frame, text="🔑", 
                                    command=self.change_admin_password,
                                    font=('Segoe UI', 12), bg=self.colors['button_bg'], 
                                    fg=self.colors['text_primary'], bd=0, padx=10,
                                    cursor="hand2")
            self.pass_btn.pack(side=tk.LEFT, padx=2)
            self.ToolTip(self.pass_btn, "Change Password")
            
            self.unlock_btn = tk.Button(btn_frame, text="🔓", 
                                      command=self.disable_lockdown,
                                      font=('Segoe UI', 12), bg=self.colors['button_bg'], 
                                      fg=self.colors['text_primary'], bd=0, padx=10,
                                      cursor="hand2")
            self.unlock_btn.pack(side=tk.LEFT, padx=2)
            self.ToolTip(self.unlock_btn, "Disable Lockdown")
        
        # Logout button
        self.logout_btn = tk.Button(btn_frame, text="🚪", 
                                  command=self.logout,
                                  font=('Segoe UI', 12), bg=self.colors['button_bg'], 
                                  fg=self.colors['text_primary'], bd=0, padx=10,
                                  cursor="hand2")
        self.logout_btn.pack(side=tk.LEFT, padx=2)
        self.ToolTip(self.logout_btn, "Logout")

        # Main Content Area
        content_frame = tk.Frame(main_container, bg=self.colors['bg'])
        content_frame.pack(fill=tk.BOTH, expand=True)

        # Initialize label storage
        self.file_counter_labels = []
        self.severity_counter_labels = []

        # ===== LEFT PANEL - Controls and Status =====
        left_panel = tk.Frame(content_frame, bg=self.colors['bg'], width=400)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=False)
        left_panel.pack_propagate(False)

        # --- NEW MULTI-FOLDER SELECTION CARD ---
        folder_card = tk.Frame(left_panel, bg=self.colors['card_bg'], 
                               relief='flat', bd=1, highlightbackground=self.colors['card_border'],
                               highlightthickness=1)
        folder_card.pack(fill=tk.X, pady=(0, 15))
        
        tk.Label(folder_card, text="📁 Protected Directories", font=('Segoe UI', 12, 'bold'),
                bg=self.colors['card_bg'], fg=self.colors['text_primary']).pack(anchor='w', padx=20, pady=(15, 10))
        
        # Listbox and Scrollbar Frame
        list_frame = tk.Frame(folder_card, bg=self.colors['card_bg'])
        list_frame.pack(fill=tk.X, padx=20, pady=(0, 10))

        # 1. The Listbox (Replaces the text entry)
        self.folder_listbox = tk.Listbox(list_frame, height=3, selectmode=tk.SINGLE,
                                         bg=self.colors['input_bg'], fg=self.colors['text_primary'],
                                         relief='solid', bd=1, highlightbackground=self.colors['input_border'])
        self.folder_listbox.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Scrollbar for Listbox
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.folder_listbox.yview)
        scrollbar.pack(side=tk.LEFT, fill=tk.Y, padx=(2, 0))
        self.folder_listbox.config(yscrollcommand=scrollbar.set)
        
        # Load existing folders from config
        from core.integrity_core import CONFIG
        current_folders = CONFIG.get("watch_folders", [])
        if not current_folders and CONFIG.get("watch_folder"):
             current_folders = [CONFIG["watch_folder"]]
        for f in current_folders:
            self.folder_listbox.insert(tk.END, f)

        # 2. Add/Remove Buttons
        btn_frame_folders = tk.Frame(folder_card, bg=self.colors['card_bg'])
        btn_frame_folders.pack(fill=tk.X, padx=20, pady=(0, 15))

        self.add_folder_btn = tk.Button(btn_frame_folders, text="➕ Add Folder", command=self._add_folder_gui,
                                        font=('Segoe UI', 9, 'bold'), bg=self.colors['accent_success'], fg='white',
                                        bd=0, padx=10, pady=5, cursor="hand2")
        self.add_folder_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))

        self.remove_folder_btn = tk.Button(btn_frame_folders, text="➖ Remove", command=self._remove_folder_gui,
                                           font=('Segoe UI', 9, 'bold'), bg=self.colors['accent_danger'], fg='white',
                                           bd=0, padx=10, pady=5, cursor="hand2")
        self.remove_folder_btn.pack(side=tk.RIGHT, expand=True, fill=tk.X, padx=(5, 0))

        # Status Card
        status_card = tk.Frame(left_panel, bg=self.colors['card_bg'],
                              relief='flat', bd=1, highlightbackground=self.colors['card_border'],
                              highlightthickness=1)
        status_card.pack(fill=tk.X, pady=(0, 15))
        
        tk.Label(status_card, text="📊 System Status", font=('Segoe UI', 12, 'bold'),
                bg=self.colors['card_bg'], fg=self.colors['text_primary']).pack(anchor='w', padx=20, pady=(15, 10))
        
        status_content = tk.Frame(status_card, bg=self.colors['card_bg'])
        status_content.pack(fill=tk.X, padx=20, pady=(0, 15))
        
        tk.Label(status_content, text="Status:", font=('Segoe UI', 10),
                bg=self.colors['card_bg'], fg=self.colors['text_secondary']).pack(side=tk.LEFT)
        
        self.status_label = tk.Label(status_content, textvariable=self.status_var,
                                    font=('Segoe UI', 10, 'bold'), bg=self.colors['card_bg'],
                                    fg=self.colors['accent_primary'])
        self.status_label.pack(side=tk.LEFT, padx=(10, 0))

        # Action Buttons Card
        action_card = tk.Frame(left_panel, bg=self.colors['card_bg'],
                              relief='flat', bd=1, highlightbackground=self.colors['card_border'],
                              highlightthickness=1)
        action_card.pack(fill=tk.X, pady=(0, 15))
        
        tk.Label(action_card, text="🎮 Control Panel", font=('Segoe UI', 12, 'bold'),
                bg=self.colors['card_bg'], fg=self.colors['text_primary']).pack(anchor='w', padx=20, pady=(15, 10))
        
        # Create button grid - IMPORTED FROM BACKUP
        buttons = [
            ("▶ Start Monitor", self.start_monitor, self.colors['accent_success']),
            ("⏹ Stop Monitor", self.stop_monitor, self.colors['accent_danger']),
            ("🔍 Verify Now", self.run_verification, self.colors['accent_primary']),
            ("🔒 Check Signatures", self.verify_signatures, self.colors['accent_secondary']),
            ("⚙ Settings", self.open_settings, self.colors['accent_info']),
            ("🔄 Reset Counters", self.reset_severity_counters, self.colors['accent_warning']),
        ]
        
        for i, (text, command, color) in enumerate(buttons):
            btn = tk.Button(action_card, text=text, command=command,
                          font=('Segoe UI', 9, 'bold'), bg=color, fg='white',
                          bd=0, padx=18, pady=9, cursor="hand2",
                          activebackground=color)
            btn.pack(fill=tk.X, padx=17, pady=4)
            btn.bind("<Enter>", lambda e, b=btn: b.configure(bg=self._lighten_color(color)))
            btn.bind("<Leave>", lambda e, b=btn, c=color: b.configure(bg=c))

        # Security Status Card - IMPORTED FROM BACKUP
        security_card = tk.Frame(left_panel, bg=self.colors['card_bg'],
                                relief='flat', bd=1, highlightbackground=self.colors['card_border'],
                                highlightthickness=1)
        security_card.pack(fill=tk.X)
        
        tk.Label(security_card, text="🛡️ Security Status", font=('Segoe UI', 12, 'bold'),
                bg=self.colors['card_bg'], fg=self.colors['text_primary']).pack(anchor='w', padx=20, pady=(15, 10))
        
        security_content = tk.Frame(security_card, bg=self.colors['card_bg'])
        security_content.pack(fill=tk.X, padx=20, pady=(0, 15))
        
        # Security indicators - IMPORTED FROM BACKUP
        indicators = [
            ("Hash Records:", self.tamper_records_var),
            ("Log Files:", self.tamper_logs_var),
        ]
        
        for label_text, var in indicators:
            indicator_frame = tk.Frame(security_content, bg=self.colors['card_bg'])
            indicator_frame.pack(fill=tk.X, pady=8)
            
            tk.Label(indicator_frame, text=label_text, font=('Segoe UI', 10),
                    bg=self.colors['card_bg'], fg=self.colors['text_secondary']).pack(side=tk.LEFT)
            
            indicator = tk.Label(indicator_frame, textvariable=var, font=('Segoe UI', 10, 'bold'),
                               bg=self.colors['indicator_info'], fg='white',
                               padx=12, pady=4, relief='flat')
            indicator.pack(side=tk.RIGHT)
            
            if label_text == "Hash Records:":
                self._rec_indicator = indicator
            else:
                self._log_indicator = indicator

        # ===== RIGHT PANEL - Dashboard and Logs =====
        right_panel = tk.Frame(content_frame, bg=self.colors['bg'])
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(20, 0))

        # Dashboard Cards Row - IMPORTED FROM BACKUP
        dashboard_frame = tk.Frame(right_panel, bg=self.colors['bg'])
        dashboard_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=False, pady=(0, 20))
        dashboard_frame.pack_propagate(False)
        dashboard_frame.configure(height=320)

        # File Statistics Card - MODIFIED: Store counter labels
        stats_card = tk.Frame(dashboard_frame, bg=self.colors['card_bg'], width=300,
                            relief='flat', bd=1, highlightbackground=self.colors['card_border'],
                            highlightthickness=1)
        stats_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        stats_card.pack_propagate(False)
        
        tk.Label(stats_card, text="📈 File Statistics", font=('Segoe UI', 12, 'bold'),
                bg=self.colors['card_bg'], fg=self.colors['text_primary']).pack(anchor='w', padx=20, pady=(15, 15))
        
        stats_content = tk.Frame(stats_card, bg=self.colors['card_bg'])
        stats_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        stats_data = [
            ("Total Files:", self.total_files_var, self.colors['accent_primary']),
            ("Created:", self.created_var, self.colors['accent_success']),
            ("Modified:", self.modified_var, self.colors['accent_warning']),
            ("Deleted:", self.deleted_var, self.colors['accent_danger']),
        ]
        
        for label, var, color in stats_data:
            stat_frame = tk.Frame(stats_content, bg=self.colors['card_bg'])
            stat_frame.pack(fill=tk.X, pady=8)
            
            tk.Label(stat_frame, text=label, font=('Segoe UI', 10),
                    bg=self.colors['card_bg'], fg=self.colors['text_secondary']).pack(side=tk.LEFT)
            
            value_label = tk.Label(stat_frame, textvariable=var, font=('Segoe UI', 14, 'bold'),
                                bg=color, fg='white', padx=15, pady=6, relief='flat')
            value_label.pack(side=tk.RIGHT)
            
            # Store the label reference
            self.file_counter_labels.append((value_label, label, color))
        
        # Severity Dashboard Card - MODIFIED: Store severity counter labels
        severity_card = tk.Frame(dashboard_frame, bg=self.colors['card_bg'], width=300,
                                relief='flat', bd=1, highlightbackground=self.colors['card_border'],
                                highlightthickness=1)
        severity_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(20, 0))
        severity_card.pack_propagate(False)
        
        tk.Label(severity_card, text="🚨 Security Alerts", font=('Segoe UI', 12, 'bold'),
                bg=self.colors['card_bg'], fg=self.colors['text_primary']).pack(anchor='w', padx=20, pady=(15, 15))
        
        severity_content = tk.Frame(severity_card, bg=self.colors['card_bg'])
        severity_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        severity_data = [
            ("CRITICAL:", self.critical_var, SEVERITY_COLORS["CRITICAL"]),
            ("HIGH:", self.high_var, SEVERITY_COLORS["HIGH"]),
            ("MEDIUM:", self.medium_var, SEVERITY_COLORS["MEDIUM"]),
            ("INFO:", self.info_var, SEVERITY_COLORS["INFO"]),
        ]
        
        for label, var, color in severity_data:
            severity_frame = tk.Frame(severity_content, bg=self.colors['card_bg'])
            severity_frame.pack(fill=tk.X, pady=8)
            
            tk.Label(severity_frame, text=label, font=('Segoe UI', 10),
                    bg=self.colors['card_bg'], fg=self.colors['text_secondary']).pack(side=tk.LEFT)
            
            value_label = tk.Label(severity_frame, textvariable=var, font=('Segoe UI', 14, 'bold'),
                                bg=color, fg='white', padx=15, pady=6, relief='flat')
            value_label.pack(side=tk.RIGHT)
        
            # Store the label reference
            self.severity_counter_labels.append((value_label, label, color))

        # Report Tools Card - IMPORTED FROM BACKUP
        report_card = tk.Frame(dashboard_frame, bg=self.colors['card_bg'], width=300,
                              relief='flat', bd=1, highlightbackground=self.colors['card_border'],
                              highlightthickness=1)
        report_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(20, 0))
        report_card.pack_propagate(False)
        
        tk.Label(report_card, text="📊 Reports", font=('Segoe UI', 12, 'bold'),
                bg=self.colors['card_bg'], fg=self.colors['text_primary']).pack(anchor='w', padx=20, pady=(15, 15))
        
        report_content = tk.Frame(report_card, bg=self.colors['card_bg'])
        report_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        report_buttons = []
        if HAS_REPORTLAB:
            report_buttons.append(("📄 Export PDF", self.export_report_pdf))
            report_buttons.append(("📋 Logs PDF", self.export_logs_pdf))
        
        if HAS_MATPLOTLIB:
            report_buttons.append(("📈 Generate Chart", self.generate_chart))
        
        report_buttons.append(("📊 View Reports", self.view_report))
        # report_buttons.append(("📁 Open Folder", self.open_reports_folder))

        for text, command in report_buttons:
            btn = tk.Button(report_content, text=text, command=command,
                          font=('Segoe UI', 10), bg=self.colors['button_bg'], fg=self.colors['text_primary'],
                          bd=0, padx=15, pady=8, cursor="hand2", width=20,
                          activebackground=self.colors['button_hover'])
            btn.pack(pady=6)
            btn.bind("<Enter>", lambda e, b=btn: b.configure(bg=self.colors['button_hover']))
            btn.bind("<Leave>", lambda e, b=btn: b.configure(bg=self.colors['button_bg']))

        # Live Logs Card
        logs_card = tk.Frame(right_panel, bg=self.colors['card_bg'],
                            relief='flat', bd=1, highlightbackground=self.colors['card_border'],
                            highlightthickness=1)
        logs_card.pack(side=tk.BOTTOM, fill=tk.X)
        logs_card.configure(height=300)
        logs_card.pack_propagate(False)
        
        # Logs header with controls
        logs_header = tk.Frame(logs_card, bg=self.colors['card_bg'])
        logs_header.pack(fill=tk.X, padx=20, pady=(15, 0))
        
        tk.Label(logs_header, text="📝 Live Security Logs", font=('Segoe UI', 12, 'bold'),
                bg=self.colors['card_bg'], fg=self.colors['text_primary']).pack(side=tk.LEFT)
        
        # Clear button
        clear_btn = tk.Button(logs_header, text="Clear", command=self._clear_logs,
                            font=('Segoe UI', 9), bg=self.colors['button_bg'], fg=self.colors['text_primary'],
                            bd=0, padx=10, pady=2, cursor="hand2")
        clear_btn.pack(side=tk.RIGHT)
        clear_btn.bind("<Enter>", lambda e, b=clear_btn: b.configure(bg=self.colors['button_hover']))
        clear_btn.bind("<Leave>", lambda e, b=clear_btn: b.configure(bg=self.colors['button_bg']))

        # Log display
        logs_content = tk.Frame(logs_card, bg=self.colors['card_bg'])
        logs_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=15)
        
        self.log_box = scrolledtext.ScrolledText(logs_content, wrap=tk.WORD, height=15,
                                               font=("Consolas", 9),
                                               bg=self.colors['card_bg'], 
                                               fg=self.colors['text_primary'],
                                               insertbackground=self.colors['text_primary'],
                                               relief='flat')
        self.log_box.pack(fill=tk.BOTH, expand=True)
        self.log_box.configure(state="disabled")

        # Footer
        footer_frame = tk.Frame(main_container, bg=self.colors['bg'], height=40)
        footer_frame.pack(fill=tk.X, pady=(20, 0))
        footer_frame.pack_propagate(False)
        
        footer_text = "🔐 Secure File Integrity Monitor v2.0 • Professional Security Edition"
        footer_label = tk.Label(footer_frame, text=footer_text, font=('Segoe UI', 9),
                              bg=self.colors['bg'], fg=self.colors['text_muted'])
        footer_label.pack(pady=10)

    # ===== MISSING METHODS FROM BACKUP =====
    
    def _update_dashboard(self):
        """Update dashboard with current statistics - IMPORTED FROM BACKUP"""
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

    def _update_severity_counters(self):
        """Update severity counters from disk - IMPORTED FROM BACKUP"""
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
        """Update tamper indicator colors - IMPORTED FROM BACKUP"""
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
            except:
                pass

    def reset_session_counts(self):
        """Reset session counts - IMPORTED FROM BACKUP"""
        self.file_tracking['session_created'] = 0
        self.file_tracking['session_modified'] = 0
        self.file_tracking['session_deleted'] = 0
        
        self.created_var.set("0")
        self.modified_var.set("0")
        self.deleted_var.set("0")
        self._append_log("Session file counters reset")

    def _track_file_changes(self, data):
        """Track file changes - IMPORTED FROM BACKUP"""
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
        """Tail log file - IMPORTED FROM BACKUP"""
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
        """Add a folder to the list (with Premium Check)"""
        current_count = self.folder_listbox.size()
        
        # 1. FETCH USER TIER AND LIMITS
        user_tier = auth.get_user_tier(self.username)
        limit = subscription_manager.get_folder_limit(user_tier)

        # 2. ENFORCE PREMIUM GATING
        if current_count >= limit:
            if user_tier == "free":
                messagebox.showwarning(
                    "⭐ Premium Feature", 
                    f"The Free Plan is limited to {limit} folder.\n\n"
                    "Please upgrade to a PRO License to monitor up to 5 directories simultaneously!"
                )
            else:
                messagebox.showwarning("Limit Reached", f"PRO maximum of {limit} folders reached.")
            return

        # 3. ADD FOLDER
        folder = filedialog.askdirectory()
        if folder:
            existing = self.folder_listbox.get(0, tk.END)
            if folder in existing:
                messagebox.showinfo("Info", "This folder is already being monitored.")
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
        """Save the listbox items to memory so start_monitor can use them"""
        folders = list(self.folder_listbox.get(0, tk.END))
        from core.integrity_core import CONFIG
        CONFIG["watch_folders"] = folders

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
        """Open settings dialog - IMPORTED FROM BACKUP"""
        win = tk.Toplevel(self.root)
        win.title("Security Settings")
        win.geometry("520x300")
        win.configure(bg=self.colors['bg'])
        
        tk.Label(win, text="🔧 Security Configuration (config.json)", 
                bg=self.colors['bg'], fg=self.colors['text_primary'], font=('Segoe UI', 12, 'bold')).pack(anchor="w", padx=10, pady=(10, 0))

        cfg = dict(CONFIG)

        tk.Label(win, text="📁 Watch folder:", bg=self.colors['bg'], fg=self.colors['text_primary'], font=('Segoe UI', 10)).pack(anchor="w", padx=10, pady=(8, 0))
        watch_var = tk.StringVar(value=cfg.get("watch_folder", ""))
        e1 = ttk.Entry(win, textvariable=watch_var, width=70, style='Modern.TEntry')
        e1.pack(padx=10)

        tk.Label(win, text="⏱️ Verify interval (seconds):", bg=self.colors['bg'], fg=self.colors['text_primary'], font=('Segoe UI', 10)).pack(anchor="w", padx=10, pady=(8, 0))
        int_var = tk.StringVar(value=str(cfg.get("verify_interval", 1800)))
        e2 = ttk.Entry(win, textvariable=int_var, width=20, style='Modern.TEntry')
        e2.pack(padx=10)

        tk.Label(win, text="🔔 Webhook URL (optional):", bg=self.colors['bg'], fg=self.colors['text_primary'], font=('Segoe UI', 10)).pack(anchor="w", padx=10, pady=(8, 0))
        web_var = tk.StringVar(value=str(cfg.get("webhook_url") or ""))
        e3 = ttk.Entry(win, textvariable=web_var, width=70, style='Modern.TEntry')
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
                # Save to AppData/config/config.json
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
        
        self.created_var.set("0")
        self.modified_var.set("0")
        self.deleted_var.set("0")
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
        """Update the status label color based on current status"""
        if not hasattr(self, 'status_label'):
            return
        
        current_status = self.status_var.get()
        if "Running" in current_status or "🟢" in current_status:
            self.status_label.configure(fg=self.colors['accent_success'])
        elif "DEMO" in current_status or "SAFE" in current_status:
            self.status_label.configure(fg=self.colors['accent_danger'])
        elif "Read-Only" in current_status:
            self.status_label.configure(fg=self.colors['accent_warning'])
        else:  # Stopped or default
            self.status_label.configure(fg=self.colors['accent_primary'])

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
        self.side_menu.place(x=-self.menu_width, y=0, height=self.root.winfo_height(), relheight=1.0)
        
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
        """Open audit logs viewer"""
        self.toggle_menu()
        # Implementation for audit logs viewer
        self._append_log("Accessing security audit logs...")

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
            self.side_menu.place(x=target_x)
            if target_x == -self.menu_width:
                self.menu_visible = False
            return
        
        new_x = current_x + step
        self.side_menu.place(x=new_x)
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
            # FIX: Unpack 3 values (success, role, message)
            # We use '_' to ignore the role since we don't need it here
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
        """Admin override to disable safe mode"""
        if self.user_role != 'admin':
            messagebox.showerror("Access Denied", "Only Admins can disable Safe Mode.")
            return
            
        if messagebox.askyesno("Confirm Unlock", "Are you sure the system is secure?\nThis will re-enable monitoring controls."):
            success = safe_mode.disable_safe_mode("Admin Override via GUI")
            if success:
                messagebox.showinfo("Unlocked", "Safe Mode disabled. System returned to normal.")
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
def main():
    try:
        root = tk.Tk()
        app = ProIntegrityGUI(root, user_role='admin', username='Admin')
        root.mainloop()
    except Exception as e:
        print(f"Failed to start GUI: {e}")
        traceback.print_exc()
        input("Press Enter to close...")

if __name__ == "__main__":
    main()