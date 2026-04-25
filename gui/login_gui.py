#!/usr/bin/env python3
"""
login_gui.py
Entry point. Displays login screen using CustomTkinter for a professional,
industry‑standard look inspired by CrowdStrike and SentinelOne.

Features:
- Admin login with Username/Password
- Restricted Viewer login (one‑click, no password)
- Brute Force Protection (lockout after 3 failed attempts)
- Google SSO integration
- Email OTP verification for registration and password reset
"""

import sys
import os
import json
import time
import threading
import tkinter as tk
import customtkinter as ctk
import random
import re

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from core.auth_manager import auth
from gui.integrity_gui import ProIntegrityGUI
from core.email_service import email_service

# Set CustomTkinter appearance
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ══════════════════════════════════════════════════════════════════════════════
# DESIGN SYSTEM — CrowdStrike / SentinelOne Inspired
# ══════════════════════════════════════════════════════════════════════════════
class DesignSystem:
    """Centralized design tokens inspired by CrowdStrike Falcon & SentinelOne"""

    # ── Core Backgrounds ──────────────────────────────────────────────────
    BG_PRIMARY      = "#0d1117"    # Main app background (GitHub-dark level)
    BG_SURFACE      = "#161b22"    # Card / panel surface
    BG_SURFACE_2    = "#1c2333"    # Elevated surface (hover states, modals)
    BG_SURFACE_3    = "#21262d"    # Tertiary surface
    BG_INPUT        = "#0d1117"    # Input field background
    BG_OVERLAY      = "#010409"    # Modal overlays

    # ── Brand Accent (CrowdStrike-inspired blue) ─────────────────────────
    ACCENT_PRIMARY  = "#2f81f7"    # Primary blue
    ACCENT_HOVER    = "#58a6ff"    # Hover state
    ACCENT_MUTED    = "#1a4b8c"    # Muted accent for borders
    ACCENT_GLOW     = "#2f81f7"    # Glow effects

    # ── Status Colors ────────────────────────────────────────────────────
    SUCCESS         = "#3fb950"
    WARNING         = "#d29922"
    ERROR           = "#f85149"
    INFO            = "#58a6ff"

    # ── Text Colors ──────────────────────────────────────────────────────
    TEXT_PRIMARY    = "#e6edf3"     # Primary text
    TEXT_SECONDARY  = "#8b949e"     # Secondary / muted text
    TEXT_TERTIARY   = "#484f58"     # Disabled / hint text
    TEXT_LINK       = "#58a6ff"     # Clickable links
    TEXT_ON_ACCENT  = "#ffffff"     # Text on accent buttons

    # ── Borders ──────────────────────────────────────────────────────────
    BORDER          = "#30363d"
    BORDER_MUTED    = "#21262d"
    BORDER_FOCUS    = "#2f81f7"

    # ── Typography ───────────────────────────────────────────────────────
    FONT_FAMILY     = "Segoe UI"
    FONT_MONO       = "Cascadia Code"  # Fallback: Consolas
    FONT_HEADING_XL = ("Segoe UI", 26, "bold")
    FONT_HEADING_LG = ("Segoe UI", 20, "bold")
    FONT_HEADING_MD = ("Segoe UI", 16, "bold")
    FONT_HEADING_SM = ("Segoe UI", 13, "bold")
    FONT_BODY       = ("Segoe UI", 12)
    FONT_BODY_SM    = ("Segoe UI", 11)
    FONT_CAPTION    = ("Segoe UI", 10)
    FONT_TINY       = ("Segoe UI", 9)
    FONT_MONO_SM    = ("Consolas", 10)
    FONT_MONO_XS    = ("Consolas", 9)

    # ── Spacing ──────────────────────────────────────────────────────────
    RADIUS_LG       = 16
    RADIUS_MD       = 10
    RADIUS_SM       = 6
    BTN_HEIGHT      = 42
    BTN_HEIGHT_SM   = 36
    INPUT_HEIGHT    = 42


DS = DesignSystem  # Alias for convenience


def _clear_unreadable_data():
    """
    Remove data files that were encrypted with the old (lost) key.
    Called only when a brand-new encryption key was generated.
    """
    import os
    from core.utils import get_app_data_dir
    log_dir = os.path.join(get_app_data_dir(), "logs")
    files_to_clear = [
        os.path.join(log_dir, "users.dat"),
        os.path.join(log_dir, "integrity_log.dat"),
        os.path.join(log_dir, "hash_records.dat"),
        os.path.join(log_dir, "integrity_log.sig"),
        os.path.join(log_dir, "hash_records.sig"),
    ]
    for f in files_to_clear:
        try:
            if os.path.exists(f):
                os.remove(f)
                print(f"[STARTUP] Cleared unreadable file: {f}")
        except Exception as e:
            print(f"[STARTUP] Could not clear {f}: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# BruteForceGuard (unchanged logic)
# ══════════════════════════════════════════════════════════════════════════════
class BruteForceGuard:
    def __init__(self, max_attempts=3, lockout_time=30):
        self.max_attempts = max_attempts
        self.lockout_time = lockout_time
        self.attempts = 0
        self.lockout_timestamp = 0

        if getattr(sys, 'frozen', False):
            base_path = os.path.dirname(sys.executable)
        else:
            base_path = os.path.dirname(os.path.abspath(__file__))

        self.state_file = os.path.join(base_path, "login_security.json")
        self._load_state()

    def _load_state(self):
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    data = json.load(f)
                    self.attempts = data.get("attempts", 0)
                    self.lockout_timestamp = data.get("lockout_timestamp", 0)
            except:
                self.reset()

    def _save_state(self):
        try:
            with open(self.state_file, 'w') as f:
                json.dump({
                    "attempts": self.attempts,
                    "lockout_timestamp": self.lockout_timestamp
                }, f)
        except Exception as e:
            print(f"Error saving security state: {e}")

    def is_locked_out(self):
        if self.lockout_timestamp > 0:
            time_passed = time.time() - self.lockout_timestamp
            if time_passed < self.lockout_time:
                return True, int(self.lockout_time - time_passed)
            else:
                self.reset()
                return False, 0
        return False, 0

    def register_failed_attempt(self):
        self.attempts += 1
        if self.attempts >= self.max_attempts:
            self.lockout_timestamp = time.time()
        self._save_state()
        return self.attempts

    def reset(self):
        self.attempts = 0
        self.lockout_timestamp = 0
        if os.path.exists(self.state_file):
            try:
                os.remove(self.state_file)
            except:
                pass


# ══════════════════════════════════════════════════════════════════════════════
# CUSTOM DIALOGS — CrowdStrike / SentinelOne Style
# ══════════════════════════════════════════════════════════════════════════════
class CustomDialog:
    """Professional modal dialog with icon, message, and action button."""
    def __init__(self, parent, title, message, dialog_type="info"):
        self.dialog = ctk.CTkToplevel(parent)
        self.dialog.title("")
        self.dialog.geometry("420x230")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        self.dialog.focus_set()
        self.dialog.configure(fg_color=DS.BG_SURFACE)

        # Center on parent
        self.dialog.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - 210
        y = parent.winfo_y() + (parent.winfo_height() // 2) - 115
        self.dialog.geometry(f"+{x}+{y}")

        # Top accent bar
        type_config = {
            "info":    {"icon": "ℹ", "color": DS.ACCENT_PRIMARY, "bar": DS.ACCENT_PRIMARY},
            "error":   {"icon": "✕", "color": DS.ERROR,          "bar": DS.ERROR},
            "success": {"icon": "✓", "color": DS.SUCCESS,        "bar": DS.SUCCESS},
            "warning": {"icon": "!", "color": DS.WARNING,        "bar": DS.WARNING},
        }
        cfg = type_config.get(dialog_type, type_config["info"])

        # Accent strip at top
        accent_bar = ctk.CTkFrame(self.dialog, fg_color=cfg["bar"], height=3, corner_radius=0)
        accent_bar.pack(fill="x")

        # Content
        content = ctk.CTkFrame(self.dialog, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=28, pady=20)

        # Icon circle
        icon_frame = ctk.CTkFrame(content, fg_color=cfg["bar"], width=44, height=44,
                                   corner_radius=22)
        icon_frame.pack(pady=(0, 12))
        icon_frame.pack_propagate(False)
        ctk.CTkLabel(icon_frame, text=cfg["icon"], font=("Segoe UI", 18, "bold"),
                     text_color="#ffffff").place(relx=0.5, rely=0.5, anchor="center")

        # Message
        ctk.CTkLabel(content, text=message, font=DS.FONT_BODY_SM,
                     text_color=DS.TEXT_PRIMARY, wraplength=360,
                     justify="center").pack(pady=(0, 20))

        # Button
        ctk.CTkButton(content, text="OK", command=self.dialog.destroy,
                      fg_color=cfg["bar"], hover_color=cfg["color"],
                      text_color="#ffffff", font=DS.FONT_HEADING_SM,
                      corner_radius=DS.RADIUS_SM, width=120,
                      height=DS.BTN_HEIGHT_SM).pack()

        self.dialog.protocol("WM_DELETE_WINDOW", self.dialog.destroy)

    def wait(self):
        self.dialog.wait_window()


class SecurityAlertDialog:
    """Enterprise-grade security alert dialog with status indicator."""
    def __init__(self, parent, title, message):
        self.dialog = ctk.CTkToplevel(parent)
        self.dialog.title("")
        self.dialog.geometry("460x300")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        self.dialog.focus_set()
        self.dialog.configure(fg_color=DS.BG_SURFACE)

        # Center
        self.dialog.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - 230
        y = parent.winfo_y() + (parent.winfo_height() // 2) - 150
        self.dialog.geometry(f"+{x}+{y}")

        # Red accent strip
        ctk.CTkFrame(self.dialog, fg_color=DS.ERROR, height=3,
                      corner_radius=0).pack(fill="x")

        # Header bar
        header = ctk.CTkFrame(self.dialog, fg_color="#1a1215", height=44, corner_radius=0)
        header.pack(fill="x")
        header.pack_propagate(False)

        # Status indicator dot (animated)
        self._dot_frame = ctk.CTkFrame(header, fg_color="transparent")
        self._dot_frame.place(relx=0.03, rely=0.5, anchor="w")
        self._dot = ctk.CTkLabel(self._dot_frame, text="●", font=("Segoe UI", 10),
                                  text_color=DS.ERROR)
        self._dot.pack(side="left", padx=(0, 8))

        self.alert_label = ctk.CTkLabel(header, text="SECURITY ALERT",
                                        font=("Segoe UI", 11, "bold"),
                                        text_color=DS.ERROR)
        self.alert_label.place(relx=0.08, rely=0.5, anchor="w")

        timestamp = time.strftime("%H:%M:%S UTC", time.gmtime())
        ctk.CTkLabel(header, text=timestamp, font=DS.FONT_MONO_XS,
                     text_color=DS.TEXT_TERTIARY).place(relx=0.95, rely=0.5, anchor="e")

        # Content
        content = ctk.CTkFrame(self.dialog, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=24, pady=16)

        # Alert type
        ctk.CTkLabel(content, text=title, font=DS.FONT_HEADING_SM,
                     text_color=DS.TEXT_PRIMARY).pack(anchor="w", pady=(0, 8))

        # Separator
        ctk.CTkFrame(content, fg_color=DS.BORDER_MUTED, height=1).pack(fill="x", pady=(0, 8))

        # Message
        ctk.CTkLabel(content, text=message, font=DS.FONT_BODY_SM,
                     text_color=DS.TEXT_SECONDARY, justify="left",
                     wraplength=400, anchor="w").pack(fill="x", pady=(0, 12))

        # Log entry
        ctk.CTkLabel(content,
                     text=f"Event logged at {timestamp} — All attempts are monitored",
                     font=DS.FONT_MONO_XS, text_color=DS.TEXT_TERTIARY).pack(anchor="w")

        # Button
        ctk.CTkButton(content, text="Acknowledge", command=self.destroy_dialog,
                      fg_color="#2d1519", hover_color="#3d1f24",
                      text_color=DS.ERROR, border_color=DS.ERROR, border_width=1,
                      font=DS.FONT_HEADING_SM, corner_radius=DS.RADIUS_SM,
                      height=DS.BTN_HEIGHT_SM).pack(pady=(12, 0), fill="x")

        # Pulse animation for dot
        self.blink_after_id = None
        self._pulse()

        self.dialog.protocol("WM_DELETE_WINDOW", self.destroy_dialog)

    def _pulse(self):
        try:
            current = self._dot.cget("text_color")
            new = DS.TEXT_TERTIARY if current == DS.ERROR else DS.ERROR
            self._dot.configure(text_color=new)
            self.blink_after_id = self.dialog.after(600, self._pulse)
        except:
            pass

    def destroy_dialog(self):
        if self.blink_after_id:
            self.dialog.after_cancel(self.blink_after_id)
        self.dialog.destroy()

    def wait(self):
        self.dialog.wait_window()


# ══════════════════════════════════════════════════════════════════════════════
# REUSABLE UI COMPONENTS
# ══════════════════════════════════════════════════════════════════════════════
def create_styled_entry(parent, placeholder="", show="", **kwargs):
    """Creates a CrowdStrike-style input field."""
    return ctk.CTkEntry(
        parent,
        placeholder_text=placeholder,
        show=show,
        font=DS.FONT_BODY,
        fg_color=DS.BG_INPUT,
        border_color=DS.BORDER,
        text_color=DS.TEXT_PRIMARY,
        placeholder_text_color=DS.TEXT_TERTIARY,
        corner_radius=DS.RADIUS_SM,
        height=DS.INPUT_HEIGHT,
        **kwargs
    )


def create_primary_button(parent, text, command, **kwargs):
    """Creates a CrowdStrike-blue primary action button."""
    return ctk.CTkButton(
        parent, text=text, command=command,
        font=DS.FONT_HEADING_SM,
        fg_color=DS.ACCENT_PRIMARY,
        hover_color=DS.ACCENT_HOVER,
        text_color=DS.TEXT_ON_ACCENT,
        corner_radius=DS.RADIUS_SM,
        height=DS.BTN_HEIGHT,
        **kwargs
    )


def create_secondary_button(parent, text, command, **kwargs):
    """Creates a secondary / ghost button."""
    return ctk.CTkButton(
        parent, text=text, command=command,
        font=DS.FONT_BODY_SM,
        fg_color="transparent",
        hover_color=DS.BG_SURFACE_3,
        text_color=DS.TEXT_SECONDARY,
        border_color=DS.BORDER,
        border_width=1,
        corner_radius=DS.RADIUS_SM,
        height=DS.BTN_HEIGHT,
        **kwargs
    )


def create_link_button(parent, text, command, color=None):
    """Creates a text-only link button."""
    return ctk.CTkButton(
        parent, text=text, command=command,
        font=DS.FONT_CAPTION,
        fg_color="transparent",
        text_color=color or DS.TEXT_LINK,
        hover=False, width=0
    )


def create_field_label(parent, text):
    """Creates a form field label."""
    return ctk.CTkLabel(parent, text=text, font=DS.FONT_CAPTION,
                        text_color=DS.TEXT_SECONDARY)


def create_divider_with_text(parent, text="or"):
    """Creates a horizontal divider with centered text — SentinelOne style."""
    frame = ctk.CTkFrame(parent, fg_color="transparent", height=20)
    frame.pack(fill="x", pady=16)

    # Left line
    left_line = ctk.CTkFrame(frame, fg_color=DS.BORDER, height=1)
    left_line.place(relx=0, rely=0.5, relwidth=0.42, anchor="w")

    # Center text
    ctk.CTkLabel(frame, text=text.upper(), font=DS.FONT_TINY,
                 text_color=DS.TEXT_TERTIARY,
                 fg_color=DS.BG_SURFACE).place(relx=0.5, rely=0.5, anchor="center")

    # Right line
    right_line = ctk.CTkFrame(frame, fg_color=DS.BORDER, height=1)
    right_line.place(relx=1.0, rely=0.5, relwidth=0.42, anchor="e")

    return frame


# ══════════════════════════════════════════════════════════════════════════════
# MAIN LOGIN WINDOW
# ══════════════════════════════════════════════════════════════════════════════
class LoginWindow:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("FMSecure — Endpoint Detection & Response")

        # ── KEY RESILIENCE ────────────────────────────────────────────────
        from core.encryption_manager import crypto_manager
        if not crypto_manager._local_ok and auth.has_users():
            import tkinter.messagebox as mb
            mb.showwarning(
                "Encryption Key Lost",
                "Your local encryption key could not be loaded.\n\n"
                "If you have a Google Drive backup, you can restore it from the "
                "next screen.\n\nOtherwise a new key will be generated and you "
                "will need to create a new admin account."
            )
            _clear_unreadable_data()
            auth._load_users()

        # --- Taskbar icon ---
        try:
            if getattr(sys, 'frozen', False):
                icon_path = os.path.join(sys._MEIPASS, "assets", "icons", "app_icon.ico")
            else:
                project_root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                icon_path = os.path.join(project_root_dir, "assets", "icons", "app_icon.ico")
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except Exception:
            pass

        # --- START HIDDEN FOR SPLASH ---
        self.root.withdraw()

        # ── Window Configuration ─────────────────────────────────────────
        self.root.geometry("500x720")
        self.root.configure(fg_color=DS.BG_PRIMARY)
        self.root.resizable(False, False)

        # Initialize Security Guard
        self.guard = BruteForceGuard(max_attempts=3, lockout_time=30)

        # --- Recovery bypass ---
        if "--recovery" in sys.argv:
            recovered_user = "admin"
            for user, data in auth.users.items():
                if data.get("role") == "admin":
                    recovered_user = user
                    break
            self.root.after(100, lambda: self._launch_main_app('admin', recovered_user))
            return

        self._center_window()

        if not auth.has_users():
            self._show_splash_screen(on_complete=self._check_tenant_then_reinstall)
        else:
            self._build_login_ui()
            self._show_splash_screen()

        self._apply_icon()

    # ══════════════════════════════════════════════════════════════════════
    # SPLASH SCREEN — Professional Loading Animation
    # ══════════════════════════════════════════════════════════════════════
    def _show_splash_screen(self, on_complete=None):
        """Professional dark splash screen with animated progress."""
        splash = tk.Toplevel(self.root)
        splash.overrideredirect(True)
        splash.configure(bg=DS.BG_OVERLAY)

        width, height = 520, 300
        x = (splash.winfo_screenwidth() // 2) - (width // 2)
        y = (splash.winfo_screenheight() // 2) - (height // 2)
        splash.geometry(f"{width}x{height}+{x}+{y}")

        canvas = tk.Canvas(splash, width=width, height=height,
                           bg=DS.BG_OVERLAY, highlightthickness=0)
        canvas.pack(fill=tk.BOTH, expand=True)

        # Top accent line
        canvas.create_line(0, 0, width, 0, fill=DS.ACCENT_PRIMARY, width=2)

        # Logo
        from PIL import Image, ImageTk
        try:
            if getattr(sys, 'frozen', False):
                base_path = sys._MEIPASS
            else:
                base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            logo_path = os.path.join(base_path, "assets", "icons", "app_icon.png")
            img = Image.open(logo_path).resize((80, 80))
            self.logo_img = ImageTk.PhotoImage(img)
            canvas.logo_img = self.logo_img
            canvas.create_image(width // 2, 80, image=self.logo_img)
        except Exception as e:
            print("Logo load error:", e)

        # Brand text
        canvas.create_text(width // 2, 140, text="FMSecure",
                           font=("Segoe UI", 22, "bold"), fill=DS.TEXT_PRIMARY)
        canvas.create_text(width // 2, 165, text="Endpoint Detection & Response Platform",
                           font=("Segoe UI", 10), fill=DS.TEXT_SECONDARY)

        # Status label
        load_label = tk.Label(splash, text="Initializing...",
                              font=("Segoe UI", 9), bg=DS.BG_OVERLAY,
                              fg=DS.TEXT_SECONDARY)
        load_label.place(relx=0.5, rely=0.78, anchor="center")

        # Progress bar
        bar_y = height - 40
        bar_x_start, bar_x_end = 80, width - 80
        canvas.create_rectangle(bar_x_start, bar_y, bar_x_end, bar_y + 3,
                                fill=DS.BG_SURFACE_3, outline="")
        progress_bar = canvas.create_rectangle(bar_x_start, bar_y, bar_x_start, bar_y + 3,
                                               fill=DS.ACCENT_PRIMARY, outline="")

        # Bottom accent
        canvas.create_line(0, height - 2, width, height - 2,
                           fill=DS.ACCENT_PRIMARY, width=2)

        loading_steps = [
            ("Loading detection engine...",              random.randint(400, 800)),
            ("Initializing telemetry services...",       random.randint(200, 500)),
            ("Verifying encryption subsystem...",        random.randint(500, 900)),
            ("Loading UI components...",                 random.randint(200, 500)),
            ("Establishing secure session...",           random.randint(200, 400)),
        ]
        total_steps = len(loading_steps)
        current_step_idx = [0]

        def process_next_step():
            if current_step_idx[0] < total_steps:
                text, duration = loading_steps[current_step_idx[0]]
                load_label.config(text=text)
                start_w = bar_x_start + ((bar_x_end - bar_x_start) * (current_step_idx[0] / total_steps))
                end_w = bar_x_start + ((bar_x_end - bar_x_start) * ((current_step_idx[0] + 1) / total_steps))
                frames = 15
                frame_delay = duration // frames

                def animate_chunk(frame=0):
                    if frame <= frames:
                        cw = start_w + ((end_w - start_w) * (frame / frames))
                        canvas.coords(progress_bar, bar_x_start, bar_y, cw, bar_y + 3)
                        splash.after(frame_delay, lambda: animate_chunk(frame + 1))
                    else:
                        current_step_idx[0] += 1
                        process_next_step()

                animate_chunk()
            else:
                splash.destroy()
                self.root.deiconify()
                if on_complete:
                    on_complete()

        process_next_step()

    # ══════════════════════════════════════════════════════════════════════
    # UTILITY METHODS
    # ══════════════════════════════════════════════════════════════════════
    def _center_window(self):
        self.root.update_idletasks()
        w = self.root.winfo_width()
        h = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (w // 2)
        y = (self.root.winfo_screenheight() // 2) - (h // 2)
        self.root.geometry(f'{w}x{h}+{x}+{y}')

    def _apply_icon(self, window=None):
        try:
            if getattr(sys, 'frozen', False):
                base = sys._MEIPASS
            else:
                base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            icon_path = os.path.join(base, "assets", "icons", "app_icon.ico")
            if os.path.exists(icon_path):
                (window or self.root).iconbitmap(icon_path)
        except Exception:
            pass

    def show_info(self, message):
        CustomDialog(self.root, "Info", message, "info").wait()

    def show_error(self, message):
        CustomDialog(self.root, "Error", message, "error").wait()

    def show_success(self, message):
        CustomDialog(self.root, "Success", message, "success").wait()

    def show_warning(self, message):
        CustomDialog(self.root, "Warning", message, "warning").wait()

    def show_security_alert(self, title, message):
        try:
            SecurityAlertDialog(self.root, title, message).wait()
        except Exception as e:
            print(f"[Dialog Error]: {e}")

    # ══════════════════════════════════════════════════════════════════════
    # LOGIN UI — CrowdStrike / SentinelOne Inspired
    # ══════════════════════════════════════════════════════════════════════
    def _build_login_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        # ── Outer container ──────────────────────────────────────────────
        outer = ctk.CTkFrame(self.root, fg_color=DS.BG_PRIMARY)
        outer.pack(fill="both", expand=True)

        # ── Centered content wrapper ─────────────────────────────────────
        wrapper = ctk.CTkFrame(outer, fg_color="transparent", width=380)
        wrapper.place(relx=0.5, rely=0.5, anchor="center")

        # ── Logo / Brand ─────────────────────────────────────────────────
        brand_frame = ctk.CTkFrame(wrapper, fg_color="transparent")
        brand_frame.pack(pady=(0, 8))

        # Try to load logo
        try:
            from PIL import Image
            if getattr(sys, 'frozen', False):
                base_path = sys._MEIPASS
            else:
                base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            logo_path = os.path.join(base_path, "assets", "icons", "app_icon.png")
            img = Image.open(logo_path)
            self._login_logo = ctk.CTkImage(light_image=img, dark_image=img, size=(48, 48))
            ctk.CTkLabel(brand_frame, image=self._login_logo, text="").pack(pady=(0, 8))
        except Exception:
            # Fallback shield icon
            ctk.CTkLabel(brand_frame, text="🛡", font=("Segoe UI", 36),
                         text_color=DS.ACCENT_PRIMARY).pack(pady=(0, 8))

        ctk.CTkLabel(brand_frame, text="FMSecure",
                     font=("Segoe UI", 28, "bold"),
                     text_color=DS.TEXT_PRIMARY).pack()
        ctk.CTkLabel(brand_frame, text="Endpoint Detection & Response",
                     font=DS.FONT_CAPTION,
                     text_color=DS.TEXT_TERTIARY).pack(pady=(2, 0))

        # ── Sign In Card ─────────────────────────────────────────────────
        card = ctk.CTkFrame(wrapper, fg_color=DS.BG_SURFACE,
                            corner_radius=DS.RADIUS_LG,
                            border_color=DS.BORDER_MUTED, border_width=1)
        card.pack(fill="x", pady=(24, 0), padx=10)

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=32, pady=28)

        # Heading
        ctk.CTkLabel(inner, text="Sign in",
                     font=DS.FONT_HEADING_LG,
                     text_color=DS.TEXT_PRIMARY).pack(anchor="w", pady=(0, 4))
        ctk.CTkLabel(inner, text="Access your security console",
                     font=DS.FONT_BODY_SM,
                     text_color=DS.TEXT_SECONDARY).pack(anchor="w", pady=(0, 20))

        # Username field
        create_field_label(inner, "Username").pack(anchor="w", pady=(0, 4))
        self.user_entry = create_styled_entry(inner, placeholder="Enter your username")
        self.user_entry.pack(fill="x", pady=(0, 14))
        self.user_entry.focus()

        # Password field
        create_field_label(inner, "Password").pack(anchor="w", pady=(0, 4))
        self.pass_entry = create_styled_entry(inner, placeholder="Enter your password", show="•")
        self.pass_entry.pack(fill="x", pady=(0, 6))

        # Forgot links row
        links_row = ctk.CTkFrame(inner, fg_color="transparent")
        links_row.pack(fill="x", pady=(0, 18))

        create_link_button(links_row, "Forgot password?",
                          self._build_forgot_pass_ui).pack(side="left")
        ctk.CTkLabel(links_row, text="·", font=DS.FONT_CAPTION,
                     text_color=DS.TEXT_TERTIARY).pack(side="left", padx=6)
        create_link_button(links_row, "Forgot username?",
                          self._build_forgot_username_ui).pack(side="left")

        # Sign In button
        self.login_btn = create_primary_button(inner, "Sign In",
                                                self._attempt_admin_login)
        self.login_btn.pack(fill="x", pady=(0, 0))

        # Divider
        create_divider_with_text(inner, "or")

        # Google SSO
        google_btn = ctk.CTkButton(
            inner, text="   Continue with Google",
            command=self._handle_google_login,
            font=DS.FONT_BODY_SM,
            fg_color="transparent",
            hover_color=DS.BG_SURFACE_3,
            text_color=DS.TEXT_PRIMARY,
            border_color=DS.BORDER,
            border_width=1,
            corner_radius=DS.RADIUS_SM,
            height=DS.BTN_HEIGHT,
            image=self._load_google_icon()
        )
        google_btn.pack(fill="x")

        # ── Restricted Viewer Section ────────────────────────────────────
        viewer_frame = ctk.CTkFrame(wrapper, fg_color="transparent")
        viewer_frame.pack(fill="x", pady=(16, 0), padx=10)

        viewer_card = ctk.CTkFrame(viewer_frame, fg_color=DS.BG_SURFACE,
                                    corner_radius=DS.RADIUS_MD,
                                    border_color=DS.BORDER_MUTED, border_width=1)
        viewer_card.pack(fill="x")

        viewer_inner = ctk.CTkFrame(viewer_card, fg_color="transparent")
        viewer_inner.pack(fill="x", padx=24, pady=16)

        viewer_text = ctk.CTkFrame(viewer_inner, fg_color="transparent")
        viewer_text.pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(viewer_text, text="Restricted Viewer",
                     font=DS.FONT_HEADING_SM,
                     text_color=DS.TEXT_SECONDARY).pack(anchor="w")
        ctk.CTkLabel(viewer_text, text="Read-only access · No credentials required",
                     font=DS.FONT_TINY,
                     text_color=DS.TEXT_TERTIARY).pack(anchor="w")

        self.guest_btn = ctk.CTkButton(
            viewer_inner, text="Enter →",
            command=self._attempt_guest_login,
            font=DS.FONT_CAPTION,
            fg_color=DS.BG_SURFACE_3,
            hover_color=DS.BORDER,
            text_color=DS.TEXT_SECONDARY,
            corner_radius=DS.RADIUS_SM,
            width=80, height=32
        )
        self.guest_btn.pack(side="right")

        # ── Status Bar ───────────────────────────────────────────────────
        status_bar = ctk.CTkFrame(self.root, fg_color=DS.BG_OVERLAY, height=28,
                                   corner_radius=0)
        status_bar.pack(fill="x", side="bottom")

        # Status dot
        status_inner = ctk.CTkFrame(status_bar, fg_color="transparent")
        status_inner.pack(side="left", padx=12)
        ctk.CTkLabel(status_inner, text="●", font=("Segoe UI", 8),
                     text_color=DS.SUCCESS).pack(side="left", padx=(0, 6))
        ctk.CTkLabel(status_inner, text="System Online · Encrypted Connection",
                     font=DS.FONT_MONO_XS,
                     text_color=DS.TEXT_TERTIARY).pack(side="left")

        ctk.CTkLabel(status_bar, text="v2.0.0", font=DS.FONT_MONO_XS,
                     text_color=DS.TEXT_TERTIARY).pack(side="right", padx=12)

        # Bind Enter key
        self.root.bind('<Return>', lambda e: self._attempt_admin_login())

    def _load_google_icon(self):
        """Try to load a Google icon, return None if not available."""
        try:
            from PIL import Image
            if getattr(sys, 'frozen', False):
                base = sys._MEIPASS
            else:
                base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            gpath = os.path.join(base, "assets", "icons", "google_icon.png")
            if os.path.exists(gpath):
                img = Image.open(gpath)
                self._google_icon = ctk.CTkImage(light_image=img, dark_image=img, size=(18, 18))
                return self._google_icon
        except Exception:
            pass
        return None

    # ══════════════════════════════════════════════════════════════════════
    # REGISTRATION UI — First Time Setup
    # ══════════════════════════════════════════════════════════════════════
    def _build_register_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        outer = ctk.CTkFrame(self.root, fg_color=DS.BG_PRIMARY)
        outer.pack(fill="both", expand=True)

        scroll = ctk.CTkScrollableFrame(outer, fg_color=DS.BG_PRIMARY)
        scroll.pack(fill="both", expand=True, padx=40, pady=30)

        # Logo
        try:
            from PIL import Image
            if getattr(sys, 'frozen', False):
                base_path = sys._MEIPASS
            else:
                base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            logo_path = os.path.join(base_path, "assets", "icons", "app_icon.png")
            img = Image.open(logo_path)
            self.register_logo = ctk.CTkImage(light_image=img, dark_image=img, size=(64, 64))
            ctk.CTkLabel(scroll, image=self.register_logo, text="").pack(pady=(10, 8))
        except Exception:
            ctk.CTkLabel(scroll, text="🛡", font=("Segoe UI", 40),
                         text_color=DS.ACCENT_PRIMARY).pack(pady=(10, 8))

        ctk.CTkLabel(scroll, text="Create Your Account",
                     font=DS.FONT_HEADING_LG,
                     text_color=DS.TEXT_PRIMARY).pack()
        ctk.CTkLabel(scroll, text="Set up your administrator credentials to get started",
                     font=DS.FONT_BODY_SM,
                     text_color=DS.TEXT_SECONDARY).pack(pady=(4, 24))

        # Card
        card = ctk.CTkFrame(scroll, fg_color=DS.BG_SURFACE,
                            corner_radius=DS.RADIUS_LG,
                            border_color=DS.BORDER_MUTED, border_width=1)
        card.pack(fill="x")

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=28, pady=24)

        # Fields
        create_field_label(inner, "Username").pack(anchor="w", pady=(0, 4))
        self.reg_user_entry = create_styled_entry(inner, placeholder="admin")
        self.reg_user_entry.insert(0, "admin")
        self.reg_user_entry.pack(fill="x", pady=(0, 12))

        create_field_label(inner, "Email Address").pack(anchor="w", pady=(0, 4))
        self.reg_email_entry = create_styled_entry(inner, placeholder="you@company.com")
        self.reg_email_entry.pack(fill="x", pady=(0, 12))

        create_field_label(inner, "Password").pack(anchor="w", pady=(0, 4))
        self.reg_pass_entry = create_styled_entry(inner, placeholder="Minimum 6 characters", show="•")
        self.reg_pass_entry.pack(fill="x", pady=(0, 12))

        create_field_label(inner, "Confirm Password").pack(anchor="w", pady=(0, 4))
        self.reg_confirm_entry = create_styled_entry(inner, placeholder="Re-enter password", show="•")
        self.reg_confirm_entry.pack(fill="x", pady=(0, 20))

        # Buttons
        self.reg_btn = create_primary_button(inner, "Create Account",
                                              self._attempt_register)
        self.reg_btn.pack(fill="x", pady=(0, 0))

        create_divider_with_text(inner, "or")

        self.google_btn = ctk.CTkButton(
            inner, text="   Sign up with Google",
            command=lambda: self._handle_google_login(mode="register"),
            font=DS.FONT_BODY_SM,
            fg_color="transparent",
            hover_color=DS.BG_SURFACE_3,
            text_color=DS.TEXT_PRIMARY,
            border_color=DS.BORDER,
            border_width=1,
            corner_radius=DS.RADIUS_SM,
            height=DS.BTN_HEIGHT,
            image=self._load_google_icon()
        )
        self.google_btn.pack(fill="x")

    def _create_input(self, parent, label_text, is_password=False, default=""):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.pack(fill="x", pady=5)
        create_field_label(frame, label_text).pack(anchor="w", pady=(0, 4))
        entry = create_styled_entry(frame, show="•" if is_password else "")
        if default:
            entry.insert(0, default)
        entry.pack(fill="x")
        return entry

    # ══════════════════════════════════════════════════════════════════════
    # OTP VERIFICATION UI
    # ══════════════════════════════════════════════════════════════════════
    def _build_otp_ui(self, username, email, password):
        self.is_processing = False
        for widget in self.root.winfo_children():
            widget.destroy()

        outer = ctk.CTkFrame(self.root, fg_color=DS.BG_PRIMARY)
        outer.pack(fill="both", expand=True)

        wrapper = ctk.CTkFrame(outer, fg_color="transparent", width=380)
        wrapper.place(relx=0.5, rely=0.5, anchor="center")

        # Icon
        ctk.CTkLabel(wrapper, text="✉", font=("Segoe UI", 48),
                     text_color=DS.ACCENT_PRIMARY).pack(pady=(0, 12))

        ctk.CTkLabel(wrapper, text="Verify Your Email",
                     font=DS.FONT_HEADING_LG,
                     text_color=DS.TEXT_PRIMARY).pack()
        ctk.CTkLabel(wrapper, text=f"Enter the 6-digit code sent to\n{email}",
                     font=DS.FONT_BODY_SM, text_color=DS.TEXT_SECONDARY,
                     justify="center").pack(pady=(4, 24))

        # OTP Card
        card = ctk.CTkFrame(wrapper, fg_color=DS.BG_SURFACE,
                            corner_radius=DS.RADIUS_LG,
                            border_color=DS.BORDER_MUTED, border_width=1)
        card.pack(fill="x", padx=10)

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=28, pady=24)

        create_field_label(inner, "Verification Code").pack(anchor="w", pady=(0, 4))
        self.otp_entry = ctk.CTkEntry(inner, font=("Segoe UI", 22, "bold"),
                                       justify="center", fg_color=DS.BG_INPUT,
                                       border_color=DS.BORDER,
                                       text_color=DS.TEXT_PRIMARY,
                                       placeholder_text="000000",
                                       corner_radius=DS.RADIUS_SM,
                                       height=52)
        self.otp_entry.pack(fill="x", pady=(0, 20))

        def verify_and_create():
            otp = self.otp_entry.get().strip()
            if not otp:
                self.show_error("Please enter the verification code.")
                return
            is_valid, msg = email_service.verify_otp(email, otp)
            if is_valid:
                success, auth_msg = auth.register_user(username, email, password, role="admin")
                if success:
                    self.show_success("Account created successfully!\nYou can now sign in.")
                    self._build_login_ui()
                else:
                    self.show_error(auth_msg)
            else:
                self.show_error(msg)

        create_primary_button(inner, "Verify & Create Account",
                              verify_and_create).pack(fill="x")

        create_link_button(wrapper, "← Back to registration",
                          self._build_register_ui).pack(pady=(16, 0))

    # ══════════════════════════════════════════════════════════════════════
    # FORGOT USERNAME UI
    # ══════════════════════════════════════════════════════════════════════
    def _build_forgot_username_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        outer = ctk.CTkFrame(self.root, fg_color=DS.BG_PRIMARY)
        outer.pack(fill="both", expand=True)

        wrapper = ctk.CTkFrame(outer, fg_color="transparent", width=380)
        wrapper.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(wrapper, text="👤", font=("Segoe UI", 42),
                     text_color=DS.ACCENT_PRIMARY).pack(pady=(0, 12))
        ctk.CTkLabel(wrapper, text="Recover Username",
                     font=DS.FONT_HEADING_LG,
                     text_color=DS.TEXT_PRIMARY).pack()
        ctk.CTkLabel(wrapper,
                     text="Enter your registered email address to\nlook up your username.",
                     font=DS.FONT_BODY_SM, text_color=DS.TEXT_SECONDARY,
                     justify="center").pack(pady=(4, 24))

        card = ctk.CTkFrame(wrapper, fg_color=DS.BG_SURFACE,
                            corner_radius=DS.RADIUS_LG,
                            border_color=DS.BORDER_MUTED, border_width=1)
        card.pack(fill="x", padx=10)

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=28, pady=24)

        create_field_label(inner, "Registered Email").pack(anchor="w", pady=(0, 4))
        self._fu_email_entry = create_styled_entry(inner, placeholder="you@company.com")
        self._fu_email_entry.pack(fill="x", pady=(0, 6))
        self._fu_email_entry.focus()

        self._fu_status = ctk.CTkLabel(inner, text="", font=DS.FONT_CAPTION,
                                        text_color=DS.ERROR, wraplength=320)
        self._fu_status.pack(pady=(0, 12))

        def _lookup():
            email = self._fu_email_entry.get().strip().lower()
            if not email or "@" not in email:
                self._fu_status.configure(text="Please enter a valid email address.",
                                          text_color=DS.ERROR)
                return

            found_username = None
            for username, data in auth.users.items():
                if data.get("registered_email", "").lower() == email:
                    found_username = username
                    break

            if not found_username:
                self._fu_status.configure(
                    text="No account found with that email.\nDouble-check or contact support.",
                    text_color=DS.ERROR)
                return

            lookup_btn.configure(state="disabled", text="Sending code…")
            self._fu_status.configure(text="", text_color=DS.TEXT_SECONDARY)

            def _send_otp():
                success, msg = email_service.send_otp_email(email, "verification")

                def _after():
                    lookup_btn.configure(state="normal", text="Look Up Username")
                    if success:
                        self._build_username_otp_ui(found_username, email)
                    else:
                        self._fu_status.configure(
                            text=f"Could not send verification code:\n{msg}",
                            text_color=DS.ERROR)

                self.root.after(0, _after)

            threading.Thread(target=_send_otp, daemon=True).start()

        lookup_btn = create_primary_button(inner, "Look Up Username", _lookup)
        lookup_btn.pack(fill="x")

        create_link_button(wrapper, "← Back to sign in",
                          self._build_login_ui).pack(pady=(16, 0))

        self.root.bind('<Return>', lambda e: _lookup())

    def _build_username_otp_ui(self, username, email):
        for widget in self.root.winfo_children():
            widget.destroy()

        outer = ctk.CTkFrame(self.root, fg_color=DS.BG_PRIMARY)
        outer.pack(fill="both", expand=True)

        wrapper = ctk.CTkFrame(outer, fg_color="transparent", width=380)
        wrapper.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(wrapper, text="✉", font=("Segoe UI", 42),
                     text_color=DS.ACCENT_PRIMARY).pack(pady=(0, 12))
        ctk.CTkLabel(wrapper, text="Verify Identity",
                     font=DS.FONT_HEADING_LG,
                     text_color=DS.TEXT_PRIMARY).pack()
        ctk.CTkLabel(wrapper, text=f"Enter the 6-digit code sent to:\n{email}",
                     font=DS.FONT_BODY_SM, text_color=DS.TEXT_SECONDARY,
                     justify="center").pack(pady=(4, 24))

        card = ctk.CTkFrame(wrapper, fg_color=DS.BG_SURFACE,
                            corner_radius=DS.RADIUS_LG,
                            border_color=DS.BORDER_MUTED, border_width=1)
        card.pack(fill="x", padx=10)

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=28, pady=24)

        self._fu_otp_entry = ctk.CTkEntry(inner, font=("Segoe UI", 22, "bold"),
                                           justify="center", fg_color=DS.BG_INPUT,
                                           border_color=DS.BORDER,
                                           text_color=DS.TEXT_PRIMARY,
                                           placeholder_text="000000",
                                           corner_radius=DS.RADIUS_SM, height=52)
        self._fu_otp_entry.pack(fill="x", pady=(0, 6))
        self._fu_otp_entry.focus()

        self._fu_otp_status = ctk.CTkLabel(inner, text="", font=DS.FONT_CAPTION,
                                            text_color=DS.ERROR)
        self._fu_otp_status.pack(pady=(0, 14))

        def _verify():
            otp = self._fu_otp_entry.get().strip()
            if not otp:
                self._fu_otp_status.configure(text="Please enter the code.")
                return
            is_valid, msg = email_service.verify_otp(email, otp)
            if is_valid:
                self._build_username_revealed_ui(username, email)
            else:
                self._fu_otp_status.configure(text=msg, text_color=DS.ERROR)
                self._fu_otp_entry.delete(0, "end")

        create_primary_button(inner, "Verify & Show Username", _verify).pack(fill="x")

        create_link_button(wrapper, "← Back",
                          self._build_forgot_username_ui).pack(pady=(16, 0))
        self.root.bind('<Return>', lambda e: _verify())

    def _build_username_revealed_ui(self, username, email):
        for widget in self.root.winfo_children():
            widget.destroy()

        outer = ctk.CTkFrame(self.root, fg_color=DS.BG_PRIMARY)
        outer.pack(fill="both", expand=True)

        wrapper = ctk.CTkFrame(outer, fg_color="transparent", width=380)
        wrapper.place(relx=0.5, rely=0.5, anchor="center")

        # Success icon
        icon_circle = ctk.CTkFrame(wrapper, fg_color=DS.SUCCESS, width=56, height=56,
                                    corner_radius=28)
        icon_circle.pack(pady=(0, 16))
        icon_circle.pack_propagate(False)
        ctk.CTkLabel(icon_circle, text="✓", font=("Segoe UI", 24, "bold"),
                     text_color="#ffffff").place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(wrapper, text="Username Found",
                     font=DS.FONT_HEADING_LG,
                     text_color=DS.TEXT_PRIMARY).pack()
        ctk.CTkLabel(wrapper, text=f"The account registered to {email}",
                     font=DS.FONT_BODY_SM, text_color=DS.TEXT_SECONDARY,
                     justify="center").pack(pady=(4, 20))

        # Username display
        name_card = ctk.CTkFrame(wrapper, fg_color=DS.BG_SURFACE,
                                  corner_radius=DS.RADIUS_MD,
                                  border_color=DS.ACCENT_MUTED, border_width=1)
        name_card.pack(padx=10)
        ctk.CTkLabel(name_card, text=username,
                     font=("Segoe UI", 24, "bold"),
                     text_color=DS.ACCENT_PRIMARY).pack(padx=40, pady=20)

        def _copy():
            self.root.clipboard_clear()
            self.root.clipboard_append(username)
            copy_btn.configure(text="✓ Copied!")
            self.root.after(2000, lambda: copy_btn.configure(text="Copy Username"))

        copy_btn = create_secondary_button(wrapper, "Copy Username", _copy)
        copy_btn.pack(fill="x", padx=50, pady=(16, 8))

        create_primary_button(wrapper, "Go to Sign In →",
                              self._build_login_ui).pack(fill="x", padx=50, pady=(0, 8))

        create_link_button(wrapper, "Forgot password too?",
                          self._build_forgot_pass_ui).pack(pady=(4, 0))

    # ══════════════════════════════════════════════════════════════════════
    # LOGIN ATTEMPTS (same logic, updated dialog text)
    # ══════════════════════════════════════════════════════════════════════
    def _attempt_admin_login(self):
        is_locked, wait_time = self.guard.is_locked_out()
        if is_locked:
            self.show_security_alert(
                "ACCOUNT LOCKED",
                f"Too many failed login attempts.\n\n"
                f"Your account has been temporarily locked.\n"
                f"Please wait {wait_time} seconds before retrying."
            )
            return

        username = self.user_entry.get().strip()
        password = self.pass_entry.get().strip()

        if not username or not password:
            self.show_security_alert(
                "MISSING CREDENTIALS",
                "Username and password are required.\nPlease provide valid credentials."
            )
            return

        success, role, msg = auth.login(username, password)

        if success:
            if role != 'admin':
                self.show_security_alert(
                    "UNAUTHORIZED ACCESS",
                    "This console requires administrator privileges.\n"
                    "Your account does not have sufficient permissions."
                )
                return
            self.guard.reset()
            self._launch_main_app(role, username)
        else:
            attempts = self.guard.register_failed_attempt()
            remaining = self.guard.max_attempts - attempts

            if remaining > 0:
                self.show_security_alert(
                    "AUTHENTICATION FAILED",
                    f"{msg}\n\n{remaining} attempt(s) remaining before lockout."
                )
            else:
                self.show_security_alert(
                    "SECURITY LOCKOUT",
                    "Maximum attempts reached.\nAccount locked for 30 seconds."
                )

            self.pass_entry.delete(0, tk.END)

    def _attempt_guest_login(self):
        self._launch_main_app(role='user', username='RestrictedViewer')

    # ══════════════════════════════════════════════════════════════════════
    # FORGOT PASSWORD
    # ══════════════════════════════════════════════════════════════════════
    def _build_forgot_pass_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        outer = ctk.CTkFrame(self.root, fg_color=DS.BG_PRIMARY)
        outer.pack(fill="both", expand=True)

        wrapper = ctk.CTkFrame(outer, fg_color="transparent", width=380)
        wrapper.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(wrapper, text="🔐", font=("Segoe UI", 42),
                     text_color=DS.ACCENT_PRIMARY).pack(pady=(0, 12))
        ctk.CTkLabel(wrapper, text="Password Recovery",
                     font=DS.FONT_HEADING_LG,
                     text_color=DS.TEXT_PRIMARY).pack()
        ctk.CTkLabel(wrapper, text="Enter your registered email to receive a reset code",
                     font=DS.FONT_BODY_SM, text_color=DS.TEXT_SECONDARY).pack(pady=(4, 24))

        card = ctk.CTkFrame(wrapper, fg_color=DS.BG_SURFACE,
                            corner_radius=DS.RADIUS_LG,
                            border_color=DS.BORDER_MUTED, border_width=1)
        card.pack(fill="x", padx=10)

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=28, pady=24)

        create_field_label(inner, "Email Address").pack(anchor="w", pady=(0, 4))
        self.fp_email_entry = create_styled_entry(inner, placeholder="you@company.com")
        self.fp_email_entry.pack(fill="x", pady=(0, 18))

        def send_reset_code():
            email = self.fp_email_entry.get().strip().lower()
            if not email:
                self.show_error("Please enter your email address.")
                return
            target_username = None
            for user, data in auth.users.items():
                if data.get("registered_email") == email:
                    target_username = user
                    break
            if not target_username:
                self.show_error("No account found with this email.")
                return

            self.root.config(cursor="watch")
            loader = ctk.CTkToplevel(self.root)
            loader.overrideredirect(True)
            lx = self.root.winfo_x() + (self.root.winfo_width() // 2) - 120
            ly = self.root.winfo_y() + (self.root.winfo_height() // 2) - 35
            loader.geometry(f"240x70+{lx}+{ly}")
            loader.configure(fg_color=DS.BG_SURFACE)
            ctk.CTkLabel(loader, text="Sending reset code…",
                         font=DS.FONT_BODY_SM, text_color=DS.ACCENT_PRIMARY).pack(expand=True)
            loader.update()
            self._apply_icon(loader)

            def _send_reset_task():
                success, msg = email_service.send_otp_email(email, "reset")

                def _update_gui():
                    self.root.config(cursor="")
                    loader.destroy()
                    if success:
                        self.show_success(f"Password reset code sent to {email}")
                        self._build_reset_pass_ui(target_username, email)
                    else:
                        self.show_error(msg)

                self.root.after(0, _update_gui)

            threading.Thread(target=_send_reset_task, daemon=True).start()

        create_primary_button(inner, "Send Recovery Code",
                              send_reset_code).pack(fill="x")

        create_link_button(wrapper, "← Back to sign in",
                          self._build_login_ui).pack(pady=(16, 0))

    def _build_reset_pass_ui(self, username, email):
        for widget in self.root.winfo_children():
            widget.destroy()

        outer = ctk.CTkFrame(self.root, fg_color=DS.BG_PRIMARY)
        outer.pack(fill="both", expand=True)

        wrapper = ctk.CTkFrame(outer, fg_color="transparent", width=380)
        wrapper.place(relx=0.5, rely=0.45, anchor="center")

        ctk.CTkLabel(wrapper, text="🔓", font=("Segoe UI", 42),
                     text_color=DS.SUCCESS).pack(pady=(0, 12))
        ctk.CTkLabel(wrapper, text="Reset Password",
                     font=DS.FONT_HEADING_LG,
                     text_color=DS.TEXT_PRIMARY).pack()

        # Account badge
        badge = ctk.CTkFrame(wrapper, fg_color=DS.BG_SURFACE_2,
                              corner_radius=DS.RADIUS_SM)
        badge.pack(pady=(8, 20))
        ctk.CTkLabel(badge, text=f"Account: {username}",
                     font=DS.FONT_MONO_SM, text_color=DS.ACCENT_PRIMARY).pack(padx=16, pady=6)

        card = ctk.CTkFrame(wrapper, fg_color=DS.BG_SURFACE,
                            corner_radius=DS.RADIUS_LG,
                            border_color=DS.BORDER_MUTED, border_width=1)
        card.pack(fill="x", padx=10)

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=28, pady=24)

        create_field_label(inner, "6-Digit OTP Code").pack(anchor="w", pady=(0, 4))
        self.rp_otp_entry = create_styled_entry(inner, placeholder="Enter code from email")
        self.rp_otp_entry.pack(fill="x", pady=(0, 12))

        create_field_label(inner, "New Password").pack(anchor="w", pady=(0, 4))
        self.rp_pass_entry = create_styled_entry(inner, placeholder="Minimum 6 characters", show="•")
        self.rp_pass_entry.pack(fill="x", pady=(0, 12))

        create_field_label(inner, "Confirm Password").pack(anchor="w", pady=(0, 4))
        self.rp_confirm_entry = create_styled_entry(inner, placeholder="Re-enter password", show="•")
        self.rp_confirm_entry.pack(fill="x", pady=(0, 18))

        def execute_reset():
            otp = self.rp_otp_entry.get().strip()
            new_pass = self.rp_pass_entry.get()
            confirm = self.rp_confirm_entry.get()

            if not otp or not new_pass or not confirm:
                self.show_error("All fields are required.")
                return
            if new_pass != confirm:
                self.show_error("Passwords do not match.")
                return
            is_valid, msg = email_service.verify_otp(email, otp)
            if is_valid:
                success, auth_msg = auth.update_password(username, new_pass)
                if success:
                    self.show_success("Password reset successfully!\nYou can now sign in.")
                    self._build_login_ui()
                else:
                    self.show_error(auth_msg)
            else:
                self.show_error(msg)

        create_primary_button(inner, "Reset Password", execute_reset).pack(fill="x")

        create_link_button(wrapper, "← Cancel",
                          self._build_login_ui).pack(pady=(16, 0))

    # ══════════════════════════════════════════════════════════════════════
    # GOOGLE SSO (same logic)
    # ══════════════════════════════════════════════════════════════════════
    def _handle_google_login(self, mode="login"):
        self.root.config(cursor="watch")
        self.root.update()
        self._google_mode = mode

        def _auth_thread():
            from core.google_auth import authenticate_google_sso
            success, result = authenticate_google_sso()
            self.root.after(0, lambda: self._process_google_result(success, result))

        threading.Thread(target=_auth_thread, daemon=True).start()

    def _process_google_result(self, success, result):
        self.root.config(cursor="")
        mode = getattr(self, '_google_mode', 'login')

        if not success:
            self.show_error(result)
            return

        email = result['email']
        name = result['name']

        is_registered, existing_username = auth.is_google_email_registered(email)

        if mode == "register":
            if is_registered:
                self.show_info(
                    f"{email} is already registered.\nTaking you to sign in.")
                if auth.has_sso_pin(existing_username):
                    self._build_sso_pin_verify_ui(existing_username, name)
                else:
                    self._build_sso_pin_setup_ui(existing_username, name)
            else:
                import uuid as _uuid
                base_username = email.split('@')[0]
                username = base_username
                counter = 1
                while username in auth.users:
                    username = f"{base_username}{counter}"
                    counter += 1
                dummy_pass = _uuid.uuid4().hex
                auth.register_user(username, email, dummy_pass, role="admin", auth_method="google")
                auth._save_db()
                self._build_sso_pin_setup_ui(username, name)
        else:
            if not is_registered:
                self.show_error(
                    f"Access Denied.\n\n{email} is not registered.\n\n"
                    "Only registered accounts can sign in with Google.\n"
                    "Use 'Create Account' first.")
                return
            if auth.has_sso_pin(existing_username):
                self._build_sso_pin_verify_ui(existing_username, name)
            else:
                self._build_sso_pin_setup_ui(existing_username, name)

    def _build_sso_pin_setup_ui(self, username, name):
        for widget in self.root.winfo_children():
            widget.destroy()

        outer = ctk.CTkFrame(self.root, fg_color=DS.BG_PRIMARY)
        outer.pack(fill="both", expand=True)

        wrapper = ctk.CTkFrame(outer, fg_color="transparent", width=380)
        wrapper.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(wrapper, text="🔐", font=("Segoe UI", 42),
                     text_color=DS.ACCENT_PRIMARY).pack(pady=(0, 12))
        ctk.CTkLabel(wrapper, text=f"Welcome, {name}!",
                     font=DS.FONT_HEADING_LG,
                     text_color=DS.TEXT_PRIMARY).pack()
        ctk.CTkLabel(wrapper,
                     text="Google identity verified.\nSet a device PIN for future sign-ins.",
                     font=DS.FONT_BODY_SM, text_color=DS.TEXT_SECONDARY,
                     justify="center").pack(pady=(4, 24))

        card = ctk.CTkFrame(wrapper, fg_color=DS.BG_SURFACE,
                            corner_radius=DS.RADIUS_LG,
                            border_color=DS.BORDER_MUTED, border_width=1)
        card.pack(fill="x", padx=10)

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=28, pady=24)

        create_field_label(inner, "New Device PIN (4+ digits)").pack(anchor="w", pady=(0, 4))
        self._pin_entry = ctk.CTkEntry(inner, show="●", font=("Segoe UI", 20, "bold"),
                                        justify="center", fg_color=DS.BG_INPUT,
                                        border_color=DS.BORDER, text_color=DS.TEXT_PRIMARY,
                                        corner_radius=DS.RADIUS_SM, height=48)
        self._pin_entry.pack(fill="x", pady=(0, 14))
        self._pin_entry.focus()

        create_field_label(inner, "Confirm PIN").pack(anchor="w", pady=(0, 4))
        self._pin_confirm_entry = ctk.CTkEntry(inner, show="●", font=("Segoe UI", 20, "bold"),
                                                justify="center", fg_color=DS.BG_INPUT,
                                                border_color=DS.BORDER, text_color=DS.TEXT_PRIMARY,
                                                corner_radius=DS.RADIUS_SM, height=48)
        self._pin_confirm_entry.pack(fill="x", pady=(0, 18))

        def _save_pin():
            pin = self._pin_entry.get().strip()
            confirm = self._pin_confirm_entry.get().strip()
            if not pin or not confirm:
                self.show_error("Both PIN fields are required.")
                return
            if pin != confirm:
                self.show_error("PINs do not match.")
                self._pin_entry.delete(0, "end")
                self._pin_confirm_entry.delete(0, "end")
                self._pin_entry.focus()
                return
            if not pin.isdigit():
                self.show_error("PIN must contain digits only (0–9).")
                return
            if len(pin) < 4:
                self.show_error("PIN must be at least 4 digits.")
                return
            ok, msg = auth.set_sso_pin(username, pin)
            if ok:
                self.show_success("Device PIN set!\nYou are now signed in.")
                self._launch_main_app(role="admin", username=username)
            else:
                self.show_error(msg)

        create_primary_button(inner, "Set PIN & Continue", _save_pin).pack(fill="x")

        create_link_button(wrapper, "← Cancel",
                          self._build_login_ui).pack(pady=(16, 0))
        self.root.bind('<Return>', lambda e: _save_pin())

    def _build_sso_pin_verify_ui(self, username, name):
        for widget in self.root.winfo_children():
            widget.destroy()

        outer = ctk.CTkFrame(self.root, fg_color=DS.BG_PRIMARY)
        outer.pack(fill="both", expand=True)

        wrapper = ctk.CTkFrame(outer, fg_color="transparent", width=380)
        wrapper.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(wrapper, text="🛡", font=("Segoe UI", 42),
                     text_color=DS.ACCENT_PRIMARY).pack(pady=(0, 12))
        ctk.CTkLabel(wrapper, text=f"Welcome back, {name}",
                     font=DS.FONT_HEADING_LG,
                     text_color=DS.TEXT_PRIMARY).pack()
        ctk.CTkLabel(wrapper,
                     text="Google identity verified.\nEnter your device PIN to continue.",
                     font=DS.FONT_BODY_SM, text_color=DS.TEXT_SECONDARY,
                     justify="center").pack(pady=(4, 24))

        card = ctk.CTkFrame(wrapper, fg_color=DS.BG_SURFACE,
                            corner_radius=DS.RADIUS_LG,
                            border_color=DS.BORDER_MUTED, border_width=1)
        card.pack(fill="x", padx=10)

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=28, pady=24)

        create_field_label(inner, "Device PIN").pack(anchor="w", pady=(0, 4))
        self._verify_pin_entry = ctk.CTkEntry(inner, show="●",
                                               font=("Segoe UI", 22, "bold"),
                                               justify="center", fg_color=DS.BG_INPUT,
                                               border_color=DS.BORDER,
                                               text_color=DS.TEXT_PRIMARY,
                                               corner_radius=DS.RADIUS_SM, height=52)
        self._verify_pin_entry.pack(fill="x", pady=(0, 18))
        self._verify_pin_entry.focus()

        self._pin_attempts = 0

        def _verify_pin():
            pin = self._verify_pin_entry.get().strip()
            if not pin:
                self.show_error("Please enter your PIN.")
                return
            if auth.verify_sso_pin(username, pin):
                self._launch_main_app(role="admin", username=username)
            else:
                self._pin_attempts += 1
                self._verify_pin_entry.delete(0, "end")
                if self._pin_attempts >= 3:
                    self.show_security_alert(
                        "PIN LOCKOUT",
                        "3 incorrect PINs entered.\nReturning to sign in.")
                    self._build_login_ui()
                else:
                    remaining = 3 - self._pin_attempts
                    self.show_error(f"Incorrect PIN.\n{remaining} attempt(s) remaining.")

        create_primary_button(inner, "Verify PIN", _verify_pin).pack(fill="x")

        create_link_button(wrapper, "← Cancel",
                          self._build_login_ui).pack(pady=(16, 0))
        self.root.bind('<Return>', lambda e: _verify_pin())

    # ══════════════════════════════════════════════════════════════════════
    # REGISTRATION ATTEMPT (same logic)
    # ══════════════════════════════════════════════════════════════════════
    def _attempt_register(self):
        if getattr(self, 'is_processing', False):
            return
        self.is_processing = True

        username = self.reg_user_entry.get().strip()
        email = self.reg_email_entry.get().strip().lower()
        password = self.reg_pass_entry.get()
        confirm = self.reg_confirm_entry.get()

        if not username or not email or not password or not confirm:
            self.show_error("All fields are required.")
            self.is_processing = False
            return

        email_pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        if not re.match(email_pattern, email):
            self.show_error("Invalid email format.")
            self.is_processing = False
            return

        if password != confirm:
            self.show_error("Passwords do not match.")
            self.is_processing = False
            return

        if len(password) < 6:
            self.show_error("Password must be at least 6 characters.")
            self.is_processing = False
            return

        self._set_ui_state("disabled")
        self.root.config(cursor="watch")

        loader = ctk.CTkToplevel(self.root)
        loader.overrideredirect(True)
        lx = self.root.winfo_x() + (self.root.winfo_width() // 2) - 100
        ly = self.root.winfo_y() + (self.root.winfo_height() // 2) - 35
        loader.geometry(f"200x70+{lx}+{ly}")
        loader.configure(fg_color=DS.BG_SURFACE)
        self._apply_icon(loader)

        ctk.CTkLabel(loader, text="Sending verification…",
                     font=DS.FONT_BODY_SM, text_color=DS.ACCENT_PRIMARY).pack(expand=True)
        loader.update()

        def _send_email_task():
            try:
                success, msg = email_service.send_otp_email(email, "verification")
            except Exception as e:
                success = False
                msg = str(e)

            def _update_gui():
                self.root.config(cursor="")
                loader.destroy()
                if success:
                    self.show_success(f"Verification code sent to:\n{email}")
                    self._build_otp_ui(username, email, password)
                else:
                    self.show_error(f"Failed to send OTP.\n\n{msg}")
                    self.is_processing = False
                    self._set_ui_state("normal")

            self.root.after(0, _update_gui)

        threading.Thread(target=_send_email_task, daemon=True).start()

    def _set_ui_state(self, state="normal"):
        target_state = "normal" if state == "normal" else "disabled"
        for btn_name in ["login_btn", "reg_btn", "google_btn", "viewer_btn", "guest_btn"]:
            if hasattr(self, btn_name):
                try:
                    getattr(self, btn_name).configure(state=target_state)
                except:
                    pass

    # ══════════════════════════════════════════════════════════════════════
    # TENANT / CLOUD / REINSTALL FLOWS (same logic, updated UI)
    # ══════════════════════════════════════════════════════════════════════
    def _check_tenant_then_reinstall(self):
        from core import tenant_manager

        env_key = os.environ.get("FMSECURE_TENANT_KEY", "").strip()
        if env_key and not tenant_manager.is_enrolled():
            self._auto_enroll_from_env(env_key)
            return

        if tenant_manager.is_enrolled():
            self._check_for_reinstall_backup()
            return

        self._build_tenant_gateway_ui()

    def _auto_enroll_from_env(self, env_key):
        from core import tenant_manager

        for widget in self.root.winfo_children():
            widget.destroy()

        outer = ctk.CTkFrame(self.root, fg_color=DS.BG_PRIMARY)
        outer.pack(fill="both", expand=True)

        wrapper = ctk.CTkFrame(outer, fg_color="transparent", width=380)
        wrapper.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(wrapper, text="🏢", font=("Segoe UI", 42),
                     text_color=DS.ACCENT_PRIMARY).pack(pady=(0, 12))
        ctk.CTkLabel(wrapper, text="Enrolling in Organisation",
                     font=DS.FONT_HEADING_MD,
                     text_color=DS.TEXT_PRIMARY).pack()
        status_var = ctk.StringVar(value="Validating organisation key…")
        ctk.CTkLabel(wrapper, textvariable=status_var,
                     font=DS.FONT_BODY_SM, text_color=DS.TEXT_SECONDARY).pack(pady=(8, 0))

        def _do_enroll():
            ok, tenant_name = tenant_manager.validate_key(env_key)
            if ok:
                tenant_manager.save(env_key,
                                    "https://fmsecure.onrender.com",
                                    tenant_name)
                self.root.after(0, lambda: status_var.set(
                    f"✓ Enrolled in: {tenant_name or 'organisation'}"))
                self.root.after(1200, self._check_for_reinstall_backup)
            else:
                self.root.after(0, lambda: status_var.set(
                    "⚠ Organisation key invalid — continuing as personal install."))
                self.root.after(1800, self._check_for_reinstall_backup)

        threading.Thread(target=_do_enroll, daemon=True).start()

    def _build_tenant_gateway_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        outer = ctk.CTkFrame(self.root, fg_color=DS.BG_PRIMARY)
        outer.pack(fill="both", expand=True)

        scroll = ctk.CTkScrollableFrame(outer, fg_color=DS.BG_PRIMARY)
        scroll.pack(fill="both", expand=True, padx=30, pady=30)

        ctk.CTkLabel(scroll, text="⚡", font=("Segoe UI", 42),
                     text_color=DS.ACCENT_PRIMARY).pack(pady=(0, 8))
        ctk.CTkLabel(scroll, text="Welcome to FMSecure",
                     font=DS.FONT_HEADING_LG,
                     text_color=DS.TEXT_PRIMARY).pack()
        ctk.CTkLabel(scroll, text="How is this installation being set up?",
                     font=DS.FONT_BODY_SM, text_color=DS.TEXT_SECONDARY).pack(pady=(4, 24))

        # Organisation option
        org_card = ctk.CTkFrame(scroll, fg_color=DS.BG_SURFACE,
                                 corner_radius=DS.RADIUS_MD,
                                 border_color=DS.ACCENT_MUTED, border_width=1)
        org_card.pack(fill="x", pady=(0, 12))

        org_inner = ctk.CTkFrame(org_card, fg_color="transparent")
        org_inner.pack(fill="x", padx=20, pady=16)

        ctk.CTkLabel(org_inner, text="🏢  Organisation Managed",
                     font=DS.FONT_HEADING_SM,
                     text_color=DS.TEXT_PRIMARY).pack(anchor="w")
        ctk.CTkLabel(org_inner,
                     text="Your IT admin provided an organisation key.\n"
                          "This machine will report to your org's dashboard.",
                     font=DS.FONT_CAPTION, text_color=DS.TEXT_SECONDARY,
                     justify="left").pack(anchor="w", pady=(4, 10))
        create_primary_button(org_inner, "Enter Organisation Key →",
                              self._build_tenant_enrollment_ui).pack(anchor="w")

        # Personal option
        personal_card = ctk.CTkFrame(scroll, fg_color=DS.BG_SURFACE,
                                      corner_radius=DS.RADIUS_MD,
                                      border_color=DS.BORDER_MUTED, border_width=1)
        personal_card.pack(fill="x", pady=(0, 12))

        personal_inner = ctk.CTkFrame(personal_card, fg_color="transparent")
        personal_inner.pack(fill="x", padx=20, pady=16)

        ctk.CTkLabel(personal_inner, text="👤  Personal Install",
                     font=DS.FONT_HEADING_SM,
                     text_color=DS.TEXT_PRIMARY).pack(anchor="w")
        ctk.CTkLabel(personal_inner,
                     text="Standard installation for personal or standalone use.\n"
                          "No organisation key required.",
                     font=DS.FONT_CAPTION, text_color=DS.TEXT_SECONDARY,
                     justify="left").pack(anchor="w", pady=(4, 10))
        create_secondary_button(personal_inner, "Continue as Personal Install",
                                self._check_for_reinstall_backup).pack(anchor="w")

        ctk.CTkLabel(scroll,
                     text="Your choice can be changed later from within the app.",
                     font=DS.FONT_TINY, text_color=DS.TEXT_TERTIARY).pack(pady=(8, 0))

    def _build_tenant_enrollment_ui(self):
        from core import tenant_manager

        for widget in self.root.winfo_children():
            widget.destroy()

        outer = ctk.CTkFrame(self.root, fg_color=DS.BG_PRIMARY)
        outer.pack(fill="both", expand=True)

        wrapper = ctk.CTkFrame(outer, fg_color="transparent", width=400)
        wrapper.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(wrapper, text="🔑", font=("Segoe UI", 40),
                     text_color=DS.ACCENT_PRIMARY).pack(pady=(0, 8))
        ctk.CTkLabel(wrapper, text="Enter Organisation Key",
                     font=DS.FONT_HEADING_LG,
                     text_color=DS.TEXT_PRIMARY).pack()
        ctk.CTkLabel(wrapper,
                     text="Your IT administrator provided this key when they\nregistered your organisation with FMSecure.",
                     font=DS.FONT_BODY_SM, text_color=DS.TEXT_SECONDARY,
                     justify="center").pack(pady=(4, 24))

        card = ctk.CTkFrame(wrapper, fg_color=DS.BG_SURFACE,
                            corner_radius=DS.RADIUS_LG,
                            border_color=DS.BORDER_MUTED, border_width=1)
        card.pack(fill="x", padx=10)

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=28, pady=24)

        create_field_label(inner, "Organisation Key").pack(anchor="w", pady=(0, 4))
        key_var = ctk.StringVar()
        key_entry = ctk.CTkEntry(inner, textvariable=key_var,
                                  placeholder_text="fms-tenant-xxxxxxxxxxxxxxxxxxxx",
                                  font=DS.FONT_MONO_SM, fg_color=DS.BG_INPUT,
                                  border_color=DS.BORDER, text_color=DS.ACCENT_PRIMARY,
                                  corner_radius=DS.RADIUS_SM, height=DS.INPUT_HEIGHT)
        key_entry.pack(fill="x", pady=(0, 6))
        key_entry.focus()

        status_lbl = ctk.CTkLabel(inner, text="", font=DS.FONT_CAPTION,
                                   text_color=DS.ERROR, wraplength=320)
        status_lbl.pack(pady=(0, 12))

        prog = ctk.CTkProgressBar(inner, width=320, mode="indeterminate",
                                   progress_color=DS.ACCENT_PRIMARY)

        def _do_enroll():
            key = key_var.get().strip()
            if not key:
                status_lbl.configure(text="Please enter the organisation key.",
                                     text_color=DS.ERROR)
                return
            if not key.startswith("fms-tenant-"):
                status_lbl.configure(
                    text="Key should start with fms-tenant-",
                    text_color=DS.ERROR)
                return

            enroll_btn.configure(state="disabled", text="Validating…")
            status_lbl.configure(text="Connecting to FMSecure server…",
                                 text_color=DS.TEXT_SECONDARY)
            prog.pack(pady=(0, 6))
            prog.start()

            def _validate_in_thread():
                ok, result = tenant_manager.validate_key(key)

                def _finish():
                    prog.stop()
                    prog.pack_forget()
                    enroll_btn.configure(state="normal",
                                         text="Enroll This Machine →")
                    if ok:
                        tenant_manager.save(
                            key,
                            "https://fmsecure.onrender.com",
                            result)
                        status_lbl.configure(
                            text=f"✓ Enrolled in: {result or 'organisation'}",
                            text_color=DS.SUCCESS)
                        self.root.after(1200, self._check_for_reinstall_backup)
                    else:
                        status_lbl.configure(text=result, text_color=DS.ERROR)

                self.root.after(0, _finish)

            threading.Thread(target=_validate_in_thread, daemon=True).start()

        enroll_btn = create_primary_button(inner, "Enroll This Machine →", _do_enroll)
        enroll_btn.pack(fill="x")

        create_link_button(wrapper, "← Back",
                          self._build_tenant_gateway_ui).pack(pady=(16, 0))

        key_entry.bind("<Return>", lambda e: _do_enroll())
        self.root.bind("<Escape>", lambda e: self._build_tenant_gateway_ui())

    # ══════════════════════════════════════════════════════════════════════
    # CLOUD BACKUP / REINSTALL DETECTION (same logic, updated UI)
    # ══════════════════════════════════════════════════════════════════════
    def _check_for_reinstall_backup(self):
        from core.utils import get_app_data_dir

        if auth.has_users():
            self._build_login_ui()
            return

        token_path = os.path.join(get_app_data_dir(), "token.pickle")
        if os.path.exists(token_path):
            self._build_cloud_probe_ui()
            self._start_drive_probe()
        else:
            self._build_cloud_gateway_ui()

    def _start_drive_probe(self):
        def _probe():
            try:
                from core.cloud_sync import cloud_sync
                from core.encryption_manager import crypto_manager

                if not cloud_sync.is_active:
                    self.root.after(0, self._build_cloud_gateway_ui)
                    return
                self._run_backup_probe(cloud_sync, crypto_manager)
            except Exception as e:
                print(f"[LOGIN] Drive probe error: {e}")
                self.root.after(0, self._build_register_ui)

        threading.Thread(target=_probe, daemon=True).start()

    def _run_backup_probe(self, cloud_sync, crypto_manager):
        try:
            machine_id = crypto_manager.get_machine_id()
            backup_info = cloud_sync.check_backup_exists(machine_id)
            archives = cloud_sync.list_archives(machine_id)

            all_options = []
            if backup_info:
                backup_info["_is_active"] = True
                backup_info["archived_at"] = backup_info.get("last_sync", "Current")
                all_options.append(backup_info)
            for a in archives:
                a["_is_active"] = False
                all_options.append(a)

            if not all_options:
                self.root.after(0, self._build_register_ui)
            elif len(all_options) == 1:
                self.root.after(0, lambda: self._build_reinstall_detection_ui(
                    all_options[0], machine_id))
            else:
                self.root.after(0, lambda: self._build_archive_picker_ui(
                    all_options, machine_id))
        except Exception as e:
            print(f"[LOGIN] Backup probe error: {e}")
            self.root.after(0, self._build_register_ui)

    def _build_cloud_gateway_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        outer = ctk.CTkFrame(self.root, fg_color=DS.BG_PRIMARY)
        outer.pack(fill="both", expand=True)

        wrapper = ctk.CTkFrame(outer, fg_color="transparent", width=400)
        wrapper.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(wrapper, text="☁", font=("Segoe UI", 48),
                     text_color=DS.ACCENT_PRIMARY).pack(pady=(0, 12))
        ctk.CTkLabel(wrapper, text="Check for Previous Installation",
                     font=DS.FONT_HEADING_MD,
                     text_color=DS.TEXT_PRIMARY).pack()
        ctk.CTkLabel(wrapper,
                     text="If you had FMSecure before, your data may be\nrecoverable from Google Drive.",
                     font=DS.FONT_BODY_SM, text_color=DS.TEXT_SECONDARY,
                     justify="center").pack(pady=(4, 20))

        # Info box
        info = ctk.CTkFrame(wrapper, fg_color=DS.BG_SURFACE_2,
                             corner_radius=DS.RADIUS_SM,
                             border_color=DS.ACCENT_MUTED, border_width=1)
        info.pack(fill="x", padx=10, pady=(0, 16))
        ctk.CTkLabel(info,
                     text="ℹ  Connecting Google Drive lets FMSecure search for\n"
                          "    your encrypted backup, accounts, and settings.",
                     font=DS.FONT_TINY, text_color=DS.INFO,
                     justify="left").pack(padx=14, pady=10)

        self._gw_status_var = ctk.StringVar(value="")
        ctk.CTkLabel(wrapper, textvariable=self._gw_status_var,
                     font=DS.FONT_TINY, text_color=DS.ERROR).pack(pady=(0, 8))

        connect_btn = create_primary_button(
            wrapper, "  Connect Google Drive & Check",
            lambda: self._gateway_connect_drive(connect_btn, skip_btn))
        connect_btn.pack(fill="x", padx=10, pady=(0, 8))

        skip_btn = create_secondary_button(
            wrapper, "Skip — Create New Account",
            self._build_register_ui)
        skip_btn.pack(fill="x", padx=10, pady=(0, 4))

        ctk.CTkLabel(wrapper,
                     text="Skipping won't delete cloud backups.\nYou can restore them later.",
                     font=DS.FONT_TINY, text_color=DS.TEXT_TERTIARY,
                     justify="center").pack(pady=(8, 0))

    def _gateway_connect_drive(self, connect_btn, skip_btn):
        connect_btn.configure(state="disabled", text="Connecting…")
        skip_btn.configure(state="disabled")
        self._gw_status_var.set("")

        def _auth_and_probe():
            try:
                from core.cloud_sync import cloud_sync
                from core.encryption_manager import crypto_manager

                cloud_sync.force_authenticate()

                if not cloud_sync.is_active:
                    def _fail():
                        connect_btn.configure(state="normal",
                                              text="  Connect Google Drive & Check")
                        skip_btn.configure(state="normal")
                        self._gw_status_var.set("Authentication failed or cancelled.")
                    self.root.after(0, _fail)
                    return

                self.root.after(0, self._build_cloud_probe_ui)
                self._run_backup_probe(cloud_sync, crypto_manager)
            except Exception as e:
                print(f"[LOGIN] Gateway auth error: {e}")
                def _err():
                    connect_btn.configure(state="normal",
                                          text="  Connect Google Drive & Check")
                    skip_btn.configure(state="normal")
                    self._gw_status_var.set(f"Error: {e}")
                self.root.after(0, _err)

        threading.Thread(target=_auth_and_probe, daemon=True).start()

    def _build_cloud_probe_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        outer = ctk.CTkFrame(self.root, fg_color=DS.BG_PRIMARY)
        outer.pack(fill="both", expand=True)

        wrapper = ctk.CTkFrame(outer, fg_color="transparent", width=380)
        wrapper.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(wrapper, text="☁", font=("Segoe UI", 48),
                     text_color=DS.ACCENT_PRIMARY).pack(pady=(0, 12))
        ctk.CTkLabel(wrapper, text="Checking for backups",
                     font=DS.FONT_HEADING_MD,
                     text_color=DS.TEXT_PRIMARY).pack()
        ctk.CTkLabel(wrapper, text="Searching Google Drive…",
                     font=DS.FONT_BODY_SM, text_color=DS.TEXT_SECONDARY).pack(pady=(4, 24))

        self._probe_spin_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self._probe_spin_idx = [0]
        self._probe_spin_lbl = ctk.CTkLabel(wrapper, text="⠋", font=("Segoe UI", 24),
                                             text_color=DS.ACCENT_PRIMARY)
        self._probe_spin_lbl.pack()

        self._animate_probe_spinner()

    def _animate_probe_spinner(self):
        lbl = getattr(self, '_probe_spin_lbl', None)
        if not lbl:
            return
        try:
            if not lbl.winfo_exists():
                return
        except Exception:
            return
        chars = self._probe_spin_chars
        idx = self._probe_spin_idx
        lbl.configure(text=chars[idx[0] % len(chars)])
        idx[0] += 1
        self.root.after(80, self._animate_probe_spinner)

    def _build_reinstall_detection_ui(self, backup_info, machine_id):
        for widget in self.root.winfo_children():
            widget.destroy()

        outer = ctk.CTkFrame(self.root, fg_color=DS.BG_PRIMARY)
        outer.pack(fill="both", expand=True)

        scroll = ctk.CTkScrollableFrame(outer, fg_color=DS.BG_PRIMARY)
        scroll.pack(fill="both", expand=True, padx=30, pady=24)

        ctk.CTkLabel(scroll, text="☁", font=("Segoe UI", 42),
                     text_color=DS.ACCENT_PRIMARY).pack(pady=(0, 8))
        ctk.CTkLabel(scroll, text="Previous Installation Found",
                     font=DS.FONT_HEADING_LG,
                     text_color=DS.TEXT_PRIMARY).pack()
        ctk.CTkLabel(scroll, text="A cloud backup was found for this device.",
                     font=DS.FONT_BODY_SM, text_color=DS.TEXT_SECONDARY).pack(pady=(4, 20))

        # Metadata card
        meta = ctk.CTkFrame(scroll, fg_color=DS.BG_SURFACE,
                             corner_radius=DS.RADIUS_MD,
                             border_color=DS.BORDER_MUTED, border_width=1)
        meta.pack(fill="x", pady=(0, 20))

        fc = backup_info.get("file_counts", {})
        rows = [
            ("Last sync", backup_info.get("last_sync", "Unknown")),
            ("Hostname", backup_info.get("hostname", "Unknown")),
            ("Account", backup_info.get("email", "Unknown")),
            ("Plan", backup_info.get("tier", "Unknown")),
            ("Vault files", f"{fc.get('vault', 0)} files"),
            ("Log files", f"{fc.get('logs', 0)} files"),
        ]
        for label, value in rows:
            row = ctk.CTkFrame(meta, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=3)
            ctk.CTkLabel(row, text=f"{label}:", font=DS.FONT_CAPTION,
                         text_color=DS.TEXT_TERTIARY, width=90, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=value, font=("Segoe UI", 10, "bold"),
                         text_color=DS.TEXT_PRIMARY, anchor="w").pack(side="left")

        create_primary_button(scroll, "Restore My Backup",
                              lambda: self._execute_restore(machine_id)).pack(fill="x", pady=(0, 8))

        create_secondary_button(scroll, "Start Fresh (archive old backup)",
                                lambda: self._execute_start_fresh(machine_id)).pack(fill="x", pady=(0, 6))

        ctk.CTkLabel(scroll,
                     text="Starting fresh archives your old data in Google Drive.\n"
                          "Your PRO license is preserved.",
                     font=DS.FONT_TINY, text_color=DS.TEXT_TERTIARY,
                     justify="center").pack(pady=(4, 0))

    def _execute_restore(self, machine_id):
        for widget in self.root.winfo_children():
            widget.destroy()

        outer = ctk.CTkFrame(self.root, fg_color=DS.BG_PRIMARY)
        outer.pack(fill="both", expand=True)

        wrapper = ctk.CTkFrame(outer, fg_color="transparent", width=400)
        wrapper.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(wrapper, text="☁", font=("Segoe UI", 42),
                     text_color=DS.ACCENT_PRIMARY).pack(pady=(0, 8))
        ctk.CTkLabel(wrapper, text="Restoring Your Installation",
                     font=DS.FONT_HEADING_MD,
                     text_color=DS.TEXT_PRIMARY).pack()
        ctk.CTkLabel(wrapper, text="Recovering data from Google Drive…",
                     font=DS.FONT_BODY_SM, text_color=DS.TEXT_SECONDARY).pack(pady=(4, 16))

        # Steps
        steps_frame = ctk.CTkFrame(wrapper, fg_color=DS.BG_SURFACE,
                                    corner_radius=DS.RADIUS_MD,
                                    border_color=DS.BORDER_MUTED, border_width=1)
        steps_frame.pack(fill="x", padx=10, pady=(0, 14))

        STEP_DEFS = [
            ("🔑", "Recovering encryption key"),
            ("👤", "Restoring account database"),
            ("📋", "Restoring audit logs"),
            ("⚙", "Reloading credentials"),
            ("✓", "Finalizing"),
        ]
        step_widgets = []
        for icon, label in STEP_DEFS:
            row = ctk.CTkFrame(steps_frame, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=3)
            icon_lbl = ctk.CTkLabel(row, text=icon, font=DS.FONT_BODY,
                                     text_color=DS.TEXT_TERTIARY, width=26)
            icon_lbl.pack(side="left")
            txt_lbl = ctk.CTkLabel(row, text=label, font=DS.FONT_BODY_SM,
                                    text_color=DS.TEXT_TERTIARY, anchor="w")
            txt_lbl.pack(side="left", padx=8)
            step_widgets.append((icon_lbl, txt_lbl))

        progress_bar = ctk.CTkProgressBar(wrapper, width=360, height=4,
                                           fg_color=DS.BG_SURFACE_3,
                                           progress_color=DS.ACCENT_PRIMARY)
        progress_bar.pack(pady=(0, 6))
        progress_bar.set(0)

        progress_var = ctk.StringVar(value="Connecting to Google Drive…")
        ctk.CTkLabel(wrapper, textvariable=progress_var,
                     font=DS.FONT_MONO_XS, text_color=DS.TEXT_SECONDARY).pack()

        SPIN = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        spin_idx = [0]
        spin_lbl = ctk.CTkLabel(wrapper, text=SPIN[0], font=("Segoe UI", 18),
                                 text_color=DS.TEXT_TERTIARY)
        spin_lbl.pack(pady=(6, 0))

        def _spin():
            try:
                if spin_lbl.winfo_exists():
                    spin_lbl.configure(text=SPIN[spin_idx[0] % len(SPIN)])
                    spin_idx[0] += 1
                    self.root.after(80, _spin)
            except Exception:
                pass
        _spin()

        TOTAL_STEPS = len(STEP_DEFS)

        def _activate_step(idx):
            for i, (il, tl) in enumerate(step_widgets):
                if i < idx:
                    il.configure(text_color=DS.SUCCESS)
                    tl.configure(text_color=DS.SUCCESS)
                elif i == idx:
                    il.configure(text_color=DS.ACCENT_PRIMARY)
                    tl.configure(text_color=DS.TEXT_PRIMARY)
                else:
                    il.configure(text_color=DS.TEXT_TERTIARY)
                    tl.configure(text_color=DS.TEXT_TERTIARY)
            progress_bar.set((idx + 1) / TOTAL_STEPS)

        def _do_restore():
            from core.encryption_manager import crypto_manager
            from core.cloud_sync import cloud_sync

            self.root.after(0, lambda: _activate_step(0))
            self.root.after(0, lambda: progress_var.set("Step 1/5: Preparing encryption recovery…"))
            try:
                for kpath in [crypto_manager.key_file, crypto_manager.key_backup]:
                    if os.path.exists(kpath):
                        os.remove(kpath)
                crypto_manager.fernet = None
                crypto_manager._key_bytes = None
                crypto_manager._local_ok = False
                crypto_manager._cloud_recovery_attempted = False
            except Exception as e:
                print(f"[RESTORE] Key clear warning: {e}")

            self.root.after(0, lambda: progress_var.set("Step 1/5: Downloading encryption key…"))
            key_ok = crypto_manager.attempt_cloud_recovery_if_needed(user_consented=True)

            if not key_ok or crypto_manager.fernet is None:
                def _fail():
                    spin_lbl.configure(text="✕", text_color=DS.ERROR)
                    progress_var.set("Key not found — please create a new account.")
                self.root.after(0, _fail)
                self.root.after(2800, self._build_register_ui)
                return

            self.root.after(0, lambda: _activate_step(1))
            self.root.after(0, lambda: progress_var.set("Step 2/5: Restoring account database…"))
            try:
                cloud_sync.restore_full_appdata(machine_id)
            except Exception as e:
                print(f"[RESTORE] AppData error: {e}")

            self.root.after(0, lambda: _activate_step(2))
            self.root.after(0, lambda: progress_var.set("Step 3/5: Restoring audit logs…"))
            try:
                cloud_sync.restore_logs_and_forensics(machine_id)
            except Exception as e:
                print(f"[RESTORE] Logs error: {e}")

            self.root.after(0, lambda: _activate_step(3))
            self.root.after(0, lambda: progress_var.set("Step 4/5: Reloading credentials…"))
            try:
                time.sleep(0.5)
                auth.reload()
                time.sleep(0.2)
                auth.reload()
            except Exception as e:
                print(f"[RESTORE] auth.reload error: {e}")

            self.root.after(0, lambda: _activate_step(4))
            self.root.after(0, lambda: progress_var.set("✓ Restore complete — please sign in."))

            def _finish():
                spin_lbl.configure(text="✓", text_color=DS.SUCCESS)
                self.root.after(2000, self._build_login_ui)
            self.root.after(0, _finish)

        threading.Thread(target=_do_restore, daemon=True).start()

    def _execute_start_fresh(self, machine_id):
        if not self.show_warning_confirm(
            "Archive your cloud backup?\n\n"
            "Your old data will be moved to an archive folder in Google Drive.\n"
            "Your PRO license is NOT cancelled."
        ):
            return

        def _do_archive():
            from core.cloud_sync import cloud_sync
            from core.encryption_manager import crypto_manager

            ok, name = cloud_sync.archive_machine_folder(machine_id)
            if ok:
                print(f"[LOGIN] Archived as: {name}")
            else:
                print(f"[LOGIN] Archive warning: {name}")

            crypto_manager.attempt_cloud_recovery_if_needed(user_consented=False)
            self.root.after(0, self._build_register_ui)

        threading.Thread(target=_do_archive, daemon=True).start()

    def show_warning_confirm(self, message):
        import tkinter.messagebox as mb
        return mb.askyesno("Confirm", message, parent=self.root)

    def _build_archive_picker_ui(self, all_options, machine_id):
        for widget in self.root.winfo_children():
            widget.destroy()

        outer = ctk.CTkFrame(self.root, fg_color=DS.BG_PRIMARY)
        outer.pack(fill="both", expand=True)

        scroll = ctk.CTkScrollableFrame(outer, fg_color=DS.BG_PRIMARY)
        scroll.pack(fill="both", expand=True, padx=20, pady=16)

        ctk.CTkLabel(scroll, text="☁", font=("Segoe UI", 36),
                     text_color=DS.ACCENT_PRIMARY).pack(pady=(0, 6))
        ctk.CTkLabel(scroll, text=f"{len(all_options)} Backup(s) Found",
                     font=DS.FONT_HEADING_MD,
                     text_color=DS.TEXT_PRIMARY).pack()
        ctk.CTkLabel(scroll, text="Select a backup to restore, or start fresh.",
                     font=DS.FONT_BODY_SM, text_color=DS.TEXT_SECONDARY).pack(pady=(4, 16))

        # List
        list_frame = ctk.CTkFrame(scroll, fg_color=DS.BG_SURFACE,
                                   corner_radius=DS.RADIUS_MD)
        list_frame.pack(fill="x", pady=(0, 12))

        selected = [None]
        all_btns = []

        def _select(opt, btn_ref):
            selected[0] = opt
            for b in all_btns:
                b.configure(fg_color=DS.BG_SURFACE_3)
            btn_ref.configure(fg_color=DS.ACCENT_MUTED)
            restore_btn.configure(state="normal")

        for opt in all_options:
            fc = opt.get("file_counts", {})
            n_files = sum(v for v in fc.values() if isinstance(v, int))
            is_act = opt.get("_is_active", False)
            tag = "★ CURRENT" if is_act else "ARCHIVE"
            date = (opt.get("last_sync") or opt.get("archived_at") or "Unknown")[:16]
            email = opt.get("email", "?")[:32]
            lbl = f"  {tag}  ·  {date}  ·  {email}  ·  {n_files} files"

            btn = ctk.CTkButton(list_frame, text=lbl,
                                command=lambda o=opt, b=None: None,
                                font=DS.FONT_CAPTION,
                                fg_color=DS.BG_SURFACE_3,
                                hover_color=DS.BG_SURFACE_2,
                                text_color=DS.TEXT_PRIMARY, anchor="w",
                                height=40, corner_radius=DS.RADIUS_SM)
            btn.configure(command=lambda o=opt, bref=btn: _select(o, bref))
            btn.pack(fill="x", padx=8, pady=3)
            all_btns.append(btn)

        restore_btn = create_primary_button(
            scroll, "Restore Selected Backup",
            lambda: self._execute_restore_from_option(selected[0], machine_id))
        restore_btn.configure(state="disabled")
        restore_btn.pack(fill="x", pady=(0, 8))

        def _start_fresh():
            if not self.show_warning_confirm(
                "Start Fresh?\n\nExisting backups remain in Google Drive.\n"
                "PRO license is NOT cancelled."
            ):
                return

            def _run():
                from core.encryption_manager import crypto_manager
                crypto_manager.attempt_cloud_recovery_if_needed(user_consented=False)
                self.root.after(0, self._build_register_ui)
            threading.Thread(target=_run, daemon=True).start()

        create_secondary_button(scroll, "Start Fresh", _start_fresh).pack(fill="x", pady=(0, 4))

        ctk.CTkLabel(scroll,
                     text="PRO license preserved — re-enter your key after registering.",
                     font=DS.FONT_TINY, text_color=DS.TEXT_TERTIARY,
                     justify="center").pack(pady=(4, 0))

    def _execute_restore_from_option(self, opt, machine_id):
        if not opt:
            return
        if opt.get("_is_active"):
            self._execute_restore(machine_id)
        else:
            self._execute_restore_from_archive(opt, machine_id)

    def _execute_restore_from_archive(self, archive, machine_id):
        for widget in self.root.winfo_children():
            widget.destroy()

        outer = ctk.CTkFrame(self.root, fg_color=DS.BG_PRIMARY)
        outer.pack(fill="both", expand=True)

        wrapper = ctk.CTkFrame(outer, fg_color="transparent", width=380)
        wrapper.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(wrapper, text="Restoring from archive…",
                     font=DS.FONT_HEADING_SM,
                     text_color=DS.ACCENT_PRIMARY).pack(pady=30)
        progress_var = ctk.StringVar(value="Starting restore…")
        ctk.CTkLabel(wrapper, textvariable=progress_var,
                     font=DS.FONT_BODY_SM, text_color=DS.TEXT_SECONDARY).pack()

        def _run():
            from core.cloud_sync import cloud_sync
            from core.encryption_manager import crypto_manager

            archive_folder_id = archive["folder_id"]

            progress_var.set("Clearing local key…")
            try:
                for kpath in [crypto_manager.key_file, crypto_manager.key_backup]:
                    if os.path.exists(kpath):
                        os.remove(kpath)
                crypto_manager.fernet = None
                crypto_manager._key_bytes = None
                crypto_manager._local_ok = False
                crypto_manager._cloud_recovery_attempted = False
            except Exception as e:
                print(f"[RESTORE_ARCHIVE] Key clear warning: {e}")

            progress_var.set("Downloading encryption key…")
            cloud_sync.restore_from_archive(archive_folder_id, subfolder="keys",
                                             machine_id=machine_id)

            progress_var.set("Loading encryption key…")
            try:
                crypto_manager._phase1_local_init()
            except Exception as e:
                print(f"[RESTORE_ARCHIVE] Phase1 reload error: {e}")

            if crypto_manager.fernet is None:
                progress_var.set("No key in this archive. Please create a new account.")
                self.root.after(2500, self._build_register_ui)
                return

            progress_var.set("Restoring account database…")
            cloud_sync.restore_from_archive(archive_folder_id, subfolder="appdata",
                                             machine_id=machine_id)

            progress_var.set("Restoring logs…")
            cloud_sync.restore_from_archive(archive_folder_id, subfolder="logs",
                                             machine_id=machine_id)

            progress_var.set("Reloading credentials…")
            try:
                time.sleep(0.5)
                auth.reload()
                time.sleep(0.2)
                auth.reload()
            except Exception as e:
                print(f"[RESTORE_ARCHIVE] auth.reload error: {e}")

            progress_var.set("✓ Restore complete — please sign in.")
            self.root.after(1500, self._build_login_ui)

        threading.Thread(target=_run, daemon=True).start()

    # ══════════════════════════════════════════════════════════════════════
    # LAUNCH MAIN APP
    # ══════════════════════════════════════════════════════════════════════
    def _launch_main_app(self, role, username):
        for widget in self.root.winfo_children():
            widget.destroy()
        app = ProIntegrityGUI(self.root, user_role=role, username=username)

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = LoginWindow()
    app.run()