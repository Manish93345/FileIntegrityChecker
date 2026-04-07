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
# ----------------------------------------------------------------------
# BruteForceGuard (unchanged)
# ----------------------------------------------------------------------
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


# ----------------------------------------------------------------------
# Custom Dialogs (replacing tkinter messagebox)
# ----------------------------------------------------------------------
class CustomDialog:
    """Base class for custom CTkToplevel dialogs."""
    def __init__(self, parent, title, message, dialog_type="info"):
        self.dialog = ctk.CTkToplevel(parent)
        self.dialog.title("")
        self.dialog.geometry("400x220")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        self.dialog.focus_set()
        self.dialog.configure(fg_color="#1e1e1e")

        # Center on parent
        self.dialog.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (self.dialog.winfo_width() // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (self.dialog.winfo_height() // 2)
        self.dialog.geometry(f"+{x}+{y}")

        # Icon and title
        icon_map = {
            "info": ("ℹ️", "#00a8ff"),
            "error": ("⚠️", "#ff4444"),
            "success": ("✅", "#00cc66"),
            "warning": ("⚠️", "#ffaa00")
        }
        icon, color = icon_map.get(dialog_type, ("ℹ️", "#00a8ff"))

        icon_label = ctk.CTkLabel(self.dialog, text=icon, font=("Segoe UI", 36), text_color=color)
        icon_label.pack(pady=(20, 5))

        msg_label = ctk.CTkLabel(self.dialog, text=message, font=("Segoe UI", 12),
                                  wraplength=350, justify="center")
        msg_label.pack(pady=(5, 20), padx=20)

        btn = ctk.CTkButton(self.dialog, text="OK", command=self.dialog.destroy,
                            fg_color=color, hover_color=color, width=100)
        btn.pack(pady=(0, 20))

        self.dialog.protocol("WM_DELETE_WINDOW", self.dialog.destroy)

    def wait(self):
        self.dialog.wait_window()


class SecurityAlertDialog:
    """Specialised dialog for security alerts with blinking effect."""
    def __init__(self, parent, title, message):
        self.dialog = ctk.CTkToplevel(parent)
        self.dialog.title("")
        self.dialog.geometry("450x280")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        self.dialog.focus_set()
        self.dialog.configure(fg_color="#0a0a0a")

        # Center
        self.dialog.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (self.dialog.winfo_width() // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (self.dialog.winfo_height() // 2)
        self.dialog.geometry(f"+{x}+{y}")

        # Header
        header = ctk.CTkFrame(self.dialog, fg_color="#330000", height=40)
        header.pack(fill="x")
        header.pack_propagate(False)

        self.alert_label = ctk.CTkLabel(header, text="⚠ INTRUSION DETECTED ⚠",
                                        font=("Consolas", 12, "bold"),
                                        text_color="#ff4444")
        self.alert_label.pack(expand=True)

        # Main content
        content = ctk.CTkFrame(self.dialog, fg_color="#111111")
        content.pack(fill="both", expand=True, padx=20, pady=20)

        title_label = ctk.CTkLabel(content, text=f"> {title} <",
                                   font=("Consolas", 11, "bold"),
                                   text_color="#ff4444")
        title_label.pack(anchor="w", pady=(0, 10))

        msg_label = ctk.CTkLabel(content, text=message,
                                 font=("Consolas", 10),
                                 text_color="#ffffff",
                                 justify="left",
                                 wraplength=380)
        msg_label.pack(fill="x", pady=(0, 20))

        log_label = ctk.CTkLabel(content,
                                 text="[SYSTEM LOG]: Unauthorized access attempt recorded",
                                 font=("Consolas", 8),
                                 text_color="#888888")
        log_label.pack(anchor="w", pady=(0, 20))

        self.ok_btn = ctk.CTkButton(content, text="[ ACKNOWLEDGE ]",
                                     command=self.destroy_dialog,
                                     fg_color="#220000",
                                     hover_color="#330000",
                                     text_color="#ff4444",
                                     font=("Consolas", 10, "bold"))
        self.ok_btn.pack()

        # Start blinking
        self.blink_after_id = None
        self._blink()

        self.dialog.protocol("WM_DELETE_WINDOW", self.destroy_dialog)

    def _blink(self):
        current = self.alert_label.cget("text_color")
        new = "#ffffff" if current == "#ff4444" else "#ff4444"
        try:
            self.alert_label.configure(text_color=new)
            self.blink_after_id = self.dialog.after(500, self._blink)
        except:
            pass

    def destroy_dialog(self):
        if self.blink_after_id:
            self.dialog.after_cancel(self.blink_after_id)
        self.dialog.destroy()

    def wait(self):
        self.dialog.wait_window()


# ----------------------------------------------------------------------
# Main Login Window
# ----------------------------------------------------------------------
class LoginWindow:
    def __init__(self):
        # self.root = tk.Tk()
        self.root = ctk.CTk()
        self.root.title("FMSecure v2.0 - Security Portal")

        # ── KEY RESILIENCE: Phase 1 local-only init ──────────────────
        # NOTE: We deliberately do NOT call attempt_cloud_recovery_if_needed() here.
        # Cloud recovery requires user consent and a working cloud_sync module.
        # Both of those only come AFTER the detection UI runs.
        #
        # What we DO here: if there are existing users but the local key is missing
        # (and cloud didn't auto-recover during encryption_manager __init__), that's
        # a genuine key-loss scenario for an existing install — warn and clear.
        #
        # Fresh installs (no users) are routed through _check_for_reinstall_backup,
        # which handles the "connect Drive / restore backup" flow properly.
        from core.encryption_manager import crypto_manager
        if not crypto_manager._local_ok and auth.has_users():
            # Key is gone but there ARE registered users — something went wrong.
            # At this point cloud_sync hasn't loaded yet, so we can't recover.
            # Clear corrupt data so the app doesn't crash on every login attempt.
            import tkinter.messagebox as mb
            mb.showwarning(
                "Encryption Key Lost",
                "Your local encryption key could not be loaded.\n\n"
                "If you have a Google Drive backup, you can restore it from the "
                "next screen.\n\nOtherwise a new key will be generated and you "
                "will need to create a new admin account."
            )
            _clear_unreadable_data()
            auth._load_users()   # reload so has_users() reflects the cleared state
        # ────────────────────────────────────────────────────────────
        
        # --- 🚨 INJECT THE WINDOWS TASKBAR ICON ---
        try:
            if getattr(sys, 'frozen', False):
                icon_path = os.path.join(sys._MEIPASS, "assets", "icons", "app_icon.ico")
            else:
                project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                icon_path = os.path.join(project_root, "assets", "icons", "app_icon.ico")
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except Exception:
            pass
            
        # --- START HIDDEN FOR SPLASH SCREEN ---
        self.root.withdraw()
        
        # Dark theme colors
        self.bg_darker = "#050505"
        self.bg_panel = "#111111"
        self.accent_green = "#00ff00"
        self.accent_cyan = "#00ffff"
        self.accent_blue = "#0088ff"
        self.text_primary = "#ffffff"
        self.text_secondary = "#aaaaaa"
        self.border_color = "#333333"
        self.input_bg = "#1a1a1a"
        self.error_red = "#ff4444"
        self.root.geometry("450x650") 
        # self.root.configure(bg="#0a0a0a")
        self.root.configure(fg_color="#0a0a0a")
        self.root.resizable(False, False)
        self.bg_dark = "#0a0a0a"
        
        # Initialize Security Guard
        self.guard = BruteForceGuard(max_attempts=3, lockout_time=30)

        # --- 🚨 HOSTILE RECOVERY BYPASS 🚨 ---
        if "--recovery" in sys.argv:
            recovered_user = "admin"
            for user, data in auth.users.items():
                if data.get("role") == "admin":
                    recovered_user = user
                    break
            self.root.after(100, lambda: self._launch_main_app('admin', recovered_user))
            return 

        # Configure styles & Center Window
        self._center_window()
        # self._configure_styles()

        if not auth.has_users():
            self._show_splash_screen(on_complete=self._check_for_reinstall_backup)
        else:
            self._build_login_ui()
            self._show_splash_screen()

        self._apply_icon()
        

    def _show_splash_screen(self, on_complete=None):
        """Displays a professional full-screen branding splash before the app loads."""
        splash = tk.Toplevel(self.root)
        splash.overrideredirect(True)
        splash.configure(bg="#050505")
    
        width, height = 550, 320
        x = (splash.winfo_screenwidth()  // 2) - (width  // 2)
        y = (splash.winfo_screenheight() // 2) - (height // 2)
        splash.geometry(f"{width}x{height}+{x}+{y}")
    
        canvas = tk.Canvas(splash, width=width, height=height,
                        bg="#050505", highlightthickness=0)
        canvas.pack(fill=tk.BOTH, expand=True)
    
        canvas.create_line(0,        0,        width, 0,        fill=self.accent_blue, width=6)
        canvas.create_line(0,        height-2, width, height-2, fill=self.accent_blue, width=6)
    
        from PIL import Image, ImageTk
        canvas.create_oval(
            width//2 - 100, height//2 - 100,
            width//2 + 100, height//2 + 100,
            fill="#0a0a0a", outline=self.accent_blue, width=2
        )
    
        # Load logo
        try:
            if getattr(sys, 'frozen', False):
                base_path = sys._MEIPASS
            else:
                base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
            logo_path = os.path.join(base_path, "assets", "icons", "app_icon.png")
            img = Image.open(logo_path)
            img = img.resize((260, 260))
            self.logo_img  = ImageTk.PhotoImage(img)
            canvas.logo_img = self.logo_img   # ← FIX: pin to canvas widget, prevents GC
            canvas.create_image(width//2, height//2 - 25, image=self.logo_img)
        except Exception as e:
            print("Logo load error:", e)
    
        load_label = tk.Label(splash, text="Initializing cryptographic vault...",
                            font=('Consolas', 9, 'italic'),
                            bg="#050505", fg=self.accent_cyan)
        load_label.place(relx=0.5, rely=0.85, anchor="center")
    
        bar_y = height - 25
        canvas.create_rectangle(60, bar_y, width-60, bar_y+4, fill="#1a1a1a", outline="")
        progress_bar = canvas.create_rectangle(60, bar_y, 60, bar_y+4,
                                            fill=self.accent_blue, outline="")
    
        loading_steps = [
            ("Loading FileIntegrityMonitor Engine...",  random.randint(500, 1000)),
            ("Booting Asynchronous Telemetry Server...", random.randint(200,  500)),
            ("Verifying RSA/AES Encryption Keys...",    random.randint(600, 1200)),
            ("Injecting CustomTkinter UI Components...", random.randint(300,  700)),
            ("Securing Local Environment...",           random.randint(200,  500)),
        ]
        total_steps       = len(loading_steps)
        current_step_idx  = [0]
    
        def process_next_step():
            if current_step_idx[0] < total_steps:
                text, duration = loading_steps[current_step_idx[0]]
                load_label.config(text=text)
                start_w = 60 + ((width - 120) * (current_step_idx[0]     / total_steps))
                end_w   = 60 + ((width - 120) * ((current_step_idx[0]+1) / total_steps))
                frames      = 15
                frame_delay = duration // frames
    
                def animate_chunk(frame=0):
                    if frame <= frames:
                        cw = start_w + ((end_w - start_w) * (frame / frames))
                        canvas.coords(progress_bar, 60, bar_y, cw, bar_y+4)
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

    def _center_window(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

    # Fixing icon
    def _apply_icon(self, window=None):
        """Set the FMSecure icon on the root or any Toplevel."""
        import sys, os
        try:
            if getattr(sys, 'frozen', False):
                base = sys._MEIPASS
            else:
                base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            icon_path = os.path.join(base, "assets", "icons", "app_icon.ico")
            if os.path.exists(icon_path):
                target = window or self.root
                target.iconbitmap(icon_path)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Custom dialog helpers
    # ------------------------------------------------------------------
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
            # alert.grab_set()
            # dialog.wait()
        except:
            print(f"[Dialog Error]: {e}")

    # ------------------------------------------------------------------
    # Login UI (modern, professional)
    # ------------------------------------------------------------------
    def _build_login_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        # Main container with subtle gradient effect (simulated by frames)
        main_container = ctk.CTkFrame(self.root, fg_color="#0f0f0f")
        main_container.pack(fill="both", expand=True)

        # Scrollable frame for content
        scroll = ctk.CTkScrollableFrame(main_container, fg_color="#0f0f0f")
        scroll.pack(fill="both", expand=True, padx=20, pady=20)

        # Header card
        header_card = ctk.CTkFrame(scroll, fg_color="#1a1a1a", corner_radius=12)
        header_card.pack(fill="x", pady=(0, 20))

        # Terminal-style header bar
        term_bar = ctk.CTkFrame(header_card, fg_color="#002200", height=28, corner_radius=0)
        term_bar.pack(fill="x")
        term_bar.pack_propagate(False)

        # Fake window dots
        dots_frame = ctk.CTkFrame(term_bar, fg_color="#002200")
        dots_frame.place(relx=0.02, rely=0.5, anchor="w")
        for color in ["#ff5f56", "#ffbd2e", "#27c93f"]:
            dot = ctk.CTkLabel(dots_frame, text="●", text_color=color, font=("Segoe UI", 14))
            dot.pack(side="left", padx=2)

        term_label = ctk.CTkLabel(term_bar, text="root@integrity-monitor:~# login_system",
                                   font=("Consolas", 10), text_color="#00ff00")
        term_label.place(relx=0.5, rely=0.5, anchor="center")

        # Main title
        title = ctk.CTkLabel(header_card, text="SYSTEM ACCESS PORTAL",
                              font=("Segoe UI", 22, "bold"), text_color="#00ccff")
        title.pack(pady=(20, 5))

        subtitle = ctk.CTkLabel(header_card, text="[SECURITY LEVEL: MAXIMUM]",
                                 font=("Consolas", 10), text_color="#aaaaaa")
        subtitle.pack(pady=(0, 20))

        # Admin login card
        admin_card = ctk.CTkFrame(scroll, fg_color="#1a1a1a", corner_radius=12)
        admin_card.pack(fill="x", pady=(0, 15))

        admin_header = ctk.CTkLabel(admin_card, text="▸ ADMINISTRATOR LOGIN ◂",
                                     font=("Segoe UI", 14, "bold"), text_color="#00ccff")
        admin_header.pack(anchor="w", padx=25, pady=(20, 10))

        # Username
        user_label = ctk.CTkLabel(admin_card, text="USERNAME", font=("Segoe UI", 10, "bold"),
                                   text_color="#aaaaaa")
        user_label.pack(anchor="w", padx=25)

        self.user_entry = ctk.CTkEntry(admin_card, placeholder_text="Enter your username",
                                        font=("Consolas", 12), fg_color="#2a2a2a",
                                        border_color="#3c3c3c", text_color="#00ff00")
        self.user_entry.pack(fill="x", padx=25, pady=(5, 15))
        self.user_entry.focus()

        # Password
        pass_label = ctk.CTkLabel(admin_card, text="PASSWORD", font=("Segoe UI", 10, "bold"),
                                   text_color="#aaaaaa")
        pass_label.pack(anchor="w", padx=25)

        self.pass_entry = ctk.CTkEntry(admin_card, placeholder_text="Enter your password",
                                        show="•", font=("Consolas", 12),
                                        fg_color="#2a2a2a", border_color="#3c3c3c",
                                        text_color="#00ff00")
        self.pass_entry.pack(fill="x", padx=25, pady=(5, 20))

        # Login button
        self.login_btn = ctk.CTkButton(admin_card, text="[ ACCESS TERMINAL ]",
                                        command=self._attempt_admin_login,
                                        fg_color="#004d00", hover_color="#006600",
                                        text_color="#00ff00", font=("Consolas", 12, "bold"),
                                        corner_radius=8, height=40)
        self.login_btn.pack(fill="x", padx=25, pady=(0, 10))

        # Forgot password
        forgot_row = ctk.CTkFrame(admin_card, fg_color="transparent")
        forgot_row.pack(pady=(0, 15))

        self.forgot_btn = ctk.CTkButton(forgot_row, text="Forgot Password?",
                                        command=self._build_forgot_pass_ui,
                                        fg_color="transparent", text_color="#00ccff",
                                        font=("Segoe UI", 10, "underline"), hover=False)
        self.forgot_btn.pack(side="left", padx=(0, 10))

        ctk.CTkLabel(forgot_row, text="|", text_color="#444444",
                    font=("Segoe UI", 10)).pack(side="left", padx=4)

        ctk.CTkButton(forgot_row, text="Forgot Username?",
                    command=self._build_forgot_username_ui,
                    fg_color="transparent", text_color="#00ccff",
                    font=("Segoe UI", 10, "underline"), hover=False).pack(side="left")

        # Google SSO
        google_btn = ctk.CTkButton(admin_card, text="🌐  Continue with Google",
                                    command=self._handle_google_login,
                                    fg_color="#ffffff", hover_color="#f0f0f0",
                                    text_color="#4285F4", font=("Segoe UI", 11, "bold"),
                                    corner_radius=8, height=40)
        google_btn.pack(fill="x", padx=25, pady=(0, 20))

        # Separator
        sep_frame = ctk.CTkFrame(scroll, fg_color="#0f0f0f", height=20)
        sep_frame.pack(fill="x")
        sep_line = ctk.CTkFrame(sep_frame, fg_color="#333333", height=1)
        sep_line.pack(fill="x", pady=9)
        sep_text = ctk.CTkLabel(sep_frame, text="║  OR  ║", font=("Consolas", 10),
                                 text_color="#aaaaaa")
        sep_text.place(relx=0.5, rely=0.5, anchor="center")

        # Guest card
        guest_card = ctk.CTkFrame(scroll, fg_color="#1a1a1a", corner_radius=12)
        guest_card.pack(fill="x", pady=(15, 20))

        guest_header = ctk.CTkLabel(guest_card, text="▸ RESTRICTED VIEWER ◂",
                                     font=("Segoe UI", 14, "bold"), text_color="#aaaaaa")
        guest_header.pack(anchor="w", padx=25, pady=(20, 5))

        guest_desc = ctk.CTkLabel(guest_card,
                                   text="Read‑only access · No credentials required",
                                   font=("Segoe UI", 10), text_color="#888888")
        guest_desc.pack(anchor="w", padx=25, pady=(0, 15))

        self.guest_btn = ctk.CTkButton(guest_card, text="[ READ‑ONLY MODE ]",
                                        command=self._attempt_guest_login,
                                        fg_color="#2a2a2a", hover_color="#3a3a3a",
                                        text_color="#aaaaaa", font=("Consolas", 11),
                                        corner_radius=8, height=40)
        self.guest_btn.pack(fill="x", padx=25, pady=(0, 25))

        # Info card
        info_card = ctk.CTkFrame(scroll, fg_color="#002233", corner_radius=8)
        info_card.pack(fill="x", pady=(0, 20))

        info_text = ctk.CTkLabel(info_card,
                                  text="⚠ NOTE: All login attempts are logged and monitored.\n"
                                       "Unauthorized access will trigger security protocols.",
                                  font=("Consolas", 9), text_color="#00ccff", justify="left")
        info_text.pack(padx=15, pady=15)

        # Status bar
        status_bar = ctk.CTkFrame(self.root, fg_color="#050505", height=30, corner_radius=0)
        status_bar.pack(fill="x", side="bottom")

        status_label = ctk.CTkLabel(status_bar,
                                     text="System: Online | Security: Active | Connection: Encrypted",
                                     font=("Consolas", 8), text_color="#00ff00")
        status_label.pack(side="left", padx=10)

        version_label = ctk.CTkLabel(status_bar, text="v1.0.0",
                                      font=("Consolas", 8), text_color="#aaaaaa")
        version_label.pack(side="right", padx=10)

        # Bind Enter key
        self.root.bind('<Return>', lambda e: self._attempt_admin_login())

    # ------------------------------------------------------------------
    # Registration UI (first time)
    # ------------------------------------------------------------------
    def _build_register_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        # Card-like container
        main_card = ctk.CTkFrame(self.root, fg_color="#1e1e1e", corner_radius=16)
        main_card.pack(expand=True, fill="both", padx=40, pady=40)

        from PIL import Image, ImageTk
        import sys, os

        def resource_path(path):
            if getattr(sys, 'frozen', False):
                return os.path.join(sys._MEIPASS, path)
            return os.path.join(os.path.abspath("."), path)

        try:
            logo_path = resource_path("assets/icons/app_icon.png")

            img = Image.open(logo_path)
            self.register_logo = ctk.CTkImage(
                light_image=img,
                dark_image=img,
                size=(120, 120)
            )
            logo_label = ctk.CTkLabel(main_card, image=self.register_logo, text="")
            logo_label.pack(pady=(30, 10))

        except Exception as e:
            print("Register logo error:", e)

        title = ctk.CTkLabel(main_card, text="First‑Time Setup",
                              font=("Segoe UI", 24, "bold"), text_color="#ffffff")
        title.pack()

        subtitle = ctk.CTkLabel(main_card, text="Register your admin account to continue",
                                 font=("Segoe UI", 12), text_color="#a0a0a0")
        subtitle.pack(pady=(0, 25))

        # Input fields
        self.reg_user_entry = self._create_input(main_card, "Username:", default="admin")
        self.reg_email_entry = self._create_input(main_card, "Registered Email:")
        self.reg_pass_entry = self._create_input(main_card, "Password:", is_password=True)
        self.reg_confirm_entry = self._create_input(main_card, "Confirm Password:", is_password=True)

        # Register button (Assigned to self.reg_btn)
        self.reg_btn = ctk.CTkButton(main_card, text="Create Account", command=self._attempt_register,
                      font=("Segoe UI", 14, "bold"), fg_color="#00a8ff", hover_color="#0077cc",
                      corner_radius=8, height=45)
        self.reg_btn.pack(fill="x", padx=40, pady=(20, 10))

        # Google SSO (Assigned to self.google_btn)
        self.google_btn = ctk.CTkButton(main_card, text="🌐  Sign up with Google",
                      command=lambda: self._handle_google_login(mode="register"),
                      fg_color="#ffffff", hover_color="#f0f0f0",
                      text_color="#4285F4", font=("Segoe UI", 12, "bold"),
                      corner_radius=8, height=45)
        self.google_btn.pack(fill="x", padx=40, pady=(0, 30))

    def _create_input(self, parent, label_text, is_password=False, default=""):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.pack(fill="x", padx=40, pady=5)
        lbl = ctk.CTkLabel(frame, text=label_text, font=("Segoe UI", 11), text_color="#a0a0a0")
        lbl.pack(anchor="w")
        entry = ctk.CTkEntry(frame, font=("Segoe UI", 13), show="•" if is_password else "",
                              fg_color="#2b2b2b", border_color="#3c3c3c")
        if default:
            entry.insert(0, default)
        entry.pack(fill="x", pady=(2, 0))
        return entry

    def _attempt_register(self):
        # 1. Check if already processing BEFORE grabbing values
        if getattr(self, 'is_processing', False):
            return
        self.is_processing = True

        username = self.reg_user_entry.get().strip()
        email = self.reg_email_entry.get().strip().lower()
        password = self.reg_pass_entry.get()
        confirm = self.reg_confirm_entry.get()

        # 2. Mandatory Fields
        if not username or not email or not password or not confirm:
            self.show_error("All fields are mandatory.")
            self.is_processing = False  # Reset flag so they can try again
            return

        # 3. Email Validation
        email_pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        if not re.match(email_pattern, email):
            self.show_error("Invalid email format. Use: user@domain.com")
            self.is_processing = False  # Reset flag
            return

        # 4. Password Match
        if password != confirm:
            self.show_error("Passwords do not match.")
            self.is_processing = False  # Reset flag
            return

        # 5. Password Length
        if len(password) < 6:
            self.show_error("Password must be at least 6 characters long.")
            self.is_processing = False  # Reset flag
            return

        # ✅ Disable UI
        self._set_ui_state("disabled")
        self.root.config(cursor="watch")

        # Loader UI
        loader = ctk.CTkToplevel(self.root)
        loader.overrideredirect(True)
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - 100
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - 40
        loader.geometry(f"200x80+{x}+{y}")
        loader.configure(fg_color="#1e1e1e")
        self._apply_icon(loader)

        ctk.CTkLabel(
            loader,
            text="⏳ Sending OTP...",
            font=("Segoe UI", 12, "bold"),
            text_color="#00a8ff"
        ).pack(expand=True)

        loader.update()

        # Thread task
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

                    #  IMPORTANT: UI enable mat karo yaha
                    # kyunki ab OTP screen aa rahi hai
                    self._build_otp_ui(username, email, password)

                else:
                    self.show_error(f"Failed to send OTP.\n\n{msg}")
                    self.is_processing = False
                    self._set_ui_state("normal")  # ✅ only on failure

            self.root.after(0, _update_gui)

        threading.Thread(target=_send_email_task, daemon=True).start()

    def _set_ui_state(self, state="normal"):
        """Toggles buttons to prevent double-clicks during processing"""
        target_state = "normal" if state == "normal" else "disabled"
        
        # List of buttons to disable
        buttons = [
            "login_btn",
            "reg_btn",
            "google_btn",
            "viewer_btn"
        ]
        
        for btn_name in buttons:
            if hasattr(self, btn_name):
                try:
                    getattr(self, btn_name).configure(state=target_state)
                except:
                    pass

    def _build_otp_ui(self, username, email, password):
        self.is_processing = False
        for widget in self.root.winfo_children():
            widget.destroy()

        main_card = ctk.CTkFrame(self.root, fg_color="#1e1e1e", corner_radius=16)
        main_card.pack(expand=True, fill="both", padx=40, pady=40)

        ctk.CTkLabel(main_card, text="📧", font=("Segoe UI", 48), text_color="#00a8ff").pack(pady=(30, 10))
        ctk.CTkLabel(main_card, text="Verify Your Email",
                     font=("Segoe UI", 24, "bold"), text_color="#ffffff").pack()
        ctk.CTkLabel(main_card, text=f"Enter the 6‑digit code sent to\n{email}",
                     font=("Segoe UI", 12), text_color="#a0a0a0", justify="center").pack(pady=(0, 20))

        self.otp_entry = ctk.CTkEntry(main_card, font=("Segoe UI", 20, "bold"),
                                       justify="center", width=200)
        self.otp_entry.pack(pady=5)

        def verify_and_create():
            otp = self.otp_entry.get().strip()
            if not otp:
                self.show_error("Please enter the OTP.")
                return
            is_valid, msg = email_service.verify_otp(email, otp)
            if is_valid:
                success, auth_msg = auth.register_user(username, email, password, role="admin")
                if success:
                    self.show_success("Account created successfully! You can now log in.")
                    self._build_login_ui()
                else:
                    self.show_error(auth_msg)
            else:
                self.show_error(msg)

        ctk.CTkButton(main_card, text="Verify & Create Account", command=verify_and_create,
                      font=("Segoe UI", 14, "bold"), fg_color="#00a8ff", hover_color="#0077cc",
                      corner_radius=8, height=45).pack(fill="x", padx=40, pady=(20, 10))
        ctk.CTkButton(main_card, text="Cancel & Go Back", command=self._build_register_ui,
                      font=("Segoe UI", 11), fg_color="transparent", text_color="#a0a0a0",
                      hover=False).pack(pady=(0, 30))

    def _build_forgot_username_ui(self):
        """Recover username by looking it up against the registered email."""
        for widget in self.root.winfo_children():
            widget.destroy()

        main_card = ctk.CTkFrame(self.root, fg_color="#1e1e1e", corner_radius=16)
        main_card.pack(expand=True, fill="both", padx=40, pady=40)

        ctk.CTkLabel(main_card, text="👤", font=("Segoe UI", 48),
                    text_color="#00a8ff").pack(pady=(30, 10))
        ctk.CTkLabel(main_card, text="Recover Your Username",
                    font=("Segoe UI", 22, "bold"), text_color="#ffffff").pack()
        ctk.CTkLabel(main_card,
                    text="Enter the email address you registered with.\nWe'll tell you the username linked to that email.",
                    font=("Segoe UI", 11), text_color="#a0a0a0",
                    justify="center").pack(pady=(6, 20))

        email_frame = ctk.CTkFrame(main_card, fg_color="transparent")
        email_frame.pack(fill="x", padx=40, pady=5)
        ctk.CTkLabel(email_frame, text="REGISTERED EMAIL",
                    font=("Segoe UI", 10, "bold"),
                    text_color="#aaaaaa").pack(anchor="w")
        self._fu_email_entry = ctk.CTkEntry(
            email_frame, font=("Segoe UI", 13),
            fg_color="#2b2b2b", border_color="#3c3c3c",
            placeholder_text="you@example.com")
        self._fu_email_entry.pack(fill="x", pady=(4, 0))
        self._fu_email_entry.focus()

        self._fu_status = ctk.CTkLabel(main_card, text="",
                                        font=("Segoe UI", 10),
                                        text_color="#ff4444", wraplength=340)
        self._fu_status.pack(pady=(8, 0))

        def _lookup():
            email = self._fu_email_entry.get().strip().lower()
            if not email or "@" not in email:
                self._fu_status.configure(text="Please enter a valid email address.",
                                        text_color="#ff4444")
                return

            found_username = None
            for username, data in auth.users.items():
                if data.get("registered_email", "").lower() == email:
                    found_username = username
                    break

            if not found_username:
                self._fu_status.configure(
                    text="No account found with that email.\n"
                        "Double-check the address or contact support.",
                    text_color="#ff4444")
                return

            # Found — send OTP to confirm identity before revealing username
            lookup_btn.configure(state="disabled", text="Sending code…")
            self._fu_status.configure(text="", text_color="#aaaaaa")

            def _send_otp():
                success, msg = email_service.send_otp_email(email, "verification")

                def _after():
                    lookup_btn.configure(state="normal", text="Look Up Username")
                    if success:
                        self._build_username_otp_ui(found_username, email)
                    else:
                        self._fu_status.configure(
                            text=f"Could not send verification code:\n{msg}",
                            text_color="#ff4444")

                self.root.after(0, _after)

            import threading
            threading.Thread(target=_send_otp, daemon=True).start()

        lookup_btn = ctk.CTkButton(
            main_card, text="Look Up Username",
            command=_lookup,
            font=("Segoe UI", 13, "bold"),
            fg_color="#00a8ff", hover_color="#0077cc",
            corner_radius=8, height=44)
        lookup_btn.pack(fill="x", padx=40, pady=(18, 10))

        ctk.CTkButton(main_card, text="< Back to Login",
                    command=self._build_login_ui,
                    font=("Segoe UI", 11), fg_color="transparent",
                    text_color="#a0a0a0", hover=False).pack(pady=(0, 30))

        self.root.bind('<Return>', lambda e: _lookup())


    def _build_username_otp_ui(self, username: str, email: str):
        """OTP confirmation screen before revealing the username."""
        for widget in self.root.winfo_children():
            widget.destroy()

        main_card = ctk.CTkFrame(self.root, fg_color="#1e1e1e", corner_radius=16)
        main_card.pack(expand=True, fill="both", padx=40, pady=40)

        ctk.CTkLabel(main_card, text="📧", font=("Segoe UI", 48),
                    text_color="#00a8ff").pack(pady=(30, 10))
        ctk.CTkLabel(main_card, text="Verify Your Identity",
                    font=("Segoe UI", 22, "bold"), text_color="#ffffff").pack()
        ctk.CTkLabel(main_card,
                    text=f"Enter the 6-digit code sent to:\n{email}",
                    font=("Segoe UI", 11), text_color="#a0a0a0",
                    justify="center").pack(pady=(6, 20))

        self._fu_otp_entry = ctk.CTkEntry(
            main_card, font=("Segoe UI", 22, "bold"),
            justify="center", width=180,
            placeholder_text="000000")
        self._fu_otp_entry.pack(pady=5)
        self._fu_otp_entry.focus()

        self._fu_otp_status = ctk.CTkLabel(main_card, text="",
                                            font=("Segoe UI", 10),
                                            text_color="#ff4444")
        self._fu_otp_status.pack(pady=(6, 0))

        def _verify():
            otp = self._fu_otp_entry.get().strip()
            if not otp:
                self._fu_otp_status.configure(text="Please enter the OTP.")
                return

            is_valid, msg = email_service.verify_otp(email, otp)

            if is_valid:
                # OTP passed — show the username in a success screen
                self._build_username_revealed_ui(username, email)
            else:
                self._fu_otp_status.configure(text=msg, text_color="#ff4444")
                self._fu_otp_entry.delete(0, "end")

        ctk.CTkButton(main_card, text="Verify & Show Username",
                    command=_verify,
                    font=("Segoe UI", 13, "bold"),
                    fg_color="#00a8ff", hover_color="#0077cc",
                    corner_radius=8, height=44).pack(
            fill="x", padx=40, pady=(18, 10))

        ctk.CTkButton(main_card, text="< Back",
                    command=self._build_forgot_username_ui,
                    font=("Segoe UI", 11), fg_color="transparent",
                    text_color="#a0a0a0", hover=False).pack(pady=(0, 30))

        self.root.bind('<Return>', lambda e: _verify())


    def _build_username_revealed_ui(self, username: str, email: str):
        """Show the recovered username and offer to go straight to login."""
        for widget in self.root.winfo_children():
            widget.destroy()

        main_card = ctk.CTkFrame(self.root, fg_color="#1e1e1e", corner_radius=16)
        main_card.pack(expand=True, fill="both", padx=40, pady=40)

        ctk.CTkLabel(main_card, text="✅", font=("Segoe UI", 52),
                    text_color="#00cc66").pack(pady=(30, 10))
        ctk.CTkLabel(main_card, text="Username Found",
                    font=("Segoe UI", 22, "bold"), text_color="#ffffff").pack()
        ctk.CTkLabel(main_card,
                    text=f"The account registered to\n{email}\n\nis:",
                    font=("Segoe UI", 11), text_color="#a0a0a0",
                    justify="center").pack(pady=(8, 12))

        # Big username display box
        name_box = ctk.CTkFrame(main_card, fg_color="#002233",
                                corner_radius=10)
        name_box.pack(padx=40, pady=(0, 20))
        ctk.CTkLabel(name_box, text=username,
                    font=("Consolas", 26, "bold"),
                    text_color="#00ccff").pack(padx=30, pady=16)

        # Copy to clipboard button
        def _copy():
            self.root.clipboard_clear()
            self.root.clipboard_append(username)
            copy_btn.configure(text="✔  Copied!")
            self.root.after(2000, lambda: copy_btn.configure(text="📋  Copy Username"))

        copy_btn = ctk.CTkButton(main_card, text="📋  Copy Username",
                                command=_copy,
                                font=("Segoe UI", 11),
                                fg_color="#2b2b2b", hover_color="#3a3a3a",
                                text_color="#00ccff",
                                corner_radius=8, height=36)
        copy_btn.pack(fill="x", padx=60, pady=(0, 10))

        ctk.CTkButton(main_card, text="Go to Login →",
                    command=self._build_login_ui,
                    font=("Segoe UI", 13, "bold"),
                    fg_color="#00a8ff", hover_color="#0077cc",
                    corner_radius=8, height=44).pack(
            fill="x", padx=40, pady=(6, 10))

        ctk.CTkButton(main_card, text="Forgot Password Too?",
                    command=self._build_forgot_pass_ui,
                    font=("Segoe UI", 10), fg_color="transparent",
                    text_color="#888888", hover=False).pack(pady=(0, 30))

    # ------------------------------------------------------------------
    # Login attempts
    # ------------------------------------------------------------------
    def _attempt_admin_login(self):
        is_locked, wait_time = self.guard.is_locked_out()
        if is_locked:
            self.show_security_alert(
                "SYSTEM LOCKDOWN",
                f"Too many failed login attempts.\n\nSecurity protocols have locked this terminal.\nPlease wait {wait_time} seconds before retrying."
            )
            return

        username = self.user_entry.get().strip()
        password = self.pass_entry.get().strip()

        if not username or not password:
            self.show_security_alert(
                "MISSING CREDENTIALS",
                "Username and password fields cannot be empty.\nPlease provide valid administrator credentials."
            )
            return

        success, role, msg = auth.login(username, password)

        if success:
            if role != 'admin':
                self.show_security_alert(
                    "UNAUTHORIZED ROLE",
                    "This terminal is reserved for ADMINISTRATOR access only.\nYour account does not have sufficient privileges."
                )
                return
            self.guard.reset()
            # self.root.quit()
            # self.root.destroy()
            self._launch_main_app(role, username)   # Reuse root, no destroy
        else:
            attempts = self.guard.register_failed_attempt()
            remaining = self.guard.max_attempts - attempts

            if remaining > 0:
                self.show_security_alert(
                    "ACCESS DENIED",
                    f"Authentication failed: {msg}\n\nWARNING: {remaining} attempts remaining before system lockdown."
                )
            else:
                self.show_security_alert(
                    "SECURITY ALERT",
                    "Maximum attempts reached.\nSystem locked for 30 seconds."
                )

            self.pass_entry.delete(0, tk.END)

    def _attempt_guest_login(self):
        self._launch_main_app(role='user', username='RestrictedViewer')

    # ------------------------------------------------------------------
    # Forgot password
    # ------------------------------------------------------------------
    def _build_forgot_pass_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        main_card = ctk.CTkFrame(self.root, fg_color="#1e1e1e", corner_radius=16)
        main_card.pack(expand=True, fill="both", padx=40, pady=40)

        ctk.CTkLabel(main_card, text="🔐", font=("Segoe UI", 48), text_color="#00a8ff").pack(pady=(30, 10))
        ctk.CTkLabel(main_card, text="Password Recovery",
                     font=("Segoe UI", 24, "bold"), text_color="#ffffff").pack()
        ctk.CTkLabel(main_card, text="Enter your registered email address",
                     font=("Segoe UI", 12), text_color="#a0a0a0").pack(pady=(0, 20))

        self.fp_email_entry = ctk.CTkEntry(main_card, font=("Segoe UI", 13), width=300)
        self.fp_email_entry.pack(pady=5)

        def send_reset_code():
            email = self.fp_email_entry.get().strip().lower()
            if not email:
                self.show_error("Please enter your email.")
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
            x = self.root.winfo_x() + (self.root.winfo_width() // 2) - 125
            y = self.root.winfo_y() + (self.root.winfo_height() // 2) - 40
            loader.geometry(f"250x80+{x}+{y}")
            loader.configure(fg_color="#111111")
            ctk.CTkLabel(loader, text="⏳ Routing Secure OTP...",
                         font=("Consolas", 11, "bold"), text_color="#00ff00").pack(expand=True)
            loader.update()
            self._apply_icon(loader)

            def _send_reset_task():
                success, msg = email_service.send_otp_email(email, "reset")
                def _update_gui():
                    self.root.config(cursor="")
                    loader.destroy()
                    if success:
                        self.show_success(f"A password reset code has been sent to {email}")
                        self._build_reset_pass_ui(target_username, email)
                    else:
                        self.show_error(msg)
                self.root.after(0, _update_gui)

            threading.Thread(target=_send_reset_task, daemon=True).start()

        ctk.CTkButton(main_card, text="[ SEND RECOVERY CODE ]", command=send_reset_code,
                      font=("Consolas", 12, "bold"), fg_color="#004d00", hover_color="#006600",
                      text_color="#00ff00", corner_radius=8, height=45).pack(fill="x", padx=40, pady=(20, 10))
        ctk.CTkButton(main_card, text="< Back to Login", command=self._build_login_ui,
                      font=("Segoe UI", 11), fg_color="transparent", text_color="#a0a0a0",
                      hover=False).pack(pady=(0, 30))

    def _build_reset_pass_ui(self, username, email):
        for widget in self.root.winfo_children():
            widget.destroy()

        main_card = ctk.CTkFrame(self.root, fg_color="#1e1e1e", corner_radius=16)
        main_card.pack(expand=True, fill="both", padx=40, pady=40)

        ctk.CTkLabel(main_card, text="🔓", font=("Segoe UI", 48), text_color="#00ff00").pack(pady=(30, 10))
        ctk.CTkLabel(main_card, text="Reset Password",
                     font=("Segoe UI", 24, "bold"), text_color="#ffffff").pack()
        ctk.CTkLabel(main_card, text=f"Account: {username}",
                     font=("Consolas", 12), text_color="#00ff00").pack(pady=(0, 20))

        # OTP
        otp_frame = ctk.CTkFrame(main_card, fg_color="transparent")
        otp_frame.pack(fill="x", padx=40, pady=5)
        ctk.CTkLabel(otp_frame, text="6‑Digit OTP Code:", font=("Segoe UI", 11),
                     text_color="#a0a0a0").pack(anchor="w")
        self.rp_otp_entry = ctk.CTkEntry(otp_frame, font=("Consolas", 13),
                                          fg_color="#2b2b2b", border_color="#3c3c3c")
        self.rp_otp_entry.pack(fill="x", pady=(2, 0))

        # New password
        pass_frame = ctk.CTkFrame(main_card, fg_color="transparent")
        pass_frame.pack(fill="x", padx=40, pady=5)
        ctk.CTkLabel(pass_frame, text="New Password:", font=("Segoe UI", 11),
                     text_color="#a0a0a0").pack(anchor="w")
        self.rp_pass_entry = ctk.CTkEntry(pass_frame, show="•", font=("Consolas", 13),
                                           fg_color="#2b2b2b", border_color="#3c3c3c")
        self.rp_pass_entry.pack(fill="x", pady=(2, 0))

        # Confirm
        confirm_frame = ctk.CTkFrame(main_card, fg_color="transparent")
        confirm_frame.pack(fill="x", padx=40, pady=5)
        ctk.CTkLabel(confirm_frame, text="Confirm Password:", font=("Segoe UI", 11),
                     text_color="#a0a0a0").pack(anchor="w")
        self.rp_confirm_entry = ctk.CTkEntry(confirm_frame, show="•", font=("Consolas", 13),
                                              fg_color="#2b2b2b", border_color="#3c3c3c")
        self.rp_confirm_entry.pack(fill="x", pady=(2, 0))

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
                    self.show_success("Password reset successfully! You can now log in.")
                    self._build_login_ui()
                else:
                    self.show_error(auth_msg)
            else:
                self.show_error(msg)

        ctk.CTkButton(main_card, text="[ COMMIT NEW PASSWORD ]", command=execute_reset,
                      font=("Consolas", 12, "bold"), fg_color="#004d00", hover_color="#006600",
                      text_color="#00ff00", corner_radius=8, height=45).pack(fill="x", padx=40, pady=(20, 10))
        ctk.CTkButton(main_card, text="Cancel", command=self._build_login_ui,
                      font=("Segoe UI", 11), fg_color="transparent", text_color="#a0a0a0",
                      hover=False).pack(pady=(0, 30))

    # ------------------------------------------------------------------
    # Google SSO
    # ------------------------------------------------------------------
    def _handle_google_login(self, mode="login"):
        """
        Opens Google OAuth in the browser.
        mode = "register"  →  first-time account creation via Google
        mode = "login"     →  returning user login (allowlist check applies)
        """
        self.root.config(cursor="watch")
        self.root.update()
        self._google_mode = mode  # store mode so _process_google_result can read it
 
        def _auth_thread():
            from core.google_auth import authenticate_google_sso
            success, result = authenticate_google_sso()
            self.root.after(0, lambda: self._process_google_result(success, result))
 
        threading.Thread(target=_auth_thread, daemon=True).start()

    def _process_google_result(self, success, result):
        """
        Called after Google OAuth completes.
 
        REGISTRATION mode (mode="register"):
            - Google verifies identity.
            - We auto-fill the email from Google.
            - If the email is ALREADY registered → redirect to login (no duplicate).
            - If the email is NEW → show PIN setup → create account.
 
        LOGIN mode (mode="login"):
            - GAP 2 FIX: Email allowlist — only registered emails pass.
            - GAP 1 FIX: Device PIN required to confirm physical presence.
        """
        self.root.config(cursor="")
        mode = getattr(self, '_google_mode', 'login')
 
        if not success:
            self.show_error(result)
            return
 
        email = result['email']
        name  = result['name']
 
        is_registered, existing_username = auth.is_google_email_registered(email)
 
        # ── REGISTRATION MODE ─────────────────────────────────────────────
        if mode == "register":
            if is_registered:
                # Account already exists — just log them in instead
                self.show_info(
                    f"{email} is already registered.\n\n"
                    "Taking you to login instead."
                )
                # Route through normal login PIN flow
                if auth.has_sso_pin(existing_username):
                    self._build_sso_pin_verify_ui(existing_username, name)
                else:
                    self._build_sso_pin_setup_ui(existing_username, name)
            else:
                # Brand new user — derive a username from the email local-part
                import uuid as _uuid
                base_username = email.split('@')[0]
                # Make username unique if somehow it collides with a manual user
                username = base_username
                counter  = 1
                while username in auth.users:
                    username = f"{base_username}{counter}"
                    counter += 1
 
                # Register silently with a random password (they'll use PIN + Google)
                dummy_pass = _uuid.uuid4().hex
                auth.register_user(
                    username, email, dummy_pass,
                    role="admin", auth_method="google"
                )
                auth._save_db()
 
                # Now ask them to set a device PIN
                self._build_sso_pin_setup_ui(username, name)
 
        # ── LOGIN MODE ────────────────────────────────────────────────────
        else:
            # GAP 2: Reject any Google account not in our system
            if not is_registered:
                self.show_error(
                    f"Access Denied.\n\n"
                    f"{email} is not registered in FMSecure.\n\n"
                    "Only pre-registered accounts can sign in with Google.\n"
                    "Please use 'Create Account' on the registration screen first."
                )
                return
 
            # GAP 1: PIN gate
            if auth.has_sso_pin(existing_username):
                self._build_sso_pin_verify_ui(existing_username, name)
            else:
                # Registered via Google but PIN was never set (edge case)
                self._build_sso_pin_setup_ui(existing_username, name)

    def _build_sso_pin_setup_ui(self, username, name):
        """
        First Google login — ask the user to create a 4-digit device PIN.
        This PIN proves physical presence on this device every future login.
        """
        for widget in self.root.winfo_children():
            widget.destroy()
 
        main_card = ctk.CTkFrame(self.root, fg_color="#1e1e1e", corner_radius=16)
        main_card.pack(expand=True, fill="both", padx=40, pady=40)
 
        ctk.CTkLabel(main_card, text="🔐", font=("Segoe UI", 48),
                     text_color="#00a8ff").pack(pady=(30, 10))
 
        ctk.CTkLabel(main_card, text=f"Welcome, {name}!",
                     font=("Segoe UI", 22, "bold"),
                     text_color="#ffffff").pack()
 
        ctk.CTkLabel(main_card,
                     text="Google identity verified.\n\n"
                          "Set a 4-digit device PIN.\n"
                          "You will enter this PIN every time\n"
                          "you sign in with Google on this device.",
                     font=("Segoe UI", 12), text_color="#a0a0a0",
                     justify="center").pack(pady=(8, 20))
 
        ctk.CTkLabel(main_card, text="NEW DEVICE PIN (4+ digits)",
                     font=("Segoe UI", 10, "bold"),
                     text_color="#aaaaaa").pack(anchor="w", padx=40)
 
        self._pin_entry = ctk.CTkEntry(
            main_card, show="●",
            font=("Segoe UI", 18, "bold"),
            justify="center", width=160)
        self._pin_entry.pack(pady=(4, 16))
        self._pin_entry.focus()
 
        ctk.CTkLabel(main_card, text="CONFIRM PIN",
                     font=("Segoe UI", 10, "bold"),
                     text_color="#aaaaaa").pack(anchor="w", padx=40)
 
        self._pin_confirm_entry = ctk.CTkEntry(
            main_card, show="●",
            font=("Segoe UI", 18, "bold"),
            justify="center", width=160)
        self._pin_confirm_entry.pack(pady=(4, 24))
 
        def _save_pin():
            pin     = self._pin_entry.get().strip()
            confirm = self._pin_confirm_entry.get().strip()
 
            if not pin or not confirm:
                self.show_error("Both PIN fields are required.")
                return
            if pin != confirm:
                self.show_error("PINs do not match. Please try again.")
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
                self.show_success(
                    "Device PIN set!\n\n"
                    "You are now logged in.\n"
                    "Use this PIN next time you sign in with Google."
                )
                self._launch_main_app(role="admin", username=username)
            else:
                self.show_error(msg)
 
        ctk.CTkButton(
            main_card, text="Set PIN & Continue",
            command=_save_pin,
            fg_color="#004d00", hover_color="#006600",
            text_color="#00ff00", font=("Consolas", 12, "bold"),
            corner_radius=8, height=40
        ).pack(fill="x", padx=40, pady=(0, 10))
 
        ctk.CTkButton(
            main_card, text="Cancel",
            command=self._build_login_ui,
            font=("Segoe UI", 11), fg_color="transparent",
            text_color="#a0a0a0", hover=False
        ).pack(pady=(0, 20))
 
        self.root.bind('<Return>', lambda e: _save_pin())
 
    def _build_sso_pin_verify_ui(self, username, name):
        """
        Returning Google user — verify device PIN to confirm physical presence.
        Also used as the credential check for sensitive actions (Gap 3 fix).
        """
        for widget in self.root.winfo_children():
            widget.destroy()
 
        main_card = ctk.CTkFrame(self.root, fg_color="#1e1e1e", corner_radius=16)
        main_card.pack(expand=True, fill="both", padx=40, pady=40)
 
        ctk.CTkLabel(main_card, text="🛡️", font=("Segoe UI", 48),
                     text_color="#00a8ff").pack(pady=(30, 10))
 
        ctk.CTkLabel(main_card, text=f"Welcome back, {name}!",
                     font=("Segoe UI", 22, "bold"),
                     text_color="#ffffff").pack()
 
        ctk.CTkLabel(main_card,
                     text="Google identity verified.\n\n"
                          "Enter your device PIN to complete sign-in.",
                     font=("Segoe UI", 12), text_color="#a0a0a0",
                     justify="center").pack(pady=(8, 20))
 
        ctk.CTkLabel(main_card, text="DEVICE PIN",
                     font=("Segoe UI", 10, "bold"),
                     text_color="#aaaaaa").pack(anchor="w", padx=40)
 
        self._verify_pin_entry = ctk.CTkEntry(
            main_card, show="●",
            font=("Segoe UI", 20, "bold"),
            justify="center", width=160)
        self._verify_pin_entry.pack(pady=(4, 24))
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
                        "DEVICE PIN LOCKED",
                        "3 incorrect PINs entered.\n\n"
                        "Returned to the login screen for security."
                    )
                    self._build_login_ui()
                else:
                    remaining = 3 - self._pin_attempts
                    self.show_error(
                        f"Incorrect PIN.\n\n"
                        f"{remaining} attempt(s) remaining before lockout."
                    )
 
        ctk.CTkButton(
            main_card, text="[ VERIFY PIN ]",
            command=_verify_pin,
            fg_color="#004d00", hover_color="#006600",
            text_color="#00ff00", font=("Consolas", 12, "bold"),
            corner_radius=8, height=40
        ).pack(fill="x", padx=40, pady=(0, 10))
 
        ctk.CTkButton(
            main_card, text="Cancel",
            command=self._build_login_ui,
            font=("Segoe UI", 11), fg_color="transparent",
            text_color="#a0a0a0", hover=False
        ).pack(pady=(0, 20))
 
        self.root.bind('<Return>', lambda e: _verify_pin())


    def _check_for_reinstall_backup(self):
        """
        Called after splash on a fresh install (no local users.dat).

        PATTERN (industry-standard, WhatsApp-style):
          1. If a cached OAuth token exists  → probe Drive silently (no user friction).
          2. If NO token                     → show a gateway screen offering the
             user the choice to connect Google Drive OR skip and create a new account.
             This handles the "full AppData wipe" scenario cleanly.

        Never silently fall through to register without giving the user the chance
        to recover their cloud backup.
        """
        from core.utils import get_app_data_dir

        # Existing users present — nothing to detect, show login UI directly
        if auth.has_users():
            self._build_login_ui()
            return

        token_path = os.path.join(get_app_data_dir(), "token.pickle")
        if os.path.exists(token_path):
            # Token cached — probe Drive silently, no user friction
            self._build_cloud_probe_ui()
            self._start_drive_probe()
        else:
            # No cached token — show gateway: connect Drive or skip
            self._build_cloud_gateway_ui()

    def _start_drive_probe(self):
        """Background Drive probe — called when token.pickle already exists."""
        def _probe():
            try:
                from core.cloud_sync import cloud_sync
                from core.encryption_manager import crypto_manager

                if not cloud_sync.is_active:
                    # Token exists but auth failed (expired/revoked) — offer gateway
                    self.root.after(0, self._build_cloud_gateway_ui)
                    return

                self._run_backup_probe(cloud_sync, crypto_manager)

            except Exception as e:
                print(f"[LOGIN] Drive probe error (non-critical): {e}")
                self.root.after(0, self._build_register_ui)

        import threading
        threading.Thread(target=_probe, daemon=True).start()

    def _run_backup_probe(self, cloud_sync, crypto_manager):
        """
        Core probe logic — shared by both the silent path (token cached) and
        the interactive path (user just authenticated). Runs on a background thread;
        schedules all UI updates via root.after().
        """
        try:
            machine_id  = crypto_manager.get_machine_id()
            backup_info = cloud_sync.check_backup_exists(machine_id)
            archives    = cloud_sync.list_archives(machine_id)

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
        """
        Gateway screen shown when there is no cached OAuth token.
        Gives the user a clear choice: connect Drive to check for a backup,
        or skip and create a new account.
        Industry pattern: never silently skip past potential data recovery.
        """
        for widget in self.root.winfo_children():
            widget.destroy()

        card = ctk.CTkFrame(self.root, fg_color="#1e1e1e", corner_radius=16)
        card.pack(expand=True, fill="both", padx=30, pady=30)

        # Header
        ctk.CTkLabel(card, text="☁", font=("Segoe UI", 48),
                     text_color="#00a8ff").pack(pady=(28, 8))
        ctk.CTkLabel(card, text="Check for Previous Installation",
                     font=("Segoe UI", 18, "bold"), text_color="#ffffff").pack()
        ctk.CTkLabel(card,
                     text="If you had FMSecure installed before, your data may\n"
                          "be recoverable from your Google Drive backup.",
                     font=("Segoe UI", 10), text_color="#a0a0a0",
                     justify="center").pack(pady=(6, 20))

        # Info box
        info = ctk.CTkFrame(card, fg_color="#002233", corner_radius=8)
        info.pack(fill="x", padx=30, pady=(0, 20))
        ctk.CTkLabel(info,
                     text="ℹ  Connecting Google Drive lets FMSecure look for\n"
                          "     your encrypted backup, accounts, logs, and settings.",
                     font=("Segoe UI", 9), text_color="#00ccff",
                     justify="left").pack(padx=14, pady=12)

        # Status label (updated during auth)
        self._gw_status_var = ctk.StringVar(value="")
        status_lbl = ctk.CTkLabel(card, textvariable=self._gw_status_var,
                                   font=("Segoe UI", 9), text_color="#ff6b6b")
        status_lbl.pack(pady=(0, 8))

        # Primary CTA
        connect_btn = ctk.CTkButton(
            card, text="🌐  Connect Google Drive & Check",
            command=lambda: self._gateway_connect_drive(connect_btn, skip_btn),
            font=("Segoe UI", 12, "bold"),
            fg_color="#00a8ff", hover_color="#0077cc",
            corner_radius=8, height=44)
        connect_btn.pack(fill="x", padx=30, pady=(0, 10))

        # Secondary: skip
        skip_btn = ctk.CTkButton(
            card, text="Skip — Create a New Account",
            command=self._build_register_ui,
            font=("Segoe UI", 11),
            fg_color="#2b2b2b", hover_color="#3a3a3a",
            text_color="#aaaaaa", corner_radius=8, height=38)
        skip_btn.pack(fill="x", padx=30, pady=(0, 4))

        ctk.CTkLabel(
            card,
            text="Skipping will not delete any cloud backups.\n"
                 "You can still restore them later from within the app.",
            font=("Segoe UI", 9), text_color="#555555",
            justify="center").pack(pady=(0, 20))

    def _gateway_connect_drive(self, connect_btn, skip_btn):
        """
        Triggered by the gateway 'Connect Google Drive' button.
        Opens the OAuth browser flow, then runs the backup probe.
        """
        connect_btn.configure(state="disabled", text="⏳  Connecting…")
        skip_btn.configure(state="disabled")
        self._gw_status_var.set("")

        def _auth_and_probe():
            try:
                from core.cloud_sync import cloud_sync
                from core.encryption_manager import crypto_manager

                # Force interactive OAuth — this will open the browser
                cloud_sync.force_authenticate()

                if not cloud_sync.is_active:
                    def _fail():
                        connect_btn.configure(state="normal",
                                              text="🌐  Connect Google Drive & Check")
                        skip_btn.configure(state="normal")
                        self._gw_status_var.set(
                            "Google Drive authentication failed or was cancelled.")
                    self.root.after(0, _fail)
                    return

                # Auth succeeded — now probe for backups
                # Show the spinner UI while probing
                self.root.after(0, self._build_cloud_probe_ui)
                self._run_backup_probe(cloud_sync, crypto_manager)

            except Exception as e:
                print(f"[LOGIN] Gateway auth error: {e}")
                def _err():
                    connect_btn.configure(state="normal",
                                          text="🌐  Connect Google Drive & Check")
                    skip_btn.configure(state="normal")
                    self._gw_status_var.set(f"Error: {e}")
                self.root.after(0, _err)

        import threading
        threading.Thread(target=_auth_and_probe, daemon=True).start()

    
    def _build_cloud_probe_ui(self):
        """
        Shown while probing Google Drive on a fresh install.
        Prevents the blank/frozen window the user was seeing.
        """
        for widget in self.root.winfo_children():
            widget.destroy()
    
        card = ctk.CTkFrame(self.root, fg_color="#1e1e1e", corner_radius=16)
        card.pack(expand=True, fill="both", padx=40, pady=60)
    
        ctk.CTkLabel(card, text="☁",
                    font=("Segoe UI", 52), text_color="#00a8ff").pack(pady=(30, 8))
    
        ctk.CTkLabel(card, text="Checking for previous installation",
                    font=("Segoe UI", 15, "bold"), text_color="#ffffff").pack()
    
        ctk.CTkLabel(card,
                    text="Looking for a cloud backup on Google Drive...",
                    font=("Segoe UI", 10), text_color="#a0a0a0").pack(pady=(6, 24))
    
        # Braille spinner — rendered as a CTkLabel so it's theme-safe
        self._probe_spin_chars = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
        self._probe_spin_idx   = [0]
        self._probe_spin_lbl   = ctk.CTkLabel(
            card, text="⠋",
            font=("Segoe UI", 24), text_color="#00a8ff"
        )
        self._probe_spin_lbl.pack()
    
        self._animate_probe_spinner()

    
    # ══════════════════════════════════════════════════════════════════════════════
    #  NEW — _animate_probe_spinner
    # ══════════════════════════════════════════════════════════════════════════════
    
    def _animate_probe_spinner(self):
        """Keeps the braille spinner spinning while Drive probe runs."""
        lbl = getattr(self, '_probe_spin_lbl', None)
        if not lbl:
            return
        try:
            if not lbl.winfo_exists():
                return
        except Exception:
            return
    
        chars = self._probe_spin_chars
        idx   = self._probe_spin_idx
        lbl.configure(text=chars[idx[0] % len(chars)])
        idx[0] += 1
        self.root.after(80, self._animate_probe_spinner)


    def _build_reinstall_detection_ui(self, backup_info: dict, machine_id: str):
        """
        The "Previous Installation Detected" screen — the WhatsApp moment.
        Shows backup metadata and offers two choices.
        """
        for widget in self.root.winfo_children():
            widget.destroy()

        main_card = ctk.CTkFrame(self.root, fg_color="#1e1e1e", corner_radius=16)
        main_card.pack(expand=True, fill="both", padx=30, pady=30)

        # Header
        ctk.CTkLabel(main_card, text="☁",
                    font=("Segoe UI", 42), text_color="#00a8ff").pack(pady=(24, 6))
        ctk.CTkLabel(main_card, text="Previous Installation Found",
                    font=("Segoe UI", 20, "bold"), text_color="#ffffff").pack()
        ctk.CTkLabel(main_card,
                    text="A cloud backup was found for this device.",
                    font=("Segoe UI", 11), text_color="#a0a0a0").pack(pady=(4, 18))

        # Metadata card
        meta = ctk.CTkFrame(main_card, fg_color="#2b2b2b", corner_radius=10)
        meta.pack(fill="x", padx=30, pady=(0, 18))

        fc   = backup_info.get("file_counts", {})
        rows = [
            ("Last sync",  backup_info.get("last_sync",  "Unknown")),
            ("Hostname",   backup_info.get("hostname",   "Unknown")),
            ("Account",    backup_info.get("email",      "Unknown")),
            ("Plan",       backup_info.get("tier",       "Unknown")),
            ("Vault files",    f"{fc.get('vault',  0)} files"),
            ("Log files",      f"{fc.get('logs',   0)} files"),
        ]
        for label, value in rows:
            row = ctk.CTkFrame(meta, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=3)
            ctk.CTkLabel(row, text=label + ":", font=("Segoe UI", 10),
                        text_color="#888888", width=100, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=value, font=("Segoe UI", 10, "bold"),
                        text_color="#ffffff", anchor="w").pack(side="left")

        # Action buttons
        ctk.CTkButton(
            main_card, text="Restore My Backup",
            command=lambda: self._execute_restore(machine_id),
            font=("Segoe UI", 13, "bold"),
            fg_color="#00a8ff", hover_color="#0077cc",
            corner_radius=8, height=44
        ).pack(fill="x", padx=30, pady=(0, 10))

        ctk.CTkButton(
            main_card, text="Start Fresh  (archive old backup)",
            command=lambda: self._execute_start_fresh(machine_id),
            font=("Segoe UI", 12),
            fg_color="#2b2b2b", hover_color="#3a3a3a",
            text_color="#aaaaaa", corner_radius=8, height=40
        ).pack(fill="x", padx=30, pady=(0, 6))

        ctk.CTkLabel(
            main_card,
            text="Starting fresh archives your old data in Google Drive.\n"
                "Your PRO license is preserved — re-enter your key after registering.",
            font=("Segoe UI", 9), text_color="#666666", justify="center"
        ).pack(pady=(0, 20))


    def _execute_restore(self, machine_id: str):
        for widget in self.root.winfo_children():
            widget.destroy()

        card = ctk.CTkFrame(self.root, fg_color="#1e1e1e", corner_radius=16)
        card.pack(expand=True, fill="both", padx=30, pady=24)

        ctk.CTkLabel(card, text="☁",
                    font=("Segoe UI", 42), text_color="#00a8ff").pack(pady=(24, 6))
        ctk.CTkLabel(card, text="Restoring Your Installation",
                    font=("Segoe UI", 18, "bold"), text_color="#ffffff").pack()
        ctk.CTkLabel(card, text="Recovering data from Google Drive…",
                    font=("Segoe UI", 10), text_color="#a0a0a0").pack(pady=(4, 16))

        # ── Step indicators ───────────────────────────────────────────────
        steps_frame = ctk.CTkFrame(card, fg_color="#2b2b2b", corner_radius=10)
        steps_frame.pack(fill="x", padx=28, pady=(0, 14))

        STEP_DEFS = [
            ("🔑", "Recovering encryption key"),
            ("👤", "Restoring account database"),
            ("📋", "Restoring audit logs & forensics"),
            ("⚙️", "Reloading credentials"),
            ("✅", "Finalizing"),
        ]
        step_widgets = []
        for icon, label in STEP_DEFS:
            row = ctk.CTkFrame(steps_frame, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=3)
            icon_lbl = ctk.CTkLabel(row, text=icon, font=("Segoe UI", 13),
                                    text_color="#444444", width=26)
            icon_lbl.pack(side="left")
            txt_lbl  = ctk.CTkLabel(row, text=label, font=("Segoe UI", 11),
                                    text_color="#555555", anchor="w")
            txt_lbl.pack(side="left", padx=8)
            step_widgets.append((icon_lbl, txt_lbl))

        # ── Progress bar ──────────────────────────────────────────────────
        progress_bar = ctk.CTkProgressBar(card, width=320, height=6,
                                        fg_color="#2b2b2b",
                                        progress_color="#00a8ff")
        progress_bar.pack(pady=(0, 6))
        progress_bar.set(0)

        progress_var = ctk.StringVar(value="Connecting to Google Drive…")
        ctk.CTkLabel(card, textvariable=progress_var,
                    font=("Consolas", 9), text_color="#00a8ff").pack()

        # ── Braille spinner ────────────────────────────────────────────────
        SPIN = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
        spin_idx = [0]
        spin_lbl = ctk.CTkLabel(card, text=SPIN[0],
                                font=("Segoe UI", 18), text_color="#555555")
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
                    il.configure(text_color="#00cc66")
                    tl.configure(text_color="#00cc66")
                elif i == idx:
                    il.configure(text_color="#00a8ff")
                    tl.configure(text_color="#ffffff")
                else:
                    il.configure(text_color="#444444")
                    tl.configure(text_color="#555555")
            progress_bar.set((idx + 1) / TOTAL_STEPS)

        def _do_restore():
            from core.encryption_manager import crypto_manager
            from core.cloud_sync import cloud_sync
            import os, time

            # Step 0 — clear local key so cloud key is downloaded fresh
            self.root.after(0, lambda: _activate_step(0))
            self.root.after(0, lambda: progress_var.set("Step 1/5: Preparing encryption recovery…"))
            try:
                for kpath in [crypto_manager.key_file, crypto_manager.key_backup]:
                    if os.path.exists(kpath):
                        os.remove(kpath)
                crypto_manager.fernet                    = None
                crypto_manager._key_bytes                = None
                crypto_manager._local_ok                 = False
                crypto_manager._cloud_recovery_attempted = False
            except Exception as e:
                print(f"[RESTORE] Key clear warning: {e}")

            # Step 1 — download encryption key
            self.root.after(0, lambda: progress_var.set("Step 1/5: Downloading encryption key…"))
            key_ok = crypto_manager.attempt_cloud_recovery_if_needed(user_consented=True)

            if not key_ok or crypto_manager.fernet is None:
                def _fail():
                    spin_lbl.configure(text="❌", text_color="#ff4444")
                    progress_var.set("⚠️  Key not found — please create a new account.")
                self.root.after(0, _fail)
                self.root.after(2800, self._build_register_ui)
                return

            # Step 2 — AppData (users.dat, config, hash records)
            self.root.after(0, lambda: _activate_step(1))
            self.root.after(0, lambda: progress_var.set("Step 2/5: Restoring account database…"))
            try:
                cloud_sync.restore_full_appdata(machine_id)
            except Exception as e:
                print(f"[RESTORE] AppData error: {e}")

            # Step 3 — Logs + forensics
            self.root.after(0, lambda: _activate_step(2))
            self.root.after(0, lambda: progress_var.set("Step 3/5: Restoring audit logs…"))
            try:
                cloud_sync.restore_logs_and_forensics(machine_id)
            except Exception as e:
                print(f"[RESTORE] Logs error: {e}")

            # Step 4 — Reload auth (double pass for safety)
            self.root.after(0, lambda: _activate_step(3))
            self.root.after(0, lambda: progress_var.set("Step 4/5: Reloading credentials…"))
            try:
                time.sleep(0.5)
                auth.reload()
                time.sleep(0.2)
                auth.reload()
            except Exception as e:
                print(f"[RESTORE] auth.reload error: {e}")

            # Step 5 — Done
            self.root.after(0, lambda: _activate_step(4))
            self.root.after(0, lambda: progress_var.set("✅ Restore complete — please log in."))

            def _finish():
                spin_lbl.configure(text="✅", text_color="#00cc66")
                self.root.after(2000, self._build_login_ui)
            self.root.after(0, _finish)

        import threading
        threading.Thread(target=_do_restore, daemon=True).start()


    def _execute_start_fresh(self, machine_id: str):
        """User chose Start Fresh. Archive old data, then show registration."""
        if not self.show_warning_confirm(
            "Archive your cloud backup?\n\n"
            "Your old data will be moved to an archive folder in Google Drive.\n"
            "Your PRO license is NOT cancelled — re-enter your key after setup."
        ):
            return

        def _do_archive():
            from core.cloud_sync import cloud_sync
            from core.encryption_manager import crypto_manager

            ok, name = cloud_sync.archive_machine_folder(machine_id)
            if ok:
                print(f"[LOGIN] Archived as: {name}")
            else:
                print(f"[LOGIN] Archive warning (non-blocking): {name}")

            # Generate a fresh local key now that the old cloud folder is archived
            crypto_manager.attempt_cloud_recovery_if_needed(user_consented=False)
            self.root.after(0, self._build_register_ui)

        import threading
        threading.Thread(target=_do_archive, daemon=True).start()


    def show_warning_confirm(self, message: str) -> bool:
        """Synchronous yes/no confirm dialog."""
        import tkinter.messagebox as mb
        return mb.askyesno("Confirm", message, parent=self.root)


    def _build_archive_picker_ui(self, all_options: list, machine_id: str):
        """
        Shown when multiple backups exist (active + archives, or multiple archives).
        Lists every available backup with date, account email, and file counts.
        User picks one and clicks Restore, or starts fresh.

        'all_options' items are dicts with the same shape as check_backup_exists()
        returns, plus '_is_active' bool and 'archived_at' string.
        """
        for widget in self.root.winfo_children():
            widget.destroy()

        main_card = ctk.CTkFrame(self.root, fg_color="#1e1e1e", corner_radius=16)
        main_card.pack(expand=True, fill="both", padx=20, pady=16)

        ctk.CTkLabel(main_card, text="☁",
                     font=("Segoe UI", 36), text_color="#00a8ff").pack(pady=(18, 4))
        ctk.CTkLabel(main_card,
                     text=f"{len(all_options)} Backup(s) Found",
                     font=("Segoe UI", 18, "bold"), text_color="#ffffff").pack()
        ctk.CTkLabel(main_card,
                     text="Select which backup to restore, or start fresh.",
                     font=("Segoe UI", 10), text_color="#a0a0a0",
                     justify="center").pack(pady=(4, 12))

        # Scrollable option list
        scroll = ctk.CTkScrollableFrame(main_card, fg_color="#2b2b2b",
                                        corner_radius=8, height=200)
        scroll.pack(fill="x", padx=20, pady=(0, 10))

        selected = [None]
        all_btns = []

        def _select(opt, btn_ref):
            selected[0] = opt
            for b in all_btns:
                b.configure(fg_color="#3b3b3b")
            btn_ref.configure(fg_color="#00a8ff")
            restore_btn.configure(state="normal")

        for opt in all_options:
            fc      = opt.get("file_counts", {})
            n_files = sum(v for v in fc.values() if isinstance(v, int))
            is_act  = opt.get("_is_active", False)
            tag     = "  ★ CURRENT  " if is_act else "  ARCHIVE  "
            date    = (opt.get("last_sync") or opt.get("archived_at") or "Unknown")[:16]
            email   = opt.get("email", "?")[:32]
            lbl     = f"{tag}  {date}   •   {email}   •   {n_files} files"

            btn = ctk.CTkButton(
                scroll, text=lbl,
                command=lambda o=opt, b=None: None,  # set below
                font=("Segoe UI", 10),
                fg_color="#3b3b3b", hover_color="#4a4a4a",
                text_color="#ffffff", anchor="w",
                height=40, corner_radius=6)
            btn.configure(command=lambda o=opt, bref=btn: _select(o, bref))
            btn.pack(fill="x", padx=8, pady=3)
            all_btns.append(btn)

        restore_btn = ctk.CTkButton(
            main_card, text="Restore Selected Backup",
            command=lambda: self._execute_restore_from_option(selected[0], machine_id),
            font=("Segoe UI", 12, "bold"),
            fg_color="#00a8ff", hover_color="#0077cc",
            state="disabled", corner_radius=8, height=42)
        restore_btn.pack(fill="x", padx=20, pady=(0, 8))

        # Start fresh — no active folder case (or user just doesn't want any backup)
        def _start_fresh():
            if not self.show_warning_confirm(
                "Start Fresh?\n\n"
                "Your existing backups will remain in Google Drive as archives.\n"
                "A new account will be created.\n\n"
                "Your PRO license is NOT cancelled — re-enter your key after setup."
            ):
                return
            def _run():
                from core.encryption_manager import crypto_manager
                crypto_manager.attempt_cloud_recovery_if_needed(user_consented=False)
                self.root.after(0, self._build_register_ui)
            import threading
            threading.Thread(target=_run, daemon=True).start()

        ctk.CTkButton(
            main_card, text="Start Fresh",
            command=_start_fresh,
            font=("Segoe UI", 11),
            fg_color="#2b2b2b", hover_color="#3a3a3a",
            text_color="#aaaaaa", corner_radius=8, height=36
        ).pack(fill="x", padx=20, pady=(0, 4))

        ctk.CTkLabel(
            main_card,
            text="Your PRO license is preserved — re-enter your key after registering.",
            font=("Segoe UI", 9), text_color="#555555", justify="center"
        ).pack(pady=(0, 12))


    def _execute_restore_from_option(self, opt: dict, machine_id: str):
        """
        Restore from a selected option (either the active backup or an archive).
        Routes to the correct restore path depending on _is_active flag.
        Both paths share the same key-clear-first logic.
        """
        if not opt:
            return

        if opt.get("_is_active"):
            # Active folder — use the standard restore flow
            self._execute_restore(machine_id)
        else:
            # Archive folder — restore from the specific archive folder_id
            self._execute_restore_from_archive(opt, machine_id)


    def _execute_restore_from_archive(self, archive: dict, machine_id: str):
        """
        Restore from a specific archive folder.
        Same key-clear-first pattern as _execute_restore.
        """
        for widget in self.root.winfo_children():
            widget.destroy()

        card = ctk.CTkFrame(self.root, fg_color="#1e1e1e", corner_radius=16)
        card.pack(expand=True, fill="both", padx=40, pady=60)
        ctk.CTkLabel(card, text="⏳ Restoring from archive...",
                     font=("Segoe UI", 14, "bold"), text_color="#00a8ff").pack(pady=30)
        progress_var = ctk.StringVar(value="Starting restore…")
        ctk.CTkLabel(card, textvariable=progress_var,
                     font=("Segoe UI", 10), text_color="#a0a0a0").pack()

        def _run():
            from core.cloud_sync import cloud_sync
            from core.encryption_manager import crypto_manager
            import os, time

            archive_folder_id = archive["folder_id"]

            # Step 1 — clear local key so crypto_manager downloads the archive's key
            progress_var.set("Clearing local key for fresh restore...")
            try:
                for kpath in [crypto_manager.key_file, crypto_manager.key_backup]:
                    if os.path.exists(kpath):
                        os.remove(kpath)
                crypto_manager.fernet                    = None
                crypto_manager._key_bytes                = None
                crypto_manager._local_ok                 = False
                crypto_manager._cloud_recovery_attempted = False
            except Exception as e:
                print(f"[RESTORE_ARCHIVE] Key clear warning: {e}")

            # Step 2 — restore key files from archive
            progress_var.set("Downloading encryption key...")
            key_result = cloud_sync.restore_from_archive(archive_folder_id,
                                                          subfolder="keys",
                                                          machine_id=machine_id)
            print(f"[RESTORE_ARCHIVE] Keys: {key_result}")

            # Step 3 — reload the key from the just-restored files
            progress_var.set("Loading encryption key...")
            try:
                crypto_manager._phase1_local_init()
            except Exception as e:
                print(f"[RESTORE_ARCHIVE] Phase1 reload error: {e}")

            if crypto_manager.fernet is None:
                progress_var.set("⚠️  No encryption key in this archive.\n"
                                 "Please create a new account.")
                self.root.after(2500, self._build_register_ui)
                return

            # Step 4 — restore appdata with the now-correct key loaded
            progress_var.set("Restoring account database...")
            cloud_sync.restore_from_archive(archive_folder_id,
                                             subfolder="appdata",
                                             machine_id=machine_id)

            progress_var.set("Restoring logs & forensics...")
            cloud_sync.restore_from_archive(archive_folder_id,
                                             subfolder="logs",
                                             machine_id=machine_id)

            # Step 5 — reload auth
            progress_var.set("Reloading credentials...")
            try:
                time.sleep(0.5)
                auth.reload()
                time.sleep(0.2)
                auth.reload()
            except Exception as e:
                print(f"[RESTORE_ARCHIVE] auth.reload error: {e}")

            progress_var.set("✅ Restore complete — please log in.")
            self.root.after(1500, self._build_login_ui)

        import threading
        threading.Thread(target=_run, daemon=True).start()

    # ------------------------------------------------------------------
    # Launch main app (reusing the same root window)
    # ------------------------------------------------------------------
    def _launch_main_app(self, role, username):
        # Clear all widgets from the current root
        for widget in self.root.winfo_children():
            widget.destroy()

        # Build the main application inside the existing root
        app = ProIntegrityGUI(self.root, user_role=role, username=username)
        # No need to start a new mainloop – the existing one continues

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = LoginWindow()
    app.run()