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

        # --- THE SMART ROUTER (Builds UI invisibly in the background) ---
        if not auth.has_users():
            self._build_register_ui()  
        else:
            self._build_login_ui()     
            
        # --- LAUNCH THE SPLASH SCREEN ---
        self._show_splash_screen()

    def _show_splash_screen(self):
        """Displays a professional full-screen branding splash before the app loads"""
        splash = tk.Toplevel(self.root)
        splash.overrideredirect(True)  # Removes Windows borders and title bar
        splash.configure(bg="#050505")
        
        # Splash dimensions and centering
        width, height = 550, 320
        x = (splash.winfo_screenwidth() // 2) - (width // 2)
        y = (splash.winfo_screenheight() // 2) - (height // 2)
        splash.geometry(f"{width}x{height}+{x}+{y}")
        
        # Main Canvas for drawing crisp vector graphics
        canvas = tk.Canvas(splash, width=width, height=height, bg="#050505", highlightthickness=0)
        canvas.pack(fill=tk.BOTH, expand=True)
        
        # Futuristic Top & Bottom Accent Lines
        canvas.create_line(0, 0, width, 0, fill=self.accent_blue, width=6)
        canvas.create_line(0, height-2, width, height-2, fill=self.accent_blue, width=6)
        
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
            img = img.resize((260, 260))  # adjust size
            self.logo_img = ImageTk.PhotoImage(img)

            canvas.create_image(width//2, height//2 - 25, image=self.logo_img)

        except Exception as e:
            print("Logo load error:", e)
        
        # Dynamic Loading Text
        load_label = tk.Label(splash, text="Initializing cryptographic vault...", 
                              font=('Consolas', 9, 'italic'), bg="#050505", fg=self.accent_cyan)
        load_label.place(relx=0.5, rely=0.85, anchor="center")
        
        # Loading Bar Background
        bar_y = height - 25
        canvas.create_rectangle(60, bar_y, width-60, bar_y+4, fill="#1a1a1a", outline="")
        progress_bar = canvas.create_rectangle(60, bar_y, 60, bar_y+4, fill=self.accent_blue, outline="")
        
        loading_steps = [
            ("Loading FileIntegrityMonitor Engine...", random.randint(500, 1000)),
            ("Booting Asynchronous Telemetry Server...", random.randint(200, 500)),
            ("Verifying RSA/AES Encryption Keys...", random.randint(600, 1200)),
            ("Injecting CustomTkinter UI Components...", random.randint(300, 700)),
            ("Securing Local Environment...", random.randint(200, 500))
        ]

        
        total_steps = len(loading_steps)
        current_step_idx = [0]
        
        def process_next_step():
            if current_step_idx[0] < total_steps:
                # Get the text and the randomized time for THIS specific step
                text, duration = loading_steps[current_step_idx[0]]
                load_label.config(text=text)
                
                # Calculate where the bar should start and end for this chunk
                start_width = 60 + ((width - 120) * (current_step_idx[0] / total_steps))
                end_width = 60 + ((width - 120) * ((current_step_idx[0] + 1) / total_steps))
                
                # Smooth micro-animation for the bar within this random duration
                frames = 15
                frame_delay = duration // frames
                
                def animate_chunk(frame=0):
                    if frame <= frames:
                        current_w = start_width + ((end_width - start_width) * (frame / frames))
                        canvas.coords(progress_bar, 60, bar_y, current_w, bar_y+4)
                        splash.after(frame_delay, lambda: animate_chunk(frame + 1))
                    else:
                        # Move to the next text phase
                        current_step_idx[0] += 1
                        process_next_step()
                
                animate_chunk()
            else:
                # Destroy splash and smoothly reveal the login window
                splash.destroy()
                self.root.deiconify()
                
        # Kick off the dynamic animation
        process_next_step()

    def _center_window(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

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
        self.forgot_btn = ctk.CTkButton(admin_card, text="Forgot Password?",
                                         command=self._build_forgot_pass_ui,
                                         fg_color="transparent", text_color="#00ccff",
                                         font=("Segoe UI", 10, "underline"), hover=False)
        self.forgot_btn.pack(pady=(0, 15))

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