#!/usr/bin/env python3
"""
login_gui.py
Entry point. Displays login screen.
Features:
- Admin login with Username/Password
- Restricted Viewer login (One-click, no password)
- Brute Force Protection (Lockout after 3 failed attempts)
"""

import sys
import os
import json
import time
import threading
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)
import tkinter as tk
from tkinter import ttk, messagebox
from core.auth_manager import auth
# Import the main class from your GUI file
from gui.integrity_gui import ProIntegrityGUI
from core.email_service import email_service

# --- SECURITY CLASS START ---
class BruteForceGuard:
    def __init__(self, max_attempts=3, lockout_time=30):
        self.max_attempts = max_attempts
        self.lockout_time = lockout_time
        self.attempts = 0
        self.lockout_timestamp = 0
        
        # Determine safe path for the security file (works for .py and .exe)
        if getattr(sys, 'frozen', False):
            # If run as .exe, store next to the executable
            base_path = os.path.dirname(sys.executable)
        else:
            # If run as script, store in current directory
            base_path = os.path.dirname(os.path.abspath(__file__))
            
        self.state_file = os.path.join(base_path, "login_security.json")
        self._load_state()

    def _load_state(self):
        """Load attempts from file to persist across restarts"""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    data = json.load(f)
                    self.attempts = data.get("attempts", 0)
                    self.lockout_timestamp = data.get("lockout_timestamp", 0)
            except:
                self.reset()

    def _save_state(self):
        """Save current attempts to file"""
        try:
            with open(self.state_file, 'w') as f:
                json.dump({
                    "attempts": self.attempts, 
                    "lockout_timestamp": self.lockout_timestamp
                }, f)
        except Exception as e:
            print(f"Error saving security state: {e}")

    def is_locked_out(self):
        """Check if user is currently locked out. Returns (bool, seconds_remaining)"""
        if self.lockout_timestamp > 0:
            time_passed = time.time() - self.lockout_timestamp
            if time_passed < self.lockout_time:
                return True, int(self.lockout_time - time_passed)
            else:
                # Lockout expired, reset automatically
                self.reset()
                return False, 0
        return False, 0

    def register_failed_attempt(self):
        """Increment failure counter"""
        self.attempts += 1
        
        # If we just hit the limit, set the timestamp
        if self.attempts >= self.max_attempts:
            self.lockout_timestamp = time.time()
        
        self._save_state()
        return self.attempts

    def reset(self):
        """Reset counters on successful login"""
        self.attempts = 0
        self.lockout_timestamp = 0
        if os.path.exists(self.state_file):
            try:
                os.remove(self.state_file)
            except:
                pass
# --- SECURITY CLASS END ---

class LoginWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("FMSecure Security Monitor")
        
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
        self.root.configure(bg="#0a0a0a")
        self.root.resizable(False, False)
        self.bg_dark = "#0a0a0a"
        
        # Initialize Security Guard
        self.guard = BruteForceGuard(max_attempts=3, lockout_time=30)

        # Initialize Security Guard
        self.guard = BruteForceGuard(max_attempts=3, lockout_time=30)

        # --- 🚨 NEW: HOSTILE RECOVERY BYPASS 🚨 ---
        if "--recovery" in sys.argv:
            # Find the primary admin user in the database
            recovered_user = "admin"
            for user, data in auth.users.items():
                if data.get("role") == "admin":
                    recovered_user = user
                    break
            
            # Hide the window and instantly launch the dashboard!
            self.root.withdraw()
            self.root.after(100, lambda: self._launch_main_app('admin', recovered_user))
            return # Stop drawing the login UI

        # --- THE SMART ROUTER ---
        if not auth.has_users():
            self._build_register_ui()  # Show Registration on first run
        else:
            self._build_login_ui()     # Show Login normally
        
        
        
        # Configure root window
        # self.root.configure(bg=self.bg_dark)
        
        # Center the window
        self._center_window()
        
        # Configure styles
        self._configure_styles()
        
        
    def _configure_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure colors for ttk widgets
        self.style.configure('TLabel', 
                           background=self.bg_dark,
                           foreground=self.text_primary)
        self.style.configure('TButton',
                           background=self.bg_panel,
                           foreground=self.text_primary,
                           bordercolor=self.border_color,
                           borderwidth=1)
        
    def _center_window(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

    def _show_hacker_error(self, title, message):
        """Show a hacker-style error dialog"""
        error_window = tk.Toplevel(self.root)
        error_window.title("⚠ ACCESS VIOLATION")
        error_window.geometry("400x250")
        error_window.resizable(False, False)
        error_window.configure(bg=self.bg_dark)
        error_window.transient(self.root)
        error_window.grab_set()
        
        # Center error window
        error_window.update_idletasks()
        e_width = error_window.winfo_width()
        e_height = error_window.winfo_height()
        e_x = (self.root.winfo_screenwidth() // 2) - (e_width // 2)
        e_y = (self.root.winfo_screenheight() // 2) - (e_height // 2)
        error_window.geometry(f'{e_width}x{e_height}+{e_x}+{e_y}')
        
        # Error header
        error_header = tk.Frame(error_window, bg="#330000", height=50)
        error_header.pack(fill=tk.X)
        error_header.pack_propagate(False)
        
        # Alert symbol and title
        alert_label = tk.Label(error_header,
                             text="⚠ INTRUSION DETECTED ⚠",
                             font=("Consolas", 12, "bold"),
                             bg="#330000",
                             fg=self.error_red)
        alert_label.pack(expand=True)
        
        # Main error frame
        error_frame = tk.Frame(error_window, 
                              bg=self.bg_panel,
                              highlightbackground=self.error_red,
                              highlightthickness=2,
                              padx=20, pady=20)
        error_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Error title
        error_title = tk.Label(error_frame,
                             text=f"> {title} <",
                             font=("Consolas", 11, "bold"),
                             bg=self.bg_panel,
                             fg=self.error_red)
        error_title.pack(anchor="w", pady=(0, 10))
        
        # Error message
        error_msg = tk.Label(error_frame,
                           text=message,
                           font=("Consolas", 10),
                           bg=self.bg_panel,
                           fg=self.text_primary,
                           justify=tk.LEFT,
                           wraplength=350)
        error_msg.pack(fill=tk.X, pady=(0, 20))
        
        # Error details
        details_label = tk.Label(error_frame,
                               text="[SYSTEM LOG]: Unauthorized access attempt recorded",
                               font=("Consolas", 8),
                               bg=self.bg_panel,
                               fg="#888888")
        details_label.pack(anchor="w", pady=(0, 20))
        
        # OK button
        ok_button = tk.Button(error_frame,
                            text="[ ACKNOWLEDGE ]",
                            command=error_window.destroy,
                            bg="#220000",
                            fg=self.error_red,
                            font=("Consolas", 10, "bold"),
                            bd=1,
                            highlightbackground=self.error_red,
                            highlightthickness=1,
                            activebackground="#330000",
                            activeforeground="#ff8888",
                            padx=20,
                            pady=8,
                            cursor="hand2")
        ok_button.pack()
        
        # Blinking effect for urgency
        def blink():
            current_color = alert_label.cget("fg")
            new_color = "#ffffff" if current_color == self.error_red else self.error_red
            try:
                alert_label.config(fg=new_color)
                error_window.after(500, blink)
            except:
                pass
        
        blink()

    def _build_login_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        # Main container with padding
        main_container = tk.Frame(self.root, bg=self.bg_dark)
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Create a canvas for scrolling with fixed size
        canvas = tk.Canvas(main_container, bg=self.bg_dark, highlightthickness=0, width=430, height=520)
        scrollbar = tk.Scrollbar(main_container, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=self.bg_dark)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw", width=430)
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True, padx=(10, 0))
        scrollbar.pack(side="right", fill="y")
        
        # Header with terminal-style look
        header_frame = tk.Frame(scrollable_frame, bg=self.bg_darker, height=100, width=410)
        header_frame.pack(fill=tk.X, pady=(10, 20), padx=10)
        header_frame.pack_propagate(False)
        
        # Terminal style header
        terminal_header = tk.Frame(header_frame, bg="#001100", height=25)
        terminal_header.pack(fill=tk.X)
        terminal_header.pack_propagate(False)
        
        # Terminal dots
        for i, color in enumerate(["#ff5555", "#ffff55", "#55ff55"]):
            dot = tk.Frame(terminal_header, bg=color, width=10, height=10)
            dot.place(x=15 + i*25, y=7)
            dot.pack_propagate(False)
        
        # Terminal title
        terminal_text = tk.Label(terminal_header, 
                                text="root@integrity-monitor:~# login_system",
                                font=("Consolas", 10, "bold"),
                                bg="#001100",
                                fg=self.accent_green)
        terminal_text.place(relx=0.5, rely=0.5, anchor="center")
        
        # Main title
        title = tk.Label(header_frame, 
                        text="SYSTEM ACCESS PORTAL",
                        font=("Courier New", 18, "bold"),
                        bg=self.bg_darker,
                        fg=self.accent_cyan)
        title.pack(expand=True)
        
        # Subtitle with glitch effect simulation
        subtitle = tk.Label(header_frame,
                          text="[SECURITY LEVEL: MAXIMUM]",
                          font=("Courier New", 9),
                          bg=self.bg_darker,
                          fg=self.text_secondary)
        subtitle.pack(pady=(0, 15))
        
        # Login Panel
        login_frame = tk.Frame(scrollable_frame, 
                              bg=self.bg_panel,
                              highlightbackground=self.border_color,
                              highlightthickness=1,
                              padx=25, pady=25)
        login_frame.pack(fill=tk.X, pady=(0, 20), padx=10)
        
        # Admin Section Title
        admin_title = tk.Label(login_frame,
                             text="> ADMIN CREDENTIALS <",
                             font=("Courier New", 11, "bold"),
                             bg=self.bg_panel,
                             fg=self.accent_blue)
        admin_title.pack(anchor="w", pady=(0, 15))
        
        # Username Field
        user_label = tk.Label(login_frame,
                            text="USERNAME:",
                            font=("Consolas", 9),
                            bg=self.bg_panel,
                            fg=self.text_secondary)
        user_label.pack(anchor="w")
        
        # Username Entry Frame (for border effect)
        user_entry_frame = tk.Frame(login_frame, 
                                   bg=self.border_color, 
                                   height=35)
        user_entry_frame.pack(fill=tk.X, pady=(5, 15))
        user_entry_frame.pack_propagate(False)
        
        self.user_entry = tk.Entry(user_entry_frame,
                                   font=("Consolas", 11),
                                   bg=self.input_bg,
                                   fg=self.accent_green,
                                   insertbackground=self.accent_green,
                                   insertwidth=2,
                                   relief=tk.FLAT,
                                   bd=0,
                                   highlightthickness=0)
        self.user_entry.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
        self.user_entry.focus()
        
        # Password Field
        pass_label = tk.Label(login_frame,
                            text="PASSWORD:",
                            font=("Consolas", 9),
                            bg=self.bg_panel,
                            fg=self.text_secondary)
        pass_label.pack(anchor="w")
        
        # Password Entry Frame (for border effect)
        pass_entry_frame = tk.Frame(login_frame, 
                                   bg=self.border_color, 
                                   height=35)
        pass_entry_frame.pack(fill=tk.X, pady=(5, 20))
        pass_entry_frame.pack_propagate(False)
        
        self.pass_entry = tk.Entry(pass_entry_frame,
                                   show="•",
                                   font=("Consolas", 11),
                                   bg=self.input_bg,
                                   fg=self.accent_green,
                                   insertbackground=self.accent_green,
                                   insertwidth=2,
                                   relief=tk.FLAT,
                                   bd=0,
                                   highlightthickness=0)
        self.pass_entry.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
        
        # Admin Login Button
        self.login_btn = tk.Button(login_frame,
                                 text="[ ACCESS TERMINAL ]",
                                 command=self._attempt_admin_login,
                                 bg="#002200",
                                 fg=self.accent_green,
                                 font=("Consolas", 10, "bold"),
                                 bd=1,
                                 highlightbackground=self.accent_green,
                                 highlightthickness=1,
                                 activebackground="#003300",
                                 activeforeground=self.accent_green,
                                 padx=20,
                                 pady=8,
                                 cursor="hand2")
        self.login_btn.pack(fill=tk.X, pady=(0, 10))

        # --- NEW: Forgot Password Link ---
        self.forgot_btn = tk.Button(login_frame, text="Forgot Password?", 
                                    command=self._build_forgot_pass_ui, 
                                    bg=self.bg_panel, fg=self.accent_blue, 
                                    bd=0, cursor="hand2", font=("Consolas", 9, "underline"),
                                    activebackground=self.bg_panel, activeforeground=self.accent_cyan)
        self.forgot_btn.pack(pady=(0, 5))


        # --- NEW: Google SSO Button ---
        # A visually distinct button for Single Sign-On
        google_btn = tk.Button(login_frame, text="🌐 Continue with Google", 
                               font=('Segoe UI', 11, 'bold'),
                               bg="#ffffff", fg="#4285F4", bd=0, pady=10, cursor="hand2",
                               command=self._handle_google_login)
        google_btn.pack(fill=tk.X, pady=(15, 0))
        
        # Hover effects to make it feel like a modern web app
        google_btn.bind("<Enter>", lambda e: google_btn.configure(bg="#f8f9fa"))
        google_btn.bind("<Leave>", lambda e: google_btn.configure(bg="#ffffff"))
        
        # Separator with terminal style
        sep_frame = tk.Frame(scrollable_frame, bg=self.bg_dark, height=20)
        sep_frame.pack(fill=tk.X, pady=10, padx=10)
        sep_frame.pack_propagate(False)
        
        sep_line = tk.Frame(sep_frame, bg=self.border_color, height=1)
        sep_line.pack(fill=tk.X, pady=9)
        
        sep_text = tk.Label(sep_frame,
                          text="║ OR ║",
                          font=("Consolas", 9),
                          bg=self.bg_dark,
                          fg=self.text_secondary)
        sep_text.place(relx=0.5, rely=0.5, anchor="center")
        
        # Guest Section
        guest_frame = tk.Frame(scrollable_frame,
                              bg=self.bg_panel,
                              highlightbackground=self.border_color,
                              highlightthickness=1,
                              padx=25, pady=20)
        guest_frame.pack(fill=tk.X, pady=(0, 20), padx=10)
        
        guest_title = tk.Label(guest_frame,
                             text="> RESTRICTED VIEWER <",
                             font=("Courier New", 11, "bold"),
                             bg=self.bg_panel,
                             fg=self.text_secondary)
        guest_title.pack(anchor="w", pady=(0, 10))
        
        guest_desc = tk.Label(guest_frame,
                            text="Read-only access with limited permissions\nNo credentials required",
                            font=("Consolas", 8),
                            bg=self.bg_panel,
                            fg="#888888",
                            justify=tk.LEFT)
        guest_desc.pack(anchor="w", pady=(0, 15))
        
        # Guest Login Button
        self.guest_btn = tk.Button(guest_frame,
                                 text="[ READ-ONLY MODE ]",
                                 command=self._attempt_guest_login,
                                 bg="#222222",
                                 fg="#aaaaaa",
                                 font=("Consolas", 10),
                                 bd=1,
                                 highlightbackground="#666666",
                                 highlightthickness=1,
                                 activebackground="#333333",
                                 activeforeground="#cccccc",
                                 padx=20,
                                 pady=8,
                                 cursor="hand2")
        self.guest_btn.pack(fill=tk.X)
        
        # Info frame at bottom
        info_frame = tk.Frame(scrollable_frame, 
                             bg="#001122",
                             highlightbackground=self.accent_blue,
                             highlightthickness=1,
                             padx=15, pady=15)
        info_frame.pack(fill=tk.X, pady=(0, 20), padx=10)
        
        info_text = tk.Label(info_frame,
                           text="⚠ NOTE: All login attempts are logged and monitored.\nUnauthorized access will trigger security protocols.",
                           font=("Consolas", 8),
                           bg="#001122",
                           fg=self.accent_cyan,
                           justify=tk.LEFT)
        info_text.pack(anchor="w")
        
        # Status bar
        status_bar = tk.Frame(self.root, bg=self.bg_darker, height=30)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        status_bar.pack_propagate(False)
        
        status_text = tk.Label(status_bar,
                             text="System: Online | Security: Active | Connection: Encrypted",
                             font=("Consolas", 8),
                             bg=self.bg_darker,
                             fg=self.accent_green)
        status_text.pack(side=tk.LEFT, padx=10)
        
        version_text = tk.Label(status_bar,
                              text="v1.0.0",
                              font=("Consolas", 8),
                              bg=self.bg_darker,
                              fg=self.text_secondary)
        version_text.pack(side=tk.RIGHT, padx=10)
        
        # Bind enter key to admin login
        self.root.bind('<Return>', lambda e: self._attempt_admin_login())
        
        # Make sure all content is visible
        scrollable_frame.update_idletasks()
        canvas.config(scrollregion=canvas.bbox("all"))

    def _build_register_ui(self):
        """Builds the First-Time Setup / Registration Screen"""
        # Clear anything currently on the window
        for widget in self.root.winfo_children():
            widget.destroy()

        main_frame = tk.Frame(self.root, bg="#1e1e1e", padx=40, pady=40)
        main_frame.pack(expand=True, fill=tk.BOTH)

        # Header
        tk.Label(main_frame, text="🛡️", font=('Segoe UI', 40), bg="#1e1e1e", fg="#00a8ff").pack(pady=(0, 10))
        tk.Label(main_frame, text="First-Time Setup", font=('Segoe UI', 20, 'bold'), bg="#1e1e1e", fg="#ffffff").pack()
        tk.Label(main_frame, text="Register your admin account to continue", font=('Segoe UI', 10), bg="#1e1e1e", fg="#a0a0a0").pack(pady=(0, 20))

        # Helper to create styled inputs
        def create_input(parent, label_text, is_password=False):
            frame = tk.Frame(parent, bg="#1e1e1e")
            frame.pack(fill=tk.X, pady=5)
            tk.Label(frame, text=label_text, font=('Segoe UI', 10), bg="#1e1e1e", fg="#a0a0a0").pack(anchor='w')
            entry = ttk.Entry(frame, font=('Segoe UI', 12), show="•" if is_password else "")
            entry.pack(fill=tk.X, pady=(5, 0))
            return entry

        # Input Fields
        self.reg_user_entry = create_input(main_frame, "Username:")
        self.reg_user_entry.insert(0, "admin") # Default suggestion
        self.reg_email_entry = create_input(main_frame, "Registered Email:")
        self.reg_pass_entry = create_input(main_frame, "Password:", is_password=True)
        self.reg_confirm_entry = create_input(main_frame, "Confirm Password:", is_password=True)

        # Register Button
        tk.Button(main_frame, text="Create Account", command=self._attempt_register,
                  font=('Segoe UI', 12, 'bold'), bg="#00a8ff", fg="white", bd=0, pady=10, cursor="hand2").pack(fill=tk.X, pady=(25, 0))

        # --- NEW: Google SSO Button (Registration) ---
        reg_google_btn = tk.Button(main_frame, text="🌐 Sign up with Google", 
                               font=('Segoe UI', 11, 'bold'),
                               bg="#ffffff", fg="#4285F4", bd=0, pady=10, cursor="hand2",
                               command=self._handle_google_login)
        reg_google_btn.pack(fill=tk.X, pady=(15, 0))
        
        reg_google_btn.bind("<Enter>", lambda e: reg_google_btn.configure(bg="#f8f9fa"))
        reg_google_btn.bind("<Leave>", lambda e: reg_google_btn.configure(bg="#ffffff"))

    def _attempt_register(self):
        """Handle the registration button click with Threaded Loading State"""
        username = self.reg_user_entry.get().strip()
        email = self.reg_email_entry.get().strip().lower()
        password = self.reg_pass_entry.get()
        confirm = self.reg_confirm_entry.get()

        # Validation
        if not username or not email or not password:
            messagebox.showerror("Error", "All fields are required.")
            return
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match.")
            return
        if "@" not in email or "." not in email:
            messagebox.showerror("Error", "Please enter a valid email address.")
            return

        # --- 1. CREATE THE UI LOADER ---
        self.root.config(cursor="watch") # Change mouse to loading spinner
        
        # Create a sleek popup loader
        loader = tk.Toplevel(self.root)
        loader.overrideredirect(True) # Remove windows borders
        # Center it over the main window
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - 100
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - 40
        loader.geometry(f"200x80+{x}+{y}")
        loader.configure(bg="#1e1e1e", highlightbackground="#00a8ff", highlightthickness=2)
        tk.Label(loader, text="⏳ Sending OTP...", font=('Segoe UI', 12, 'bold'), bg="#1e1e1e", fg="#00a8ff").pack(expand=True)
        loader.update() # Force UI to draw it immediately

        # --- 2. BACKGROUND THREAD TASK ---
        def _send_email_task():
            success, msg = email_service.send_otp_email(email, "verification")
            
            # --- 3. RETURN TO MAIN UI THREAD ---
            def _update_gui():
                self.root.config(cursor="") # Reset mouse
                loader.destroy() # Remove popup
                
                if success:
                    messagebox.showinfo("OTP Sent", f"A 6-digit verification code has been sent to:\n{email}")
                    self._build_otp_ui(username, email, password) # Switch to OTP Screen
                else:
                    messagebox.showerror("Email Error", f"Could not send email.\n\n{msg}")
            
            # Safely tell Tkinter to run _update_gui on the main thread
            self.root.after(0, _update_gui)

        # Start the background thread so the UI doesn't freeze!
        threading.Thread(target=_send_email_task, daemon=True).start()

    def _build_otp_ui(self, username, email, password):
        """Builds the OTP Verification Screen"""
        for widget in self.root.winfo_children():
            widget.destroy()

        main_frame = tk.Frame(self.root, bg="#1e1e1e", padx=40, pady=40)
        main_frame.pack(expand=True, fill=tk.BOTH)

        # Header
        tk.Label(main_frame, text="📧", font=('Segoe UI', 40), bg="#1e1e1e", fg="#00a8ff").pack(pady=(0, 10))
        tk.Label(main_frame, text="Verify Your Email", font=('Segoe UI', 20, 'bold'), bg="#1e1e1e", fg="#ffffff").pack()
        tk.Label(main_frame, text=f"Enter the 6-digit code sent to\n{email}", font=('Segoe UI', 10), bg="#1e1e1e", fg="#a0a0a0", justify=tk.CENTER).pack(pady=(0, 20))

        # OTP Input
        frame = tk.Frame(main_frame, bg="#1e1e1e")
        frame.pack(fill=tk.X, pady=5)
        self.otp_entry = ttk.Entry(frame, font=('Segoe UI', 20, 'bold'), justify='center')
        self.otp_entry.pack(fill=tk.X, pady=(5, 0))

        def verify_and_create():
            otp = self.otp_entry.get().strip()
            if not otp:
                messagebox.showerror("Error", "Please enter the OTP.")
                return
            
            # Check the OTP using our new service
            is_valid, msg = email_service.verify_otp(email, otp)
            if is_valid:
                # OTP is correct, NOW we create the account in the database
                success, auth_msg = auth.register_user(username, email, password, role="admin")
                if success:
                    messagebox.showinfo("Success", "Account created successfully! You can now log in.")
                    self._build_login_ui()
                else:
                    messagebox.showerror("Registration Failed", auth_msg)
            else:
                messagebox.showerror("Verification Failed", msg)

        # Buttons
        tk.Button(main_frame, text="Verify & Create Account", command=verify_and_create,
                  font=('Segoe UI', 12, 'bold'), bg="#00a8ff", fg="white", bd=0, pady=10, cursor="hand2").pack(fill=tk.X, pady=(25, 0))
        tk.Button(main_frame, text="Cancel & Go Back", command=self._build_register_ui,
                  font=('Segoe UI', 10), bg="#1e1e1e", fg="#a0a0a0", bd=0, cursor="hand2").pack(fill=tk.X, pady=(10, 0))


    

    def _attempt_admin_login(self):
        # 1. CHECK SECURITY LOCKOUT
        is_locked, wait_time = self.guard.is_locked_out()
        
        if is_locked:
            self._show_hacker_error("SYSTEM LOCKDOWN", 
                                  f"Too many failed login attempts.\n\nSecurity protocols have locked this terminal.\nPlease wait {wait_time} seconds before retrying.")
            return

        # 2. PROCEED WITH LOGIN
        username = self.user_entry.get().strip()
        password = self.pass_entry.get().strip()
        
        if not username or not password:
            self._show_hacker_error("MISSING CREDENTIALS", 
                                   "Username and password fields cannot be empty.\nPlease provide valid administrator credentials.")
            return
            
        success, role, msg = auth.login(username, password)
        
        if success:
            if role != 'admin':
                self._show_hacker_error("UNAUTHORIZED ROLE", 
                                       "This terminal is reserved for ADMINISTRATOR access only.\nYour account does not have sufficient privileges.")
                return
                
            # SUCCESS: Reset guard and launch
            self.guard.reset()
            self.root.destroy()
            self._launch_main_app(role, username)
        else:
            # FAILURE: Register attempt and warn
            attempts = self.guard.register_failed_attempt()
            remaining = self.guard.max_attempts - attempts
            
            if remaining > 0:
                self._show_hacker_error("ACCESS DENIED", 
                                       f"Authentication failed: {msg}\n\nWARNING: {remaining} attempts remaining before system lockdown.")
            else:
                self._show_hacker_error("SECURITY ALERT", 
                                       "Maximum attempts reached.\nSystem locked for 30 seconds.")
            
            self.pass_entry.delete(0, tk.END)

    def _attempt_guest_login(self):
        # Direct login for viewer
        self.root.destroy()
        # Pass role='user' to trigger restrictions in main app
        self._launch_main_app(role='user', username='RestrictedViewer')

    def _build_forgot_pass_ui(self):
        """Builds the email entry screen for password recovery"""
        for widget in self.root.winfo_children():
            widget.destroy()

        main_frame = tk.Frame(self.root, bg=self.bg_dark, padx=40, pady=40)
        main_frame.pack(expand=True, fill=tk.BOTH)

        tk.Label(main_frame, text="🔐", font=('Segoe UI', 40), bg=self.bg_dark, fg=self.accent_blue).pack(pady=(0, 10))
        tk.Label(main_frame, text="Password Recovery", font=('Courier New', 18, 'bold'), bg=self.bg_dark, fg=self.accent_cyan).pack()
        tk.Label(main_frame, text="Enter your registered email address", font=('Consolas', 10), bg=self.bg_dark, fg=self.text_secondary).pack(pady=(0, 20))

        frame = tk.Frame(main_frame, bg=self.bg_dark)
        frame.pack(fill=tk.X, pady=5)
        self.fp_email_entry = ttk.Entry(frame, font=('Consolas', 12))
        self.fp_email_entry.pack(fill=tk.X, pady=(5, 0))

        def send_reset_code():
            email = self.fp_email_entry.get().strip().lower()
            if not email:
                messagebox.showerror("Error", "Please enter your email.")
                return
            
            target_username = None
            for user, data in auth.users.items():
                if data.get("registered_email") == email:
                    target_username = user
                    break
            
            if not target_username:
                messagebox.showerror("Security Notice", "No account found with this email.")
                return

            # --- 1. CREATE THE UI LOADER ---
            self.root.config(cursor="watch")
            loader = tk.Toplevel(self.root)
            loader.overrideredirect(True)
            x = self.root.winfo_x() + (self.root.winfo_width() // 2) - 125
            y = self.root.winfo_y() + (self.root.winfo_height() // 2) - 40
            loader.geometry(f"250x80+{x}+{y}")
            loader.configure(bg="#111111", highlightbackground="#00ff00", highlightthickness=2)
            tk.Label(loader, text="⏳ Routing Secure OTP...", font=('Courier New', 11, 'bold'), bg="#111111", fg="#00ff00").pack(expand=True)
            loader.update()

            # --- 2. BACKGROUND THREAD TASK ---
            def _send_reset_task():
                success, msg = email_service.send_otp_email(email, "reset")
                
                # --- 3. RETURN TO MAIN UI THREAD ---
                def _update_gui():
                    self.root.config(cursor="")
                    loader.destroy()
                    
                    if success:
                        messagebox.showinfo("OTP Sent", f"A password reset code has been sent to {email}")
                        self._build_reset_pass_ui(target_username, email)
                    else:
                        messagebox.showerror("Error", msg)
                
                self.root.after(0, _update_gui)

            # Start thread
            threading.Thread(target=_send_reset_task, daemon=True).start()

        tk.Button(main_frame, text="[ SEND RECOVERY CODE ]", command=send_reset_code,
                  font=('Consolas', 10, 'bold'), bg="#002200", fg=self.accent_green, bd=1, highlightbackground=self.accent_green, cursor="hand2", pady=8).pack(fill=tk.X, pady=(25, 0))
        
        tk.Button(main_frame, text="< Back to Login", command=self._build_login_ui,
                  font=('Consolas', 10), bg=self.bg_dark, fg=self.text_secondary, bd=0, cursor="hand2").pack(fill=tk.X, pady=(10, 0))


    def _handle_google_login(self):
        """Triggers the Google SSO flow in a background thread to prevent GUI freezing"""
        self.root.config(cursor="watch") # Change mouse to a loading spinner
        self.root.update()

        def _auth_thread():
            from core.google_auth import authenticate_google_sso
            success, result = authenticate_google_sso()
            # Safely push the result back to the main Tkinter thread
            self.root.after(0, lambda: self._process_google_result(success, result))

        import threading
        threading.Thread(target=_auth_thread, daemon=True).start()

    def _process_google_result(self, success, result):
        """Handles the data sent back from Google after the browser closes"""
        self.root.config(cursor="") # Reset mouse
        
        if success:
            email = result['email']
            name = result['name']
            
            # Generate a username from the email (e.g. 'kumarmanish85211')
            username = email.split('@')[0]
            
            # --- SEAMLESS REGISTRATION ---
            # If this is their first time logging in, register them automatically!
            # --- SEAMLESS REGISTRATION ---
            from core.auth_manager import auth
            if username not in auth.users:
                import uuid
                dummy_pass = str(uuid.uuid4()) 
                auth.register_user(username, email, dummy_pass, role="admin")
                
                # We REMOVED the auto-upgrade! Google SSO users must buy a license.
                auth._save_db()
                
                
            
            from tkinter import messagebox
            messagebox.showinfo("Google SSO", f"Welcome back, {name}!\nSuccessfully authenticated via Google.")
            
            # Destroy the login screen and securely launch the main Dashboard
            self.root.destroy()
            self._launch_main_app(role="admin", username=username)
        else:
            from tkinter import messagebox
            messagebox.showerror("SSO Error", result)

    def _build_reset_pass_ui(self, username, email):
        """Builds the screen to enter the OTP and new password"""
        for widget in self.root.winfo_children():
            widget.destroy()

        main_frame = tk.Frame(self.root, bg=self.bg_dark, padx=40, pady=40)
        main_frame.pack(expand=True, fill=tk.BOTH)

        tk.Label(main_frame, text="🔓", font=('Segoe UI', 40), bg=self.bg_dark, fg=self.accent_green).pack(pady=(0, 10))
        tk.Label(main_frame, text="Reset Password", font=('Courier New', 18, 'bold'), bg=self.bg_dark, fg=self.accent_cyan).pack()
        tk.Label(main_frame, text=f"Account: {username}", font=('Consolas', 10), bg=self.bg_dark, fg=self.accent_green).pack(pady=(0, 20))

        def create_input(label_text, is_password=False):
            frame = tk.Frame(main_frame, bg=self.bg_dark)
            frame.pack(fill=tk.X, pady=5)
            tk.Label(frame, text=label_text, font=('Consolas', 10), bg=self.bg_dark, fg=self.text_secondary).pack(anchor='w')
            entry = ttk.Entry(frame, font=('Consolas', 12), show="•" if is_password else "")
            entry.pack(fill=tk.X, pady=(2, 0))
            return entry

        self.rp_otp_entry = create_input("6-Digit OTP Code:")
        self.rp_pass_entry = create_input("New Password:", True)
        self.rp_confirm_entry = create_input("Confirm Password:", True)

        def execute_reset():
            otp = self.rp_otp_entry.get().strip()
            new_pass = self.rp_pass_entry.get()
            confirm = self.rp_confirm_entry.get()

            if not otp or not new_pass or not confirm:
                messagebox.showerror("Error", "All fields are required.")
                return
            if new_pass != confirm:
                messagebox.showerror("Error", "Passwords do not match.")
                return
            
            # Verify OTP
            is_valid, msg = email_service.verify_otp(email, otp)
            if is_valid:
                # Commit new password to the encrypted database
                success, auth_msg = auth.update_password(username, new_pass)
                if success:
                    messagebox.showinfo("Success", "Password reset successfully! You can now log in.")
                    self._build_login_ui()
                else:
                    messagebox.showerror("Error", auth_msg)
            else:
                messagebox.showerror("Verification Failed", msg)

        tk.Button(main_frame, text="[ COMMIT NEW PASSWORD ]", command=execute_reset,
                  font=('Consolas', 10, 'bold'), bg="#002200", fg=self.accent_green, bd=1, highlightbackground=self.accent_green, cursor="hand2", pady=8).pack(fill=tk.X, pady=(25, 0))
        tk.Button(main_frame, text="Cancel", command=self._build_login_ui,
                  font=('Consolas', 10), bg=self.bg_dark, fg=self.text_secondary, bd=0, cursor="hand2").pack(fill=tk.X, pady=(10, 0))

    def _launch_main_app(self, role, username):
        # Create the main application root
        main_root = tk.Tk()
        
        # Initialize the GUI with the user role
        app = ProIntegrityGUI(main_root, user_role=role, username=username)
        
        # IMPORTANT: Start the main loop for the new window
        main_root.mainloop()

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = LoginWindow()
    app.run()