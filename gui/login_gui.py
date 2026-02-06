#!/usr/bin/env python3
"""
login_gui.py
Entry point. Displays login screen.
Features:
- Admin login with Username/Password
- Restricted Viewer login (One-click, no password)
"""

import sys
sys.path.append('..')
import tkinter as tk
from tkinter import ttk, messagebox
from core.auth_manager import auth
# Import the main class from your GUI file
from gui.integrity_gui import ProIntegrityGUI

class LoginWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("〄 INTEGRITY MONITOR - ACCESS CONTROL")
        self.root.geometry("450x550")  # Increased height for better visibility
        self.root.resizable(False, False)
        
        # Dark theme colors
        self.bg_dark = "#0a0a0a"
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
        
        # Configure root window
        self.root.configure(bg=self.bg_dark)
        
        # Center the window
        self._center_window()
        
        # Configure styles
        self._configure_styles()
        
        self._build_ui()
        
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
            alert_label.config(fg=new_color)
            error_window.after(500, blink)
        
        blink()

    def _build_ui(self):
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

    def _attempt_admin_login(self):
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
            self.root.destroy()
            self._launch_main_app(role, username)
        else:
            self._show_hacker_error("ACCESS DENIED", 
                                   f"Authentication failed: {msg}\n\nCredentials rejected by security system.\nPlease verify your username and password.")
            self.pass_entry.delete(0, tk.END)

    def _attempt_guest_login(self):
        # Direct login for viewer
        self.root.destroy()
        # Pass role='user' to trigger restrictions in main app
        self._launch_main_app(role='user', username='RestrictedViewer')

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