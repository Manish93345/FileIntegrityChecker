#!/usr/bin/env python3
"""
login_gui.py
Entry point. Displays login screen.
Features:
- Admin login with Username/Password
- Restricted Viewer login (One-click, no password)
"""

import tkinter as tk
from tkinter import ttk, messagebox
from auth_manager import auth
# Import the main class from your GUI file
from integrity_gui import ProIntegrityGUI 

class LoginWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🔐 Secure Login - Integrity Monitor")
        self.root.geometry("400x420") # Increased height for split options
        self.root.resizable(False, False)
        
        # Center the window
        self._center_window()
        
        # Styles
        self.style = ttk.Style()
        self.style.configure('TEntry', padding=5)
        self.style.configure('TButton', padding=5)
        
        self._build_ui()
        
    def _center_window(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

    def _build_ui(self):
        # Header
        header_frame = tk.Frame(self.root, bg="#0d6efd", height=80)
        header_frame.pack(fill=tk.X)
        
        title = tk.Label(header_frame, text="🛡️ SECURITY ACCESS", 
                        font=("Segoe UI", 16, "bold"), bg="#0d6efd", fg="white")
        title.place(relx=0.5, rely=0.5, anchor="center")
        
        # Main Container
        main_frame = tk.Frame(self.root, padx=40, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- ADMIN SECTION ---
        tk.Label(main_frame, text="Admin Login", font=("Segoe UI", 11, "bold"), fg="#0d6efd").pack(anchor="w", pady=(0, 10))
        
        # Username
        tk.Label(main_frame, text="Username:", font=("Segoe UI", 9)).pack(anchor="w")
        self.user_entry = ttk.Entry(main_frame, font=("Segoe UI", 10))
        self.user_entry.pack(fill=tk.X, pady=(0, 10))
        self.user_entry.focus()
        
        # Password
        tk.Label(main_frame, text="Password:", font=("Segoe UI", 9)).pack(anchor="w")
        self.pass_entry = ttk.Entry(main_frame, show="•", font=("Segoe UI", 10))
        self.pass_entry.pack(fill=tk.X, pady=(0, 15))
        
        # Login Button
        self.login_btn = tk.Button(main_frame, text="🔒 LOGIN AS ADMIN", 
                                 command=self._attempt_admin_login,
                                 bg="#0d6efd", fg="white", 
                                 font=("Segoe UI", 10, "bold"),
                                 bd=0, padx=10, pady=8, cursor="hand2")
        self.login_btn.pack(fill=tk.X)

        # Separator
        ttk.Separator(main_frame, orient='horizontal').pack(fill='x', pady=20)

        # --- GUEST SECTION ---
        tk.Label(main_frame, text="Restricted Access", font=("Segoe UI", 11, "bold"), fg="#6c757d").pack(anchor="w", pady=(0, 5))
        
        # Guest Button
        self.guest_btn = tk.Button(main_frame, text="👤 LOGIN AS VIEWER (No Password)", 
                                 command=self._attempt_guest_login,
                                 bg="#e9ecef", fg="#212529", 
                                 font=("Segoe UI", 10),
                                 bd=0, padx=10, pady=8, cursor="hand2")
        self.guest_btn.pack(fill=tk.X)
        
        # Bind enter key to admin login
        self.root.bind('<Return>', lambda e: self._attempt_admin_login())

    def _attempt_admin_login(self):
        username = self.user_entry.get().strip()
        password = self.pass_entry.get().strip()
        
        if not username or not password:
            messagebox.showwarning("Input Required", "Please enter Admin username and password.")
            return
            
        success, role, msg = auth.login(username, password)
        
        if success:
            if role != 'admin':
                # Just in case a non-admin is in the DB
                messagebox.showerror("Error", "This form is for Admins only.")
                return
            self.root.destroy()
            self._launch_main_app(role, username)
        else:
            messagebox.showerror("Access Denied", msg)
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