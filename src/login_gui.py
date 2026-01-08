#!/usr/bin/env python3
"""
login_gui.py
The new entry point for the application.
Displays a login screen, validates credentials, and launches the main GUI.
"""

import tkinter as tk
from tkinter import ttk, messagebox
from auth_manager import auth
# Import the main class from your renamed GUI file
from integrity_gui import ProIntegrityGUI 

class LoginWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🔐 Secure Login - Integrity Monitor")
        self.root.geometry("400x350")
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
        
        # Form
        form_frame = tk.Frame(self.root, padx=40, pady=30)
        form_frame.pack(fill=tk.BOTH, expand=True)
        
        # Username
        tk.Label(form_frame, text="Username:", font=("Segoe UI", 10)).pack(anchor="w")
        self.user_entry = ttk.Entry(form_frame, font=("Segoe UI", 11))
        self.user_entry.pack(fill=tk.X, pady=(5, 15))
        self.user_entry.focus()
        
        # Password
        tk.Label(form_frame, text="Password:", font=("Segoe UI", 10)).pack(anchor="w")
        self.pass_entry = ttk.Entry(form_frame, show="•", font=("Segoe UI", 11))
        self.pass_entry.pack(fill=tk.X, pady=(5, 20))
        
        # Login Button
        self.login_btn = tk.Button(form_frame, text="LOGIN >", 
                                 command=self._attempt_login,
                                 bg="#0d6efd", fg="white", 
                                 font=("Segoe UI", 11, "bold"),
                                 bd=0, padx=10, pady=5, cursor="hand2")
        self.login_btn.pack(fill=tk.X)
        
        # Bind enter key
        self.root.bind('<Return>', lambda e: self._attempt_login())
        
        # Footer
        tk.Label(self.root, text="Default: admin/admin123 | user/user123", 
                fg="grey", font=("Segoe UI", 8)).pack(side=tk.BOTTOM, pady=10)

    def _attempt_login(self):
        username = self.user_entry.get().strip()
        password = self.pass_entry.get().strip()
        
        if not username or not password:
            messagebox.showwarning("Input Required", "Please enter both username and password.")
            return
            
        success, role, msg = auth.login(username, password)
        
        if success:
            self.root.destroy()
            self._launch_main_app(role, username)
        else:
            messagebox.showerror("Access Denied", msg)
            self.pass_entry.delete(0, tk.END)

    def _launch_main_app(self, role, username):
        # Create the main application root
        main_root = tk.Tk()
        
        # Initialize the GUI with the user role
        # We pass role and username to the constructor
        app = ProIntegrityGUI(main_root, user_role=role, username=username)
        
        main_root.mainloop()

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = LoginWindow()
    app.run()