# integrity_gui.py
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import threading
import time
import os
from integrity_core import start_monitoring, stop_monitoring, verify_all_files, generate_report
from config_loader import load_config  # if you separated config logic

class IntegrityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ File Integrity Checker")
        self.root.geometry("850x600")
        self.root.resizable(False, False)

        # Colors & Style
        self.bg = "#f7f8fa"
        self.btn_bg = "#0078D7"
        self.btn_fg = "#ffffff"
        self.root.configure(bg=self.bg)

        # Folder Path
        self.folder_path = tk.StringVar()
        self.monitor_thread = None
        self.monitor_running = False

        # Folder selection
        tk.Label(root, text="📁 Folder to Monitor:", bg=self.bg, font=("Segoe UI", 11)).pack(pady=(15, 0))
        frame = tk.Frame(root, bg=self.bg)
        frame.pack(pady=(5, 10))
        tk.Entry(frame, textvariable=self.folder_path, width=70).pack(side=tk.LEFT, padx=5)
        tk.Button(frame, text="Browse", command=self.browse_folder, bg=self.btn_bg, fg=self.btn_fg).pack(side=tk.LEFT)

        # Buttons
        btn_frame = tk.Frame(root, bg=self.bg)
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="Start Monitoring", command=self.start_monitor, bg="#28a745", fg="white", width=18).grid(row=0, column=0, padx=5, pady=5)
        tk.Button(btn_frame, text="Stop Monitoring", command=self.stop_monitor, bg="#dc3545", fg="white", width=18).grid(row=0, column=1, padx=5, pady=5)
        tk.Button(btn_frame, text="Run Full Verification", command=self.run_verification, bg="#17a2b8", fg="white", width=18).grid(row=0, column=2, padx=5, pady=5)
        tk.Button(btn_frame, text="View Report", command=self.view_report, bg="#6c757d", fg="white", width=18).grid(row=0, column=3, padx=5, pady=5)

        # Log display area
        tk.Label(root, text="📜 Live Log Output:", bg=self.bg, font=("Segoe UI", 11)).pack()
        self.log_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=20, font=("Consolas", 10))
        self.log_box.pack(pady=10)
        self.log_box.configure(state='disabled')

        self.update_log_box()

    def browse_folder(self):
        path = filedialog.askdirectory()
        if path:
            self.folder_path.set(path)

    def start_monitor(self):
        folder = self.folder_path.get()
        if not folder or not os.path.exists(folder):
            messagebox.showerror("Error", "Please select a valid folder.")
            return

        if self.monitor_running:
            messagebox.showinfo("Info", "Monitoring is already running.")
            return

        self.monitor_running = True
        self.log("✅ Monitoring started for: " + folder)
        self.monitor_thread = threading.Thread(target=start_monitoring, args=(folder,), daemon=True)
        self.monitor_thread.start()

    def stop_monitor(self):
        if not self.monitor_running:
            messagebox.showinfo("Info", "No monitoring session is active.")
            return
        stop_monitoring()
        self.monitor_running = False
        self.log("🛑 Monitoring stopped.")

    def run_verification(self):
        folder = self.folder_path.get()
        if not folder or not os.path.exists(folder):
            messagebox.showerror("Error", "Please select a valid folder.")
            return
        summary = verify_all_files(folder)
        msg = f"✅ Verification Done!\n\nModified: {len(summary['modified'])}\nNew: {len(summary['created'])}\nDeleted: {len(summary['deleted'])}\nTampered: {len(summary.get('tampered', []))}"
        messagebox.showinfo("Verification Summary", msg)
        self.log("🔍 Full verification executed.")

    def view_report(self):
        report = generate_report()
        if not report:
            messagebox.showwarning("No Report", "No recent report found.")
            return
        self.log("📊 Report Summary:\n" + str(report))

    def log(self, text):
        self.log_box.configure(state='normal')
        self.log_box.insert(tk.END, f"{time.strftime('%H:%M:%S')} → {text}\n")
        self.log_box.configure(state='disabled')
        self.log_box.see(tk.END)

    def update_log_box(self):
        log_file = "integrity_log.txt"
        if os.path.exists(log_file):
            with open(log_file, "r", encoding="utf-8") as f:
                lines = f.readlines()[-5:]
                for line in lines:
                    if line not in self.log_box.get("1.0", tk.END):
                        self.log(line.strip())
        self.root.after(3000, self.update_log_box)

# ---------- MAIN ----------
if __name__ == "__main__":
    root = tk.Tk()
    app = IntegrityApp(root)
    root.mainloop()
