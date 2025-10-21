# integrity_gui.py
#!/usr/bin/env python3
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import threading
import time
import os
import traceback

# Import core
from integrity_core import (
    load_config,
    FileIntegrityMonitor,
    CONFIG,
    LOG_FILE,
    REPORT_SUMMARY_FILE
)

class IntegrityGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ File Integrity Checker - GUI")
        self.root.geometry("900x640")
        self.root.resizable(True, True)

        # Ensure config loaded (tries default config.json next to core file)
        ok = load_config(None)
        if not ok:
            messagebox.showwarning("Config", "config.json not found or invalid. Core defaults will be used (check console).")

        # Monitor object (created but monitoring not started)
        self.monitor = FileIntegrityMonitor()
        self.monitor_thread = None
        self.monitor_running = False

        # UI variables
        self.folder_var = tk.StringVar(value=os.path.abspath(CONFIG.get("watch_folder", os.getcwd())))
        self.status_var = tk.StringVar(value="Stopped")

        # Build UI
        self._build_ui()

        # Start periodic log updater
        self._schedule_log_update()

    def _build_ui(self):
        pad = 8
        frame_top = tk.Frame(self.root)
        frame_top.pack(fill=tk.X, padx=pad, pady=(pad, 0))

        tk.Label(frame_top, text="Folder to monitor:", anchor="w").pack(anchor="w")
        entry_frame = tk.Frame(frame_top)
        entry_frame.pack(fill=tk.X, pady=(4, 6))
        self.entry = tk.Entry(entry_frame, textvariable=self.folder_var, width=80)
        self.entry.pack(side=tk.LEFT, padx=(0,6), fill=tk.X, expand=True)
        tk.Button(entry_frame, text="Browse", width=10, command=self._browse).pack(side=tk.LEFT)

        buttons = tk.Frame(frame_top)
        buttons.pack(fill=tk.X, pady=(6,0))
        tk.Button(buttons, text="Start Monitoring", bg="#28a745", fg="white", command=self.start_monitor, width=18).pack(side=tk.LEFT, padx=6)
        tk.Button(buttons, text="Stop Monitoring", bg="#dc3545", fg="white", command=self.stop_monitor, width=18).pack(side=tk.LEFT, padx=6)
        tk.Button(buttons, text="Run Full Verification", bg="#17a2b8", fg="white", command=self.run_verification, width=18).pack(side=tk.LEFT, padx=6)
        tk.Button(buttons, text="View Report", bg="#6c757d", fg="white", command=self.view_report, width=18).pack(side=tk.LEFT, padx=6)

        status_frame = tk.Frame(self.root)
        status_frame.pack(fill=tk.X, padx=pad, pady=(8, 0))
        tk.Label(status_frame, text="Status: ").pack(side=tk.LEFT)
        tk.Label(status_frame, textvariable=self.status_var, fg="blue").pack(side=tk.LEFT)

        # Log area
        log_frame = tk.Frame(self.root)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=pad, pady=pad)
        tk.Label(log_frame, text="Live Log Output").pack(anchor="w")
        self.log_box = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=24, font=("Consolas", 10))
        self.log_box.pack(fill=tk.BOTH, expand=True)
        self.log_box.configure(state="disabled")

        # Bottom buttons: open folder and open report file
        bottom = tk.Frame(self.root)
        bottom.pack(fill=tk.X, padx=pad, pady=(0, pad))
        tk.Button(bottom, text="Open Log File", command=self.open_log).pack(side=tk.LEFT, padx=6)
        tk.Button(bottom, text="Open Report File", command=self.open_report).pack(side=tk.LEFT, padx=6)
        tk.Button(bottom, text="Quit", command=self._quit).pack(side=tk.RIGHT, padx=6)

    def _browse(self):
        d = filedialog.askdirectory()
        if d:
            self.folder_var.set(d)

    def start_monitor(self):
        if self.monitor_running:
            messagebox.showinfo("Info", "Monitor already running.")
            return
        folder = self.folder_var.get()
        if not folder or not os.path.exists(folder):
            messagebox.showerror("Error", "Choose a valid folder to monitor.")
            return

        # Start monitoring in a background thread (the monitor itself uses watchdog & its own thread)
        def _start():
            try:
                started = self.monitor.start_monitoring(watch_folder=folder)
                if started:
                    self.monitor_running = True
                    self._set_status(f"Running (watching {folder})")
                    self._append_log(f"Monitor started for: {folder}")
                else:
                    self._append_log("Failed to start monitor (see console).")
                    messagebox.showerror("Error", "Failed to start monitor. Check console/logs.")
            except Exception as e:
                self._append_log(f"Exception starting monitor: {e}")
                traceback.print_exc()
                messagebox.showerror("Error", f"Exception starting monitor: {e}")

        t = threading.Thread(target=_start, daemon=True)
        t.start()

    def stop_monitor(self):
        if not self.monitor_running:
            messagebox.showinfo("Info", "Monitor is not running.")
            return
        try:
            self.monitor.stop_monitoring()
            self.monitor_running = False
            self._set_status("Stopped")
            self._append_log("Monitor stopped by user.")
        except Exception as e:
            self._append_log(f"Exception stopping monitor: {e}")
            traceback.print_exc()
            messagebox.showerror("Error", f"Exception stopping monitor: {e}")

    def run_verification(self):
        folder = self.folder_var.get()
        if not folder or not os.path.exists(folder):
            messagebox.showerror("Error", "Choose a valid folder for verification.")
            return

        def _verify():
            try:
                self._append_log("Manual verification started...")
                summary = self.monitor.run_verification(watch_folder=folder)
                # summary is a dict returned by verify_all_files_and_update
                txt = (
                    f"Verification completed.\n"
                    f"Total monitored: {summary.get('total_monitored')}\n"
                    f"New: {len(summary.get('created', []))}\n"
                    f"Modified: {len(summary.get('modified', []))}\n"
                    f"Deleted: {len(summary.get('deleted', []))}\n"
                    f"Skipped: {len(summary.get('skipped', []))}\n"
                    f"Tampered records: {'YES' if summary.get('tampered_records') else 'NO'}\n"
                    f"Tampered logs: {'YES' if summary.get('tampered_logs') else 'NO'}\n"
                )
                messagebox.showinfo("Verification Summary", txt)
                self._append_log("Manual verification finished.")
            except Exception as e:
                self._append_log(f"Verification exception: {e}")
                traceback.print_exc()
                messagebox.showerror("Error", f"Verification failed: {e}")

        threading.Thread(target=_verify, daemon=True).start()

    def view_report(self):
        try:
            txt = self.monitor.get_summary()
            if not txt:
                messagebox.showinfo("Report", "No report summary found.")
            else:
                self._show_text_window("Report Summary", txt)
        except Exception as e:
            self._append_log(f"Error reading report: {e}")
            traceback.print_exc()
            messagebox.showerror("Error", f"Error reading report: {e}")

    # Utilities for log display
    def _append_log(self, text):
        # append text to GUI log area (we'll also tail the real integrity_log file)
        self.log_box.configure(state="normal")
        self.log_box.insert(tk.END, f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {text}\n")
        self.log_box.configure(state="disabled")
        self.log_box.see(tk.END)

    def _set_status(self, s):
        self.status_var.set(s)

    def open_log(self):
        if os.path.exists(LOG_FILE):
            os.startfile(LOG_FILE)
        else:
            messagebox.showinfo("Info", "Log file not found.")

    def open_report(self):
        if os.path.exists(REPORT_SUMMARY_FILE):
            os.startfile(REPORT_SUMMARY_FILE)
        else:
            messagebox.showinfo("Info", "Report file not found.")

    def _show_text_window(self, title, content):
        win = tk.Toplevel(self.root)
        win.title(title)
        win.geometry("700x500")
        st = scrolledtext.ScrolledText(win, wrap=tk.WORD)
        st.pack(fill=tk.BOTH, expand=True)
        st.insert(tk.END, content)
        st.configure(state="disabled")

    # Periodically tail integrity_log.txt into the GUI (every 2s)
    def _schedule_log_update(self):
        try:
            if os.path.exists(LOG_FILE):
                # read last N lines
                with open(LOG_FILE, "r", encoding="utf-8") as f:
                    lines = f.readlines()[-200:]  # limit
                # update GUI area if new
                existing = self.log_box.get("1.0", tk.END)
                # Insert only lines not already present by checking tail
                # (simple approach: compare last 100 chars)
                tail_check = existing[-500:]
                for line in lines[-200:]:
                    if line.strip() and (line not in existing):
                        self.log_box.configure(state="normal")
                        self.log_box.insert(tk.END, line)
                        self.log_box.configure(state="disabled")
                        self.log_box.see(tk.END)
            # schedule again
        except Exception as e:
            # ignore transient read errors
            pass
        self.root.after(2000, self._schedule_log_update)

    def _quit(self):
        if self.monitor_running:
            if not messagebox.askyesno("Quit", "Monitor is running. Stop and quit?"):
                return
            try:
                self.monitor.stop_monitoring()
            except Exception:
                pass
        self.root.quit()

if __name__ == "__main__":
    root = tk.Tk()
    app = IntegrityGUI(root)
    root.mainloop()
