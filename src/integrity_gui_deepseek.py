#!/usr/bin/env python3
"""
integrity_gui.py
Professional GUI for Secure File Integrity Monitor
- Uses integrity_core for backend logic
- Modern tkinter interface with clean design
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os
import time
from datetime import datetime
from integrity_core import FileIntegrityMonitor, load_config, CONFIG, now_pretty

class ModernButton(ttk.Button):
    """Custom styled button for modern look"""
    def __init__(self, master=None, **kwargs):
        style = ttk.Style()
        style.configure('Modern.TButton', 
                       padding=(20, 10),
                       font=('Segoe UI', 10, 'bold'))
        kwargs['style'] = 'Modern.TButton'
        super().__init__(master, **kwargs)

class FileIntegrityGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Integrity Monitor")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # Initialize monitor
        self.monitor = FileIntegrityMonitor()
        self.monitoring = False
        
        # Setup styles
        self.setup_styles()
        
        # Create GUI
        self.create_widgets()
        
        # Load initial config
        self.load_initial_config()
        
    def setup_styles(self):
        """Configure modern styles for widgets"""
        style = ttk.Style()
        
        # Configure styles for different themes
        if 'clam' in style.theme_names():
            style.theme_use('clam')
        
        # Custom styles
        style.configure('Title.TLabel', 
                       font=('Segoe UI', 16, 'bold'),
                       foreground='#2c3e50')
        
        style.configure('Subtitle.TLabel',
                       font=('Segoe UI', 11),
                       foreground='#34495e')
        
        style.configure('Status.TLabel',
                       font=('Segoe UI', 10, 'bold'))
        
        style.configure('Success.TLabel',
                       foreground='#27ae60')
        
        style.configure('Error.TLabel',
                       foreground='#e74c3c')
        
        style.configure('Warning.TLabel',
                       foreground='#f39c12')
        
        style.configure('Modern.TButton',
                       font=('Segoe UI', 10, 'bold'),
                       padding=(15, 8))
        
        style.configure('Action.TButton',
                       font=('Segoe UI', 9, 'bold'),
                       padding=(10, 5))

    def create_widgets(self):
        """Create and arrange all GUI widgets"""
        # Main container
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, 
                               text="Secure File Integrity Monitor", 
                               style='Title.TLabel')
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Folder selection section
        folder_frame = ttk.LabelFrame(main_frame, text="Monitor Folder", padding="10")
        folder_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 15))
        folder_frame.columnconfigure(1, weight=1)
        
        ttk.Label(folder_frame, text="Selected Folder:", style='Subtitle.TLabel').grid(
            row=0, column=0, sticky=tk.W, pady=(0, 5))
        
        self.folder_var = tk.StringVar(value="No folder selected")
        folder_display = ttk.Entry(folder_frame, textvariable=self.folder_var, 
                                  state='readonly', font=('Segoe UI', 9))
        folder_display.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.select_btn = ModernButton(folder_frame, 
                                      text="Select Folder", 
                                      command=self.select_folder)
        self.select_btn.grid(row=2, column=0, sticky=tk.W)
        
        # Status section
        status_frame = ttk.LabelFrame(main_frame, text="Monitoring Status", padding="10")
        status_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 15))
        status_frame.columnconfigure(1, weight=1)
        
        ttk.Label(status_frame, text="Status:", style='Subtitle.TLabel').grid(
            row=0, column=0, sticky=tk.W)
        
        self.status_var = tk.StringVar(value="Not Monitoring")
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var, 
                                     style='Status.TLabel')
        self.status_label.grid(row=0, column=1, sticky=tk.W, padx=(10, 0))
        
        self.files_var = tk.StringVar(value="Files monitored: 0")
        ttk.Label(status_frame, textvariable=self.files_var).grid(
            row=1, column=0, columnspan=2, sticky=tk.W, pady=(5, 0))
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=3, pady=(0, 15))
        
        self.start_btn = ModernButton(button_frame, 
                                     text="Start Monitoring", 
                                     command=self.start_monitoring)
        self.start_btn.grid(row=0, column=0, padx=(0, 10))
        
        self.verify_btn = ModernButton(button_frame, 
                                      text="Run Full Verification", 
                                      command=self.run_verification)
        self.verify_btn.grid(row=0, column=1, padx=(0, 10))
        
        self.summary_btn = ModernButton(button_frame, 
                                       text="Show Summary Report", 
                                       command=self.show_summary)
        self.summary_btn.grid(row=0, column=2, padx=(0, 10))
        
        # Log/Output section
        output_frame = ttk.LabelFrame(main_frame, text="Activity Log", padding="10")
        output_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(output_frame, 
                                                 height=15, 
                                                 font=('Consolas', 9),
                                                 wrap=tk.WORD)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure tags for colored text
        self.log_text.tag_configure('success', foreground='#27ae60')
        self.log_text.tag_configure('error', foreground='#e74c3c')
        self.log_text.tag_configure('warning', foreground='#f39c12')
        self.log_text.tag_configure('info', foreground='#3498db')
        self.log_text.tag_configure('file_event', foreground='#8e44ad')
        
        # Bottom status bar
        status_bar = ttk.Frame(main_frame)
        status_bar.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E))
        status_bar.columnconfigure(0, weight=1)
        
        self.status_bar_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(status_bar, textvariable=self.status_bar_var, 
                                relief=tk.SUNKEN, anchor=tk.W)
        status_label.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        # Update UI state
        self.update_ui_state()

    def load_initial_config(self):
        """Load initial configuration and update UI"""
        try:
            if load_config():
                watch_folder = CONFIG.get("watch_folder", "")
                if watch_folder and os.path.exists(watch_folder):
                    self.folder_var.set(watch_folder)
                    self.log_message(f"Loaded configuration: {watch_folder}", 'info')
                else:
                    self.log_message("Please select a folder to monitor", 'warning')
            else:
                self.log_message("Configuration file not found or invalid", 'error')
        except Exception as e:
            self.log_message(f"Error loading config: {str(e)}", 'error')

    def select_folder(self):
        """Handle folder selection"""
        folder = filedialog.askdirectory(title="Select Folder to Monitor")
        if folder:
            self.folder_var.set(folder)
            CONFIG["watch_folder"] = folder
            self.log_message(f"Selected folder: {folder}", 'success')
            self.update_ui_state()
            
            # If monitoring is active, restart with new folder
            if self.monitoring:
                self.log_message("Restarting monitoring with new folder...", 'warning')
                self.stop_monitoring()
                time.sleep(1)  # Brief pause
                self.start_monitoring_thread()

    def start_monitoring(self):
        """Start or stop monitoring"""
        if not self.monitoring:
            self.start_monitoring_thread()
        else:
            self.stop_monitoring()

    def start_monitoring_thread(self):
        """Start monitoring in a separate thread"""
        if not self.folder_var.get() or self.folder_var.get() == "No folder selected":
            messagebox.showerror("Error", "Please select a folder first")
            return
        
        if not os.path.exists(self.folder_var.get()):
            messagebox.showerror("Error", "Selected folder does not exist")
            return
        
        # Disable buttons during startup
        self.update_ui_state(False)
        
        def monitor_thread():
            try:
                # Pass the selected folder explicitly to start_monitoring
                if self.monitor.start_monitoring(watch_folder=self.folder_var.get()):
                    self.monitoring = True
                    self.root.after(0, self.on_monitoring_started)
                    
                    # Start log monitoring thread
                    threading.Thread(target=self.monitor_logs, daemon=True).start()
                else:
                    self.root.after(0, self.on_monitoring_failed)
            except Exception as e:
                self.root.after(0, lambda: self.on_monitoring_failed(str(e)))
        
        threading.Thread(target=monitor_thread, daemon=True).start()
        self.log_message("Starting monitoring...", 'info')

    def stop_monitoring(self):
        """Stop monitoring"""
        try:
            self.monitor.stop_monitoring()
            self.monitoring = False
            self.status_var.set("Not Monitoring")
            self.status_label.configure(style='Status.TLabel')
            self.log_message("Monitoring stopped", 'warning')
            self.update_ui_state()
        except Exception as e:
            self.log_message(f"Error stopping monitoring: {str(e)}", 'error')

    def monitor_logs(self):
        """Monitor the log file for real-time updates"""
        log_file_path = "integrity_log.txt"
        last_position = 0
        
        # Get initial file size
        if os.path.exists(log_file_path):
            last_position = os.path.getsize(log_file_path)
        
        while self.monitoring:
            try:
                if os.path.exists(log_file_path):
                    with open(log_file_path, 'r', encoding='utf-8') as f:
                        f.seek(last_position)
                        new_lines = f.readlines()
                        
                        if new_lines:
                            last_position = f.tell()
                            
                            # Process new log entries in GUI thread
                            for line in new_lines:
                                line = line.strip()
                                if line and not line.startswith('#'):  # Skip empty lines and comments
                                    self.root.after(0, lambda l=line: self.process_log_entry(l))
                
                time.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                time.sleep(2)  # Continue even if there's an error

    def process_log_entry(self, log_entry):
        """Process a log entry and update GUI accordingly"""
        # Color code based on log content
        if any(keyword in log_entry for keyword in ['CREATED:', 'MODIFIED:', 'DELETED:', 'INITIALIZED:']):
            self.log_message(log_entry, 'file_event')
        elif any(keyword in log_entry for keyword in ['ALERT:', 'ERROR_', 'FAILED', 'TAMPER']):
            self.log_message(log_entry, 'error')
        elif any(keyword in log_entry for keyword in ['SKIP_', 'WARNING']):
            self.log_message(log_entry, 'warning')
        elif any(keyword in log_entry for keyword in ['completed', 'successful', 'OK']):
            self.log_message(log_entry, 'success')
        else:
            self.log_message(log_entry, 'info')
        
        # Update file count if we have handler access
        if self.monitoring and self.monitor.handler:
            try:
                file_count = len(self.monitor.handler.records)
                self.files_var.set(f"Files monitored: {file_count}")
            except:
                pass

    def on_monitoring_started(self):
        """Called when monitoring successfully starts"""
        self.status_var.set("Monitoring Active")
        self.status_label.configure(style='Success.TLabel')
        self.log_message("Monitoring started successfully", 'success')
        
        # Update initial file count
        if self.monitor.handler:
            file_count = len(self.monitor.handler.records)
            self.files_var.set(f"Files monitored: {file_count}")
        
        self.update_ui_state()
        
        # Start periodic status updates
        self.update_status()

    def on_monitoring_failed(self, error_msg="Failed to start monitoring"):
        """Called when monitoring fails to start"""
        self.status_var.set("Monitoring Failed")
        self.status_label.configure(style='Error.TLabel')
        self.log_message(f"Monitoring failed: {error_msg}", 'error')
        self.update_ui_state()

    def run_verification(self):
        """Run full verification in a separate thread"""
        if not self.folder_var.get() or self.folder_var.get() == "No folder selected":
            messagebox.showerror("Error", "Please select a folder first")
            return
        
        def verify_thread():
            self.root.after(0, lambda: self.status_bar_var.set("Running verification..."))
            self.root.after(0, lambda: self.verify_btn.config(state='disabled'))
            
            try:
                # Pass the current folder explicitly
                summary = self.monitor.run_verification(watch_folder=self.folder_var.get())
                self.root.after(0, lambda: self.on_verification_complete(summary))
            except Exception as e:
                self.root.after(0, lambda: self.on_verification_failed(str(e)))
        
        self.log_message("Starting full verification...", 'info')
        threading.Thread(target=verify_thread, daemon=True).start()

    def on_verification_complete(self, summary):
        """Called when verification completes successfully"""
        self.status_bar_var.set("Verification completed")
        self.verify_btn.config(state='normal')
        
        # Extract key information from summary
        total = summary.get('total_monitored', 0)
        new = len(summary.get('created', []))
        modified = len(summary.get('modified', []))
        deleted = len(summary.get('deleted', []))
        skipped = len(summary.get('skipped', []))
        
        message = (f"Verification complete: {total} files monitored, "
                  f"{new} new, {modified} modified, {deleted} deleted, {skipped} skipped")
        
        self.log_message(message, 'success')
        
        # Update file count
        self.files_var.set(f"Files monitored: {total}")
        
        # Show detailed summary in messagebox
        details = (
            f"Verification Summary ({summary.get('timestamp', '')}):\n\n"
            f"Total files monitored: {total}\n"
            f"New files: {new}\n"
            f"Modified files: {modified}\n"
            f"Deleted files: {deleted}\n"
            f"Skipped files: {skipped}\n"
            f"Records tampered: {'YES' if summary.get('tampered_records') else 'NO'}\n"
            f"Logs tampered: {'YES' if summary.get('tampered_logs') else 'NO'}"
        )
        
        messagebox.showinfo("Verification Complete", details)

    def on_verification_failed(self, error_msg):
        """Called when verification fails"""
        self.status_bar_var.set("Verification failed")
        self.verify_btn.config(state='normal')
        self.log_message(f"Verification failed: {error_msg}", 'error')
        messagebox.showerror("Verification Failed", f"Error during verification:\n{error_msg}")

    def show_summary(self):
        """Show summary report"""
        try:
            summary_text = self.monitor.get_summary()
            if summary_text == "No report summary file found.":
                messagebox.showinfo("Summary Report", "No summary report available yet.\nRun a verification first.")
            else:
                # Create a new window for summary
                summary_window = tk.Toplevel(self.root)
                summary_window.title("Summary Report")
                summary_window.geometry("600x400")
                summary_window.resizable(True, True)
                
                # Create scrolled text widget
                text_widget = scrolledtext.ScrolledText(summary_window, wrap=tk.WORD)
                text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
                
                # Insert summary text
                text_widget.insert(tk.END, summary_text)
                text_widget.config(state=tk.DISABLED)
                
                # Add close button
                close_btn = ttk.Button(summary_window, text="Close", 
                                      command=summary_window.destroy)
                close_btn.pack(pady=(0, 10))
                
                self.log_message("Summary report displayed", 'info')
        except Exception as e:
            self.log_message(f"Error showing summary: {str(e)}", 'error')
            messagebox.showerror("Error", f"Failed to show summary:\n{str(e)}")

    def update_status(self):
        """Periodically update status information"""
        if self.monitoring:
            try:
                # Update file count
                if self.monitor.handler:
                    file_count = len(self.monitor.handler.records)
                    self.files_var.set(f"Files monitored: {file_count}")
                
                # Schedule next update
                self.root.after(5000, self.update_status)  # Update every 5 seconds
            except Exception:
                # If there's an error, stop updating
                pass

    def update_ui_state(self, enabled=True):
        """Update UI elements based on current state"""
        if enabled:
            folder_selected = self.folder_var.get() != "No folder selected"
            
            self.select_btn.config(state='normal')
            self.start_btn.config(state='normal')
            self.verify_btn.config(state='normal' if folder_selected else 'disabled')
            self.summary_btn.config(state='normal')
            
            # Update start button text based on monitoring state
            if self.monitoring:
                self.start_btn.config(text="Stop Monitoring")
            else:
                self.start_btn.config(text="Start Monitoring")
        else:
            # Disable all buttons during operations
            self.select_btn.config(state='disabled')
            self.start_btn.config(state='disabled')
            self.verify_btn.config(state='disabled')
            self.summary_btn.config(state='disabled')

    def log_message(self, message, tag='info'):
        """Add message to log with timestamp and colored tag"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        self.log_text.insert(tk.END, log_entry, tag)
        self.log_text.see(tk.END)
        self.log_text.update_idletasks()

    def on_closing(self):
        """Handle application closing"""
        if self.monitoring:
            self.stop_monitoring()
        self.root.destroy()

def main():
    """Main function to start the GUI application"""
    try:
        root = tk.Tk()
        app = FileIntegrityGUI(root)
        
        # Handle window closing
        root.protocol("WM_DELETE_WINDOW", app.on_closing)
        
        # Start the application
        root.mainloop()
    except Exception as e:
        print(f"Failed to start GUI: {e}")
        messagebox.showerror("Fatal Error", f"Failed to start application:\n{e}")

if __name__ == "__main__":
    main()