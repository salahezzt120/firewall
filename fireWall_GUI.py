import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from threading import Thread
import packet_filter
from datetime import datetime
import winsound  # Used for Windows warning sound, replace with another method for cross-platform

class FirewallGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Network Firewall Monitor")
        self.root.geometry("1200x800")
        self.root.config(bg="#1e293b")
        
        # Style configuration
        self.style = ttk.Style()
        self.style.configure("Custom.TNotebook", background="#1e293b", padding=5)
        self.style.configure("Custom.TNotebook.Tab", padding=[12, 8], font=('Helvetica', 10, 'bold'))
        
        # Create main container with padding
        self.main_container = ttk.Frame(self.root, padding="10")
        self.main_container.grid(row=0, column=0, sticky="nsew")
        
        # Create notebook for tabbed interface
        self.notebook = ttk.Notebook(self.main_container, style="Custom.TNotebook")
        self.notebook.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        # Create tabs
        self.monitoring_tab = ttk.Frame(self.notebook)
        self.rules_tab = ttk.Frame(self.notebook)
        self.stats_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.monitoring_tab, text="Live Monitoring")
        self.notebook.add(self.rules_tab, text="Firewall Rules")
        self.notebook.add(self.stats_tab, text="Statistics")
        
        # Setup tabs
        self.setup_monitoring_tab()
        self.setup_rules_tab()
        self.setup_stats_tab()
        
        # Initialize status bar
        self.setup_status_bar()
        
        # Configure grid weights
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        self.main_container.grid_rowconfigure(0, weight=1)
        self.main_container.grid_columnconfigure(0, weight=1)
        
        # Initialize variables
        self.is_capturing = False
        self.packet_count = 0
        
        # Start periodic updates
        self.update_status()
        self.update_logs()

    def setup_monitoring_tab(self):
        # Create frames for different sections
        log_frame = ttk.LabelFrame(self.monitoring_tab, text="Live Packet Logs", padding="5")
        log_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        # Create log displays with labels
        allowed_frame = ttk.Frame(log_frame)
        allowed_frame.grid(row=0, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")
        
        ttk.Label(allowed_frame, text="Allowed Packets", font=('Helvetica', 10, 'bold')).pack()
        self.allowed_log = scrolledtext.ScrolledText(allowed_frame, height=15, width=60,
                                                   font=('Consolas', 10), bg="#0f172a", fg="#4ade80")
        self.allowed_log.pack(expand=True, fill="both")
        
        blocked_frame = ttk.Frame(log_frame)
        blocked_frame.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
        
        ttk.Label(blocked_frame, text="Blocked Packets", font=('Helvetica', 10, 'bold')).pack()
        self.blocked_log = scrolledtext.ScrolledText(blocked_frame, height=15, width=60,
                                                   font=('Consolas', 10), bg="#0f172a", fg="#ef4444")
        self.blocked_log.pack(expand=True, fill="both")
        
        alert_frame = ttk.Frame(log_frame)
        alert_frame.grid(row=1, column=1, padx=5, pady=5, sticky="nsew")
        
        ttk.Label(alert_frame, text="Alerts", font=('Helvetica', 10, 'bold')).pack()
        self.alert_log = scrolledtext.ScrolledText(alert_frame, height=15, width=60,
                                                  font=('Consolas', 10), bg="#0f172a", fg="#f59e0b")
        self.alert_log.pack(expand=True, fill="both")
        # Control buttons
        control_frame = ttk.Frame(self.monitoring_tab)
        control_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=5)
        
        self.start_button = ttk.Button(control_frame, text="Start Capture", command=self.start_capture)
        self.start_button.pack(side="left", padx=5)
        
        self.stop_button = ttk.Button(control_frame, text="Stop Capture", command=self.stop_capture, state="disabled")
        self.stop_button.pack(side="left", padx=5)
        
        self.clear_button = ttk.Button(control_frame, text="Clear Logs", command=self.clear_logs)
        self.clear_button.pack(side="left", padx=5)

    def setup_rules_tab(self):
        # IP Management
        ip_frame = ttk.LabelFrame(self.rules_tab, text="IP Management", padding="5")
        ip_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        ttk.Label(ip_frame, text="IP Address:").grid(row=0, column=0, padx=5, pady=5)
        self.ip_entry = ttk.Entry(ip_frame, width=20)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(ip_frame, text="Add IP", command=self.add_ip).grid(row=0, column=2, padx=5, pady=5)
        ttk.Button(ip_frame, text="Remove IP", command=self.remove_ip).grid(row=0, column=3, padx=5, pady=5)
        
        # Blacklisted IPs display
        self.blacklist_display = scrolledtext.ScrolledText(ip_frame, height=5, width=40)
        self.blacklist_display.grid(row=1, column=0, columnspan=4, padx=5, pady=5)
        
        # Port Management
        port_frame = ttk.LabelFrame(self.rules_tab, text="Port Management", padding="5")
        port_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        
        ttk.Label(port_frame, text="Port:").grid(row=0, column=0, padx=5, pady=5)
        self.port_entry = ttk.Entry(port_frame, width=20)
        self.port_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(port_frame, text="Add Port", command=self.add_port).grid(row=0, column=2, padx=5, pady=5)
        ttk.Button(port_frame, text="Remove Port", command=self.remove_port).grid(row=0, column=3, padx=5, pady=5)
        
        # Blocked Ports display
        self.ports_display = scrolledtext.ScrolledText(port_frame, height=5, width=40)
        self.ports_display.grid(row=1, column=0, columnspan=4, padx=5, pady=5)
        

       # Packet Size Management
        size_frame = ttk.LabelFrame(self.rules_tab, text="Packet Size Management", padding="5")
        size_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)

        ttk.Label(size_frame, text="Max Packet Size (bytes):").grid(row=0, column=0, padx=5, pady=5)
        self.size_entry = ttk.Entry(size_frame, width=20)
        self.size_entry.grid(row=0, column=1, padx=5, pady=5)
        self.size_entry.insert(0, str(packet_filter.MAX_PACKET_SIZE))

        ttk.Button(size_frame, text="Apply", command=self.apply_max_packet_size).grid(row=0, column=2, padx=5, pady=5)

        # DoS Threshold Management
        dos_frame = ttk.LabelFrame(self.rules_tab, text="DoS Threshold Management", padding="5")
        dos_frame.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)

        ttk.Label(dos_frame, text="DoS Threshold (packets/IP):").grid(row=0, column=0, padx=5, pady=5)
        self.dos_threshold_entry = ttk.Entry(dos_frame, width=20)
        self.dos_threshold_entry.grid(row=0, column=1, padx=5, pady=5)
        self.dos_threshold_entry.insert(0, str(packet_filter.DOS_THRESHOLD))

        ttk.Button(dos_frame, text="Apply", command=self.apply_dos_threshold).grid(row=0, column=2, padx=5, pady=5)

        ttk.Label(dos_frame, text="DoS Time Interval (seconds):").grid(row=1, column=0, padx=5, pady=5)
        self.dos_interval_entry = ttk.Entry(dos_frame, width=20)
        self.dos_interval_entry.grid(row=1, column=1, padx=5, pady=5)
        self.dos_interval_entry.insert(0, str(packet_filter.DOS_TIME_INTERVAL))

        ttk.Button(dos_frame, text="Apply", command=self.apply_dos_interval).grid(row=1, column=2, padx=5, pady=5)
        # Update displays
        self.update_rule_displays()

    def setup_stats_tab(self):
        stats_frame = ttk.LabelFrame(self.stats_tab, text="Packet Statistics", padding="5")
        stats_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        # Statistics display
        self.stats_display = scrolledtext.ScrolledText(stats_frame, height=20, width=50,
                                                     font=('Consolas', 10), bg="#0f172a", fg="#60a5fa")
        self.stats_display.pack(expand=True, fill="both", padx=5, pady=5)

    def setup_status_bar(self):
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, padding=(5, 2))
        self.status_bar.grid(row=1, column=0, sticky="ew")
        
        # Packet counter
        self.packet_counter = ttk.Label(self.status_bar, text="Packets: 0")
        self.packet_counter.pack(side="right", padx=5)
        
        # Status text
        self.status_text = ttk.Label(self.status_bar, text="Status: Ready")
        self.status_text.pack(side="left", padx=5)

    def start_capture(self):
        self.is_capturing = True
        packet_filter.reset_logs()
        self.clear_logs()
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        packet_filter.stop_event.clear()
        Thread(target=packet_filter.capture_packets, daemon=True).start()
        self.status_text.config(text="Status: Capturing")
        self.log_action("Started packet capture")

    def stop_capture(self):
        self.is_capturing = False
        packet_filter.stop_capture()
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        
        # Show summary log as message box
        try:
            with open(packet_filter.SUMMARY_LOG_FILE, "r") as f:
                summary = f.read().strip()
            messagebox.showinfo("Capture Summary", summary)
        except Exception as e:
            messagebox.showerror("Error", f"Error reading summary log: {str(e)}")
        
        self.status_text.config(text="Status: Stopped")
        self.log_action("Stopped packet capture")
        
        # Clear all logs after stopping capture
        self.clear_logs()

    def clear_logs(self):
        # Clear the log text areas in the GUI
        self.allowed_log.delete(1.0, tk.END)
        self.blocked_log.delete(1.0, tk.END)
        self.stats_display.delete(1.0, tk.END)
        self.alert_log.delete(1.0, tk.END)
        
        # Reset packet count
        self.packet_count = 0
        self.update_packet_counter()
        
        # File paths for the log files
        log_files = [
            "logs/summary.log",
            "logs/blocked.log",
            "logs/allowed.log",
            "logs/maliscious.log"
        ]
        
        # Clear the contents of the log files
        for log_file in log_files:
            try:
                with open(log_file, "w") as file:
                    file.truncate(0)  # Clears the file content
            except Exception as e:
                self.log_action(f"Error clearing log file {log_file}: {str(e)}")
        
        # Also clear the summary log file
        try:
            with open(packet_filter.SUMMARY_LOG_FILE, "w") as file:
                packet_filter.packet_summary={  # Reset the packet summary
                    "total": 0,
                    "allowed": 0,
                    "blocked": 0,
                    "malicious": 0
                }
                file.truncate(0)  # Clears the file content
        except Exception as e:
            self.log_action(f"Error clearing summary log file: {str(e)}")
    
        # Log the clear action
        self.log_action("Cleared all logs, including summary")

    def update_logs(self):
        try:
            # Update allowed log
            with open(packet_filter.ALLOWED_LOG_FILE, "r") as f:
                current_allowed = self.allowed_log.get(1.0, tk.END).strip()
                new_allowed = f.read().strip()
                if new_allowed != current_allowed:
                    self.allowed_log.delete(1.0, tk.END)
                    self.allowed_log.insert(tk.END, new_allowed)
                    self.allowed_log.see(tk.END)
            
            # Update blocked log
            with open(packet_filter.ALERT_LOG_FILE, "r") as f:
                current_blocked = self.blocked_log.get(1.0, tk.END).strip()
                new_blocked = f.read().strip()
                if new_blocked != current_blocked:
                    self.blocked_log.delete(1.0, tk.END)
                    self.blocked_log.insert(tk.END, new_blocked)
                    self.blocked_log.see(tk.END)

            with open(packet_filter.Maliscious_LOG_FILE, "r") as f:
                current_alerts = self.alert_log.get(1.0, tk.END).strip()
                new_alerts = f.read().strip()
                if new_alerts != current_alerts:
                    self.alert_log.delete(1.0, tk.END)
                    self.alert_log.insert(tk.END, new_alerts)
                    self.alert_log.see(tk.END)
                    # Check for DoS attack message
                    if "Detected DoS Attack" in new_alerts:
                        self.show_alert("DoS Attack Detected!", "Warning: A Denial of Service (DoS) attack has been detected!")
            
            # Update statistics
            with open(packet_filter.SUMMARY_LOG_FILE, "r") as f:
                current_stats = self.stats_display.get(1.0, tk.END).strip()
                new_stats = f.read().strip()
                if new_stats != current_stats:
                    self.stats_display.delete(1.0, tk.END)
                    self.stats_display.insert(tk.END, new_stats)
                    self.packet_count = packet_filter.packet_summary["total"]
                    
        except Exception as e:
            self.log_action(f"Error updating logs: {str(e)}")
        
        # Schedule next update
        self.root.after(1000, self.update_logs)

    def show_alert(self, title, message):
        # Show a warning message with an icon and sound
        messagebox.showwarning(title, message)
        
        # Play a warning sound (Windows-specific)
        winsound.Beep(1000, 500)  # 1000 Hz for 500 ms

    def update_status(self):
        current_time = datetime.now().strftime("%H:%M:%S")
        self.status_text.config(text=f"Status: {'Capturing' if self.is_capturing else 'Ready'} | Time: {current_time}")
        self.root.after(1000, self.update_status)

    def update_packet_counter(self):
        self.packet_counter.config(text=f"Packets: {self.packet_count}")

    def update_rule_displays(self):
        # Schedule the next refresh
        self.root.after(1000, self.update_rule_displays)
        # Update IP display
        self.blacklist_display.delete(1.0, tk.END)
        ips = "\n".join(packet_filter.BLACKLISTED_IPS) if packet_filter.BLACKLISTED_IPS else "No blacklisted IPs"
        self.blacklist_display.insert(tk.END, ips)
        
        # Update Port display
        self.ports_display.delete(1.0, tk.END)
        ports = "\n".join(map(str, packet_filter.BLOCKED_PORTS)) if packet_filter.BLOCKED_PORTS else "No blocked ports"
        self.ports_display.insert(tk.END, ports)

    def log_action(self, message):
        # Add to logs with timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} - {message}")

    def add_ip(self):
        ip = self.ip_entry.get().strip()
        if ip and ip not in packet_filter.BLACKLISTED_IPS:
            packet_filter.add_blacklisted_ip(ip)
            self.update_rule_displays()
            self.log_action(f"Added IP: {ip}")
        else:
            messagebox.showerror("Invalid IP", "Invalid or duplicate IP address.")

    def remove_ip(self):
        ip = self.ip_entry.get().strip()
        if ip and ip in packet_filter.BLACKLISTED_IPS:
            packet_filter.remove_blacklisted_ip(ip)
            self.update_rule_displays()
            self.log_action(f"Removed IP: {ip}")
        else:
            messagebox.showerror("Invalid IP", "IP address not found in blacklist.")

    def add_port(self):
        port = self.port_entry.get().strip()
        if port.isdigit() and 1 <= int(port) <= 65535 and int(port) not in packet_filter.BLOCKED_PORTS:
            packet_filter.add_blocked_port(int(port))
            self.update_rule_displays()
            self.log_action(f"Added port: {port}")
        else:
            messagebox.showerror("Invalid Port", "Invalid or duplicate port.")

    def remove_port(self):
        port = self.port_entry.get().strip()
        if port.isdigit() and int(port) in packet_filter.BLOCKED_PORTS:
            packet_filter.remove_blocked_port(int(port))
            self.update_rule_displays()
            self.log_action(f"Removed port: {port}")
        else:
            messagebox.showerror("Invalid Port", "Port not found in blocked ports.")
    def apply_max_packet_size(self):
        size = self.size_entry.get().strip()
        if size.isdigit() and int(size) > 0:
            packet_filter.MAX_PACKET_SIZE = int(size)
            self.log_action(f"Set MAX_PACKET_SIZE to {size} bytes")
        else:
            messagebox.showerror("Invalid Size", "Invalid packet size.")

    def apply_dos_threshold(self):
        threshold = self.dos_threshold_entry.get().strip()
        if threshold.isdigit() and int(threshold) > 0:
            packet_filter.DOS_THRESHOLD = int(threshold)
            self.log_action(f"Set DOS_THRESHOLD to {threshold} packets/IP")
        else:
            messagebox.showerror("Invalid Threshold", "Invalid DoS threshold.")

    def apply_dos_interval(self):
        interval = self.dos_interval_entry.get().strip()
        if interval.isdigit() and int(interval) > 0:
            packet_filter.DOS_TIME_INTERVAL = int(interval)
            self.log_action(f"Set DOS_TIME_INTERVAL to {interval} seconds")
        else:
            messagebox.showerror("Invalid Interval", "Invalid DoS time interval.")


# Main execution
if __name__ == "__main__":
    root = tk.Tk()
    gui = FirewallGUI(root)
    root.mainloop()
