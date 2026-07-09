import os
import sys
import json
import subprocess
import threading
import tkinter as tk
from tkinter import messagebox
from datetime import datetime

# Relaunch script using the virtual environment python interpreter if customtkinter is missing
try:
    import customtkinter
except ImportError:
    # Path to virtual environment python interpreter on Windows
    venv_python = os.path.join(os.path.dirname(__file__), ".venv", "Scripts", "python.exe")
    if os.path.exists(venv_python) and sys.executable != venv_python:
        subprocess.run([venv_python] + sys.argv)
        sys.exit(0)
    else:
        print("customtkinter is not installed. Please install it using: pip install customtkinter")
        sys.exit(1)

# Configure CustomTkinter appearance
customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("blue")

def load_stats():
    """
    Dynamically loads metrics from the simulation files (scan_history.json, reports/, quarantine/).
    """
    history_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_history.json")
    quarantine_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")
    reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    
    total_scans = 0
    threats_detected = 0
    files_quarantined = 0
    integrity_alerts = 0
    
    # 1. Total Scans & Threats Detected from scan history
    if os.path.exists(history_file):
        try:
            with open(history_file, "r") as f:
                history = json.load(f)
                total_scans = len(history)
                threats_detected = sum(entry.get("malicious_files", 0) for entry in history)
        except Exception:
            pass
            
    # 2. Total Quarantined Files count in quarantine folder
    if os.path.exists(quarantine_dir):
        try:
            files_quarantined = len([f for f in os.listdir(quarantine_dir) if os.path.isfile(os.path.join(quarantine_dir, f))])
        except Exception:
            pass
            
    # 3. Integrity Alerts count parsed across all integrity reports
    if os.path.exists(reports_dir):
        try:
            for report_file in os.listdir(reports_dir):
                if report_file.startswith("integrity_report_") and report_file.endswith(".txt"):
                    path = os.path.join(reports_dir, report_file)
                    with open(path, "r") as f:
                        content = f.read()
                        for line in content.splitlines():
                            if "Modified Files:" in line:
                                integrity_alerts += int(line.split(":")[-1].strip())
                            elif "Deleted Files:" in line:
                                integrity_alerts += int(line.split(":")[-1].strip())
                            elif "New Files:" in line:
                                integrity_alerts += int(line.split(":")[-1].strip())
        except Exception:
            pass
            
    return {
        "total_scans": total_scans,
        "threats_detected": threats_detected,
        "files_quarantined": files_quarantined,
        "integrity_alerts": integrity_alerts
    }


class AntivirusGUI(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        
        # Configure Main Window
        self.title("Basic Antivirus Simulation V2")
        self.geometry("1400x800")
        self.minsize(1200, 750)
        self.configure(fg_color="#0F172A") # Background: Slate 900
        
        # Theme Configurations
        self.sidebar_bg = "#1E293B"       # Slate 800
        self.button_color = "#334155"     # Slate 700
        self.button_hover = "#475569"     # Slate 600
        self.accent_color = "#3B82F6"     # Blue 500
        self.accent_hover = "#2563EB"     # Blue 600
        
        # Load Signature count for system information
        try:
            sys.path.append(os.path.dirname(os.path.abspath(__file__)))
            from scanner import load_signatures
            self.sig_count = len(load_signatures())
        except Exception:
            self.sig_count = 0
            
        # Create UI Components
        self.create_layout()
        
        # Initial views populating
        self.refresh_all_views()
        
    def create_layout(self):
        # Configure root responsive weights
        self.grid_columnconfigure(0, weight=0) # Sidebar: Fixed width
        self.grid_columnconfigure(1, weight=1) # Main Frame: Responsive
        self.grid_rowconfigure(0, weight=1)
        
        # =====================================================================
        # 1. SIDEBAR FRAME
        # =====================================================================
        sidebar_frame = customtkinter.CTkFrame(self, fg_color=self.sidebar_bg, corner_radius=0, width=280)
        sidebar_frame.grid(row=0, column=0, sticky="nsew")
        sidebar_frame.grid_rowconfigure(9, weight=1) # Push exit button down
        
        # Title/Logo Area
        logo_label = customtkinter.CTkLabel(
            sidebar_frame, 
            text="🛡️ SIM SHIELD", 
            font=("Segoe UI", 20, "bold"), 
            text_color=self.accent_color
        )
        logo_label.grid(row=0, column=0, padx=25, pady=(30, 5), sticky="w")
        
        logo_subtitle = customtkinter.CTkLabel(
            sidebar_frame, 
            text="Simulation Control Hub", 
            font=("Segoe UI", 11, "italic"), 
            text_color="#94A3B8"
        )
        logo_subtitle.grid(row=1, column=0, padx=25, pady=(0, 30), sticky="w")
        
        # Sidebar Action Buttons
        sidebar_buttons = [
            ("🔍 Malware Scan", self.run_malware_scan),
            ("➕ Create Baseline", self.create_baseline),
            ("🔄 Integrity Scan", self.run_integrity_scan),
            ("📁 Reports", self.go_to_reports),
            ("📜 Scan History", self.go_to_history),
            ("☣️ Quarantine", self.show_quarantine),
        ]
        
        row_idx = 2
        for text, command in sidebar_buttons:
            btn = customtkinter.CTkButton(
                sidebar_frame,
                text=text,
                command=command,
                fg_color=self.button_color,
                hover_color=self.button_hover,
                text_color="white",
                font=("Segoe UI", 12, "bold"),
                height=45,
                anchor="w",
                corner_radius=8
            )
            btn.grid(row=row_idx, column=0, padx=20, pady=8, sticky="ew")
            row_idx += 1
            
        # Exit Button in Sidebar
        exit_btn = customtkinter.CTkButton(
            sidebar_frame,
            text="❌ Exit Hub",
            command=self.exit_app,
            fg_color="#EF4444",
            hover_color="#DC2626",
            text_color="white",
            font=("Segoe UI", 12, "bold"),
            height=45,
            anchor="w",
            corner_radius=8
        )
        exit_btn.grid(row=10, column=0, padx=20, pady=30, sticky="ew")
        
        # =====================================================================
        # 2. MAIN LAYOUT CONTAINER
        # =====================================================================
        main_frame = customtkinter.CTkFrame(self, fg_color="transparent")
        main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(1, weight=1) # Tabview consumes space
        
        # Header Label (Window Title inside the App Layout)
        header_lbl = customtkinter.CTkLabel(
            main_frame,
            text="Basic Antivirus Simulation V2",
            font=("Segoe UI", 26, "bold"),
            text_color="white"
        )
        header_lbl.grid(row=0, column=0, pady=(10, 20), sticky="w")
        
        # =====================================================================
        # 3. TABVIEW (MAIN CONTENT AREA)
        # =====================================================================
        self.tabview = customtkinter.CTkTabview(
            main_frame, 
            fg_color="#1E293B",
            segmented_button_fg_color="#0F172A",
            segmented_button_selected_color=self.accent_color,
            segmented_button_selected_hover_color=self.accent_hover,
            segmented_button_unselected_color="#0F172A",
            segmented_button_unselected_hover_color=self.button_hover
        )
        self.tabview.grid(row=1, column=0, sticky="nsew")
        
        # Add Tabs
        self.tabview.add("Dashboard")
        self.tabview.add("Scan Results")
        self.tabview.add("Reports")
        self.tabview.add("History")
        
        self.setup_dashboard_tab()
        self.setup_scan_results_tab()
        self.setup_reports_tab()
        self.setup_history_tab()
        
        # =====================================================================
        # 4. STATUS BAR
        # =====================================================================
        self.status_frame = customtkinter.CTkFrame(main_frame, fg_color="#1E293B", height=40, corner_radius=6)
        self.status_frame.grid(row=2, column=0, pady=(15, 0), sticky="ew")
        self.status_frame.grid_columnconfigure(0, weight=1)
        
        self.status_label = customtkinter.CTkLabel(
            self.status_frame, 
            text="System Status: READY", 
            font=("Segoe UI", 12, "bold"), 
            text_color="#10B981"
        )
        self.status_label.grid(row=0, column=0, padx=15, pady=5, sticky="w")
        
        self.db_label = customtkinter.CTkLabel(
            self.status_frame, 
            text=f"Signature Base: {self.sig_count} loaded", 
            font=("Segoe UI", 12), 
            text_color="#94A3B8"
        )
        self.db_label.grid(row=0, column=1, padx=15, pady=5, sticky="e")
        
    # =====================================================================
    # TAB CONFIGURATIONS
    # =====================================================================
    def setup_dashboard_tab(self):
        tab = self.tabview.tab("Dashboard")
        tab.grid_columnconfigure((0, 1, 2, 3), weight=1, uniform="equal")
        tab.grid_rowconfigure(2, weight=1) # Grid row stretchiness
        
        # 1. Dashboard Metrics Cards
        self.card_total_scans = self.create_card(tab, "🔍 TOTAL SCANS", "0", 0, 0, self.accent_color)
        self.card_threats = self.create_card(tab, "⚠️ THREATS DETECTED", "0", 0, 1, "#EF4444")
        self.card_quarantined = self.create_card(tab, "🛡️ QUARANTINED FILES", "0", 0, 2, "#10B981")
        self.card_integrity = self.create_card(tab, "🚨 INTEGRITY ALERTS", "0", 0, 3, "#F59E0B")
        
        # 2. System Health Summary Card
        health_frame = customtkinter.CTkFrame(tab, fg_color="#0F172A", corner_radius=10, border_color="#1E293B", border_width=1)
        health_frame.grid(row=1, column=0, columnspan=4, padx=10, pady=10, sticky="nsew")
        health_frame.grid_columnconfigure(0, weight=1)
        
        self.health_title = customtkinter.CTkLabel(
            health_frame, 
            text="🟢 SYSTEM HEALTH: SECURED", 
            font=("Segoe UI", 18, "bold"), 
            text_color="#10B981"
        )
        self.health_title.grid(row=0, column=0, padx=20, pady=(20, 5), sticky="w")
        
        self.health_desc = customtkinter.CTkLabel(
            health_frame, 
            text="All files checked, no malware detected, and integrity baseline is up to date.", 
            font=("Segoe UI", 13), 
            text_color="#94A3B8"
        )
        self.health_desc.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="w")
        
        # 3. Project Configuration/Directories Info Box
        info_frame = customtkinter.CTkFrame(tab, fg_color="#0F172A", corner_radius=10, border_color="#1E293B", border_width=1)
        info_frame.grid(row=2, column=0, columnspan=4, padx=10, pady=10, sticky="nsew")
        info_frame.grid_columnconfigure((0, 1), weight=1)
        
        left_info = (
            f"Simulation Path:\n  {os.path.dirname(os.path.abspath(__file__))}\n\n"
            "Active Directories:\n"
            "  📂 test_files/     (Scanning Directory Target)\n"
            "  📂 quarantine/     (Malicious File Isolation Vault)\n"
            "  📂 reports/        (Automated Reports Output Folder)"
        )
        left_label = customtkinter.CTkLabel(
            info_frame, 
            text=left_info, 
            font=("Segoe UI", 13), 
            text_color="#CBD5E1", 
            justify="left",
            anchor="w"
        )
        left_label.grid(row=0, column=0, padx=25, pady=25, sticky="w")
        
        right_info = (
            "Signature Configuration:\n"
            "  📄 malware_signatures.txt (Contains target SHA-256 signatures)\n"
            "  ⚙️ Status: ACTIVE\n\n"
            "Integrity Parameters:\n"
            "  📄 baseline.json (Holds trusted environment snapshot)\n"
            "  ⚙️ Status: ACTIVE"
        )
        right_label = customtkinter.CTkLabel(
            info_frame, 
            text=right_info, 
            font=("Segoe UI", 13), 
            text_color="#CBD5E1", 
            justify="left",
            anchor="w"
        )
        right_label.grid(row=0, column=1, padx=25, pady=25, sticky="w")
        
    def create_card(self, parent, title, value, row, col, border_col):
        """Creates a stylized metric card for security overview."""
        card = customtkinter.CTkFrame(
            parent, 
            fg_color="#0F172A", 
            border_color=border_col, 
            border_width=1, 
            corner_radius=10
        )
        card.grid(row=row, column=col, padx=10, pady=(20, 10), sticky="nsew")
        card.grid_columnconfigure(0, weight=1)
        
        title_lbl = customtkinter.CTkLabel(
            card, 
            text=title, 
            font=("Segoe UI", 12, "bold"), 
            text_color="#94A3B8"
        )
        title_lbl.grid(row=0, column=0, padx=20, pady=(20, 5), sticky="w")
        
        value_lbl = customtkinter.CTkLabel(
            card, 
            text=value, 
            font=("Segoe UI", 34, "bold"), 
            text_color=border_col
        )
        value_lbl.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="w")
        
        return value_lbl
        
    def setup_scan_results_tab(self):
        tab = self.tabview.tab("Scan Results")
        tab.grid_rowconfigure(1, weight=1)
        tab.grid_columnconfigure(0, weight=1)
        
        # Sub-header Status Info
        self.scan_status_label = customtkinter.CTkLabel(
            tab, 
            text="Antivirus Engine Ready. Trigger a scan from the control sidebar.", 
            font=("Segoe UI", 13, "italic"),
            text_color="#94A3B8"
        )
        self.scan_status_label.grid(row=0, column=0, padx=15, pady=(10, 5), sticky="w")
        
        # Scrolled console Textbox
        self.output_text = customtkinter.CTkTextbox(
            tab,
            fg_color="#0F172A",
            text_color="#E2E8F0",
            font=("Consolas", 12),
            corner_radius=8,
            border_color="#1E293B",
            border_width=1
        )
        self.output_text.grid(row=1, column=0, padx=15, pady=10, sticky="nsew")
        self.output_text.configure(state="disabled")
        
        # Indeterminate scanning progress bar
        self.progress_bar = customtkinter.CTkProgressBar(
            tab, 
            orientation="horizontal", 
            height=6, 
            fg_color="#0F172A", 
            progress_color=self.accent_color
        )
        self.progress_bar.grid(row=2, column=0, padx=15, pady=(5, 15), sticky="ew")
        self.progress_bar.set(0)
        
    def setup_reports_tab(self):
        tab = self.tabview.tab("Reports")
        tab.grid_rowconfigure(0, weight=1)
        tab.grid_columnconfigure(0, weight=1)  # Left sidebar (width ratio 1)
        tab.grid_columnconfigure(1, weight=3)  # Right detail (width ratio 3)
        
        # Left sidebar frame for reports selection list
        list_frame = customtkinter.CTkFrame(tab, fg_color="#0F172A", corner_radius=8, border_color="#1E293B", border_width=1)
        list_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        list_frame.grid_rowconfigure(1, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)
        
        list_header = customtkinter.CTkLabel(
            list_frame, 
            text="📂 Generated Logs", 
            font=("Segoe UI", 14, "bold"), 
            text_color="white"
        )
        list_header.grid(row=0, column=0, padx=15, pady=(15, 5), sticky="w")
        
        # Scrollable panel for log file selection buttons
        self.reports_scroll = customtkinter.CTkScrollableFrame(list_frame, fg_color="transparent")
        self.reports_scroll.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
        
        # Right frame for displaying selected log content
        detail_frame = customtkinter.CTkFrame(tab, fg_color="#0F172A", corner_radius=8, border_color="#1E293B", border_width=1)
        detail_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        detail_frame.grid_rowconfigure(1, weight=1)
        detail_frame.grid_columnconfigure(0, weight=1)
        
        self.report_view_title = customtkinter.CTkLabel(
            detail_frame, 
            text="Select a scan report file on the left to review metrics", 
            font=("Segoe UI", 14, "bold"), 
            text_color="white"
        )
        self.report_view_title.grid(row=0, column=0, padx=20, pady=(15, 5), sticky="w")
        
        self.report_view_text = customtkinter.CTkTextbox(
            detail_frame,
            fg_color="#0F172A",
            text_color="#CBD5E1",
            font=("Consolas", 12),
            corner_radius=8,
            border_color="#1E293B",
            border_width=1
        )
        self.report_view_text.grid(row=1, column=0, padx=20, pady=(5, 20), sticky="nsew")
        self.report_view_text.configure(state="disabled")
        
    def setup_history_tab(self):
        tab = self.tabview.tab("History")
        tab.grid_rowconfigure(1, weight=1)
        tab.grid_columnconfigure(0, weight=1)
        
        list_header = customtkinter.CTkLabel(
            tab, 
            text="📜 Historical Antivirus Runs", 
            font=("Segoe UI", 16, "bold"), 
            text_color="white"
        )
        list_header.grid(row=0, column=0, padx=15, pady=(15, 5), sticky="w")
        
        # Scrollable area to display structured history cards
        self.history_scroll = customtkinter.CTkScrollableFrame(tab, fg_color="transparent")
        self.history_scroll.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        
    # =====================================================================
    # VIEW SYNCRONIZATIONS
    # =====================================================================
    def refresh_all_views(self):
        self.update_dashboard()
        self.populate_reports_list()
        self.populate_history_list()
        
    def update_dashboard(self):
        """Fetches fresh metrics and updates UI cards and status indicators."""
        stats = load_stats()
        
        # Update metrics labels
        self.card_total_scans.configure(text=str(stats["total_scans"]))
        self.card_threats.configure(text=str(stats["threats_detected"]))
        self.card_quarantined.configure(text=str(stats["files_quarantined"]))
        self.card_integrity.configure(text=str(stats["integrity_alerts"]))
        
        # Update health status bar indicators
        if stats["threats_detected"] > 0 or stats["integrity_alerts"] > 0:
            self.health_title.configure(text="🔴 SYSTEM HEALTH: ACTION REQUIRED", text_color="#EF4444")
            self.health_desc.configure(
                text="Security alerts found. Unsafe files detected, quarantined, or file integrity snap matches failed. Review history logs."
            )
            self.status_label.configure(text="System Status: ALERTS REPORTED", text_color="#EF4444")
        else:
            self.health_title.configure(text="🟢 SYSTEM HEALTH: SECURED", text_color="#10B981")
            self.health_desc.configure(
                text="All checks clean. Antivirus signature database loaded and file integrity verification is normal."
            )
            self.status_label.configure(text="System Status: READY", text_color="#10B981")
            
    def populate_reports_list(self):
        """Finds all report files and populates selection buttons in the reports scrollview."""
        for widget in self.reports_scroll.winfo_children():
            widget.destroy()
            
        reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
        if not os.path.exists(reports_dir):
            return
            
        try:
            files = sorted([f for f in os.listdir(reports_dir) if f.endswith(".txt")], reverse=True)
            for filename in files:
                emoji = "📝" if "integrity" in filename else "🔍"
                btn = customtkinter.CTkButton(
                    self.reports_scroll,
                    text=f"{emoji} {filename}",
                    anchor="w",
                    fg_color=self.button_color,
                    hover_color=self.button_hover,
                    text_color="white",
                    font=("Segoe UI", 11),
                    height=35,
                    command=lambda fn=filename: self.view_report_detail(fn)
                )
                btn.pack(fill=tk.X, padx=5, pady=4)
        except Exception:
            pass
            
    def view_report_detail(self, filename):
        """Reads selected report content and displays in the panel viewer."""
        reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
        path = os.path.join(reports_dir, filename)
        
        self.report_view_title.configure(text=f"📄 Log view: {filename}")
        
        try:
            with open(path, "r") as f:
                content = f.read()
            self.report_view_text.configure(state="normal")
            self.report_view_text.delete("1.0", tk.END)
            self.report_view_text.insert(tk.END, content)
            self.report_view_text.configure(state="disabled")
        except Exception as e:
            messagebox.showerror("Read Error", f"Could not view report logs: {e}")
            
    def populate_history_list(self):
        """Generates dynamic historical cards for each run logged in scan_history.json."""
        for widget in self.history_scroll.winfo_children():
            widget.destroy()
            
        history_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_history.json")
        if not os.path.exists(history_file):
            lbl = customtkinter.CTkLabel(self.history_scroll, text="No historical logs recorded.", font=("Segoe UI", 13), text_color="#94A3B8")
            lbl.pack(pady=20)
            return
            
        try:
            with open(history_file, "r") as f:
                history = json.load(f)
                
            if not history:
                lbl = customtkinter.CTkLabel(self.history_scroll, text="No scan history found.", font=("Segoe UI", 13), text_color="#94A3B8")
                lbl.pack(pady=20)
                return
                
            for idx, entry in enumerate(reversed(history)):
                timestamp = entry.get("timestamp", "N/A")
                total = entry.get("total_files", 0)
                safe = entry.get("safe_files", 0)
                malicious = entry.get("malicious_files", 0)
                quarantined = entry.get("files_quarantined", 0)
                
                # If threat detected, color border red, otherwise dark slate gray
                border_col = "#EF4444" if malicious > 0 else "#334155"
                card_bg = "#0F172A"
                
                card = customtkinter.CTkFrame(
                    self.history_scroll, 
                    fg_color=card_bg, 
                    border_color=border_col, 
                    border_width=1, 
                    corner_radius=8
                )
                card.pack(fill=tk.X, padx=10, pady=5)
                
                title_lbl = customtkinter.CTkLabel(
                    card, 
                    text=f"🛡️ Scan Report #{len(history) - idx}  |  🕒 {timestamp}", 
                    font=("Segoe UI", 13, "bold"), 
                    text_color="white"
                )
                title_lbl.pack(anchor="w", padx=20, pady=(12, 6))
                
                metrics_text = f"Scanned: {total} files   |   Safe: {safe}   |   Threats Found: {malicious}   |   Quarantined: {quarantined}"
                metrics_lbl = customtkinter.CTkLabel(card, text=metrics_text, font=("Segoe UI", 12), text_color="#94A3B8")
                metrics_lbl.pack(anchor="w", padx=20, pady=(0, 12))
                
        except Exception as e:
            lbl = customtkinter.CTkLabel(self.history_scroll, text=f"Failed to read logs: {e}", font=("Segoe UI", 13), text_color="#EF4444")
            lbl.pack(pady=20)

    # =====================================================================
    # CONSOLE DISPLAY LOGGER
    # =====================================================================
    def write_output(self, text):
        self.output_text.configure(state="normal")
        self.output_text.insert(customtkinter.END, text)
        self.output_text.see(customtkinter.END)
        self.output_text.configure(state="disabled")
        
    def clear_output(self):
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", customtkinter.END)
        self.output_text.configure(state="disabled")

    # =====================================================================
    # SUBPROCESS BACKGROUND RUNNER (THREADED)
    # =====================================================================
    def run_process_threaded(self, command, task_name, on_complete_callback):
        """
        Runs the simulation executable inside a separate Thread. Keeps the GUI
        active, pulses the progress bar, and updates status values on completion.
        """
        self.status_label.configure(text=f"System Status: {task_name.upper()} ACTIVE...", text_color=self.accent_color)
        self.scan_status_label.configure(text=f"Executing simulation module: {task_name}...")
        self.progress_bar.start()
        
        self.clear_output()
        self.write_output(f"============================================================\n")
        self.write_output(f"[START] {task_name.upper()} MODULE INITIALIZED\n")
        self.write_output(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.write_output(f"============================================================\n\n")
        
        def run_thread():
            try:
                # Runs with sys.executable to stay within environment pathings
                result = subprocess.run(
                    [sys.executable] + command,
                    capture_output=True,
                    text=True,
                    check=True
                )
                stdout, stderr = result.stdout, None
            except subprocess.CalledProcessError as e:
                stdout, stderr = e.stdout, e.stderr
            except Exception as e:
                stdout, stderr = "", str(e)
                
            # Safely schedule result updates back into main loop
            self.after(0, lambda: self.finish_process(stdout, stderr, task_name, on_complete_callback))
            
        threading.Thread(target=run_thread, daemon=True).start()
        
    def finish_process(self, stdout, stderr, task_name, on_complete_callback):
        self.progress_bar.stop()
        self.progress_bar.set(0)
        self.status_label.configure(text="System Status: READY", text_color="#10B981")
        self.scan_status_label.configure(text="Engine idle. Output recorded below.")
        
        if stdout:
            self.write_output(stdout + "\n")
        if stderr:
            self.write_output(f"[ERROR] Executable raised exception:\n{stderr}\n")
            messagebox.showerror("Task Failed", f"{task_name} encountered an error:\n{stderr}")
        else:
            messagebox.showinfo("Task Complete", f"{task_name} finished successfully!")
            
        self.write_output(f"============================================================\n")
        self.write_output(f"[END] {task_name.upper()} PROCESSING COMPLETE\n")
        self.write_output(f"============================================================\n")
        
        # Reload views with fresh data
        if on_complete_callback:
            on_complete_callback()

    # =====================================================================
    # ACTION TRIGGERS
    # =====================================================================
    def run_malware_scan(self):
        self.tabview.set("Scan Results")
        self.run_process_threaded(["scanner.py"], "Malware Scan", self.refresh_all_views)
        
    def create_baseline(self):
        self.tabview.set("Scan Results")
        self.run_process_threaded(["integrity_monitor.py"], "Create Baseline", self.refresh_all_views)
        
    def run_integrity_scan(self):
        self.tabview.set("Scan Results")
        self.run_process_threaded(["integrity_monitor.py", "scan"], "Integrity Scan", self.refresh_all_views)
        
    def go_to_reports(self):
        self.tabview.set("Reports")
        self.populate_reports_list()
        
    def go_to_history(self):
        self.tabview.set("History")
        self.populate_history_list()
        
    def show_quarantine(self):
        self.tabview.set("Scan Results")
        self.clear_output()
        self.write_output(">>> Querying Quarantine Vault...\n")
        
        quarantine_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")
        if not os.path.exists(quarantine_dir):
            self.write_output("[INFO] Quarantine directory does not exist.\n\n")
            messagebox.showinfo("Quarantine Vault", "No quarantined threats found.")
            return
            
        try:
            files = os.listdir(quarantine_dir)
            if not files:
                self.write_output("Quarantine Vault is currently empty.\n\n")
                messagebox.showinfo("Quarantine Vault", "No quarantined threats found.")
                return
                
            self.write_output("=================================\n")
            self.write_output("QUARANTINED THREATS\n")
            self.write_output("===================\n")
            for filename in files:
                path = os.path.join(quarantine_dir, filename)
                size = os.path.getsize(path)
                self.write_output(f"⚠️ Filename: {filename} ({size} bytes)\n")
            self.write_output("=================================\n\n")
            messagebox.showinfo("Quarantine Vault", f"Found {len(files)} quarantined threats.")
        except Exception as e:
            self.write_output(f"[ERROR] Failed to query quarantine folder: {e}\n\n")
            messagebox.showerror("Error", f"Failed to retrieve quarantined files: {e}")
            
    def exit_app(self):
        if messagebox.askyesno("Exit Shield Hub", "Are you sure you want to exit?"):
            self.destroy()


if __name__ == "__main__":
    app = AntivirusGUI()
    app.mainloop()
