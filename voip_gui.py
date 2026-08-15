import tkinter as tk
from tkinter import ttk, scrolledtext, font, messagebox
import subprocess
import glob
import threading
import queue
import os
import json
import sys
import csv
from datetime import datetime

DUPLICATE_WINDOW_SECONDS = 10
DUPLICATE_DURATION_TOLERANCE = 0.5

class VoIPTrackerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("VoIP Sentinel")
        self.geometry("1050x700")
        self.configure(bg="#0d1117")

        # Color Palette
        self.bg_color = "#0d1117"       # Very dark near-black
        self.fg_color = "#c9d1d9"       # Light gray text
        self.accent_color = "#00d9ff"   # Teal/Blue accent
        self.card_bg = "#161b22"        # Slightly lighter for cards/panels

        self.process = None
        self.log_queue = queue.Queue()
        self.is_running = False

        # Stats
        self.calls_monitored = 0
        self.high_risk_count = 0
        self.session_start_time = "--:--"

        # Pulse animation state
        self.pulse_state = 0
        self.pulse_direction = 1

        self.setup_ui()
        self.poll_log_queue()
        self.pulse_status_dot()

    def setup_ui(self):
        # Fonts
        self.title_font = font.Font(family="Segoe UI", size=22, weight="bold")
        self.header_font = font.Font(family="Segoe UI", size=14, weight="bold")
        self.normal_font = font.Font(family="Segoe UI", size=11)
        self.small_font = font.Font(family="Segoe UI", size=9)
        self.mono_font = font.Font(family="Consolas", size=10)
        self.btn_font = font.Font(family="Segoe UI", size=11, weight="bold")

        # --- TOP BAR ---
        top_bar = tk.Frame(self, bg=self.bg_color, pady=15, padx=25)
        top_bar.pack(fill=tk.X)

        title_lbl = tk.Label(top_bar, text="🛡️ VoIP Sentinel", font=self.title_font, fg=self.accent_color, bg=self.bg_color)
        title_lbl.pack(side=tk.LEFT)

        # Status Indicator
        status_frame = tk.Frame(top_bar, bg=self.bg_color)
        status_frame.pack(side=tk.RIGHT, pady=5)

        self.status_canvas = tk.Canvas(status_frame, width=24, height=24, bg=self.bg_color, highlightthickness=0)
        self.status_canvas.pack(side=tk.LEFT, padx=(0, 8))
        self.status_dot = self.status_canvas.create_oval(6, 6, 18, 18, fill="#555555", outline="")

        self.status_label = tk.Label(status_frame, text="Idle", font=self.header_font, fg="#888888", bg=self.bg_color)
        self.status_label.pack(side=tk.LEFT)

        # --- MAIN CONTENT AREA ---
        content_frame = tk.Frame(self, bg=self.bg_color)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=25, pady=(0, 15))

        # --- Sidebar (Stats) ---
        sidebar = tk.Frame(content_frame, bg=self.card_bg, width=220, padx=20, pady=20)
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 20))

        tk.Label(sidebar, text="SESSION STATS", font=self.header_font, fg=self.fg_color, bg=self.card_bg).pack(anchor="w", pady=(0, 25))

        tk.Label(sidebar, text="Calls Monitored", font=self.small_font, fg="#8b949e", bg=self.card_bg).pack(anchor="w")
        self.lbl_calls = tk.Label(sidebar, text="0", font=self.title_font, fg=self.accent_color, bg=self.card_bg)
        self.lbl_calls.pack(anchor="w", pady=(0, 20))

        tk.Label(sidebar, text="High Risk Anomalies", font=self.small_font, fg="#8b949e", bg=self.card_bg).pack(anchor="w")
        self.lbl_high_risk = tk.Label(sidebar, text="0", font=self.title_font, fg="#f85149", bg=self.card_bg)
        self.lbl_high_risk.pack(anchor="w", pady=(0, 20))

        tk.Label(sidebar, text="Session Started At", font=self.small_font, fg="#8b949e", bg=self.card_bg).pack(anchor="w")
        self.lbl_session_start = tk.Label(sidebar, text="--:--", font=self.normal_font, fg=self.fg_color, bg=self.card_bg)
        self.lbl_session_start.pack(anchor="w")

        # --- Center Panel (Cards) ---
        center_panel = tk.Frame(content_frame, bg=self.bg_color)
        center_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Label(center_panel, text="Detected Calls", font=self.header_font, fg=self.fg_color, bg=self.bg_color).pack(anchor="w", pady=(0, 10))

        # Scrollable Canvas for Cards
        self.cards_canvas = tk.Canvas(center_panel, bg=self.bg_color, highlightthickness=0)
        
        # Style the scrollbar to fit dark theme better
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Vertical.TScrollbar", background=self.card_bg, bordercolor=self.bg_color, arrowcolor=self.fg_color)
        scrollbar = ttk.Scrollbar(center_panel, orient="vertical", command=self.cards_canvas.yview, style="Vertical.TScrollbar")
        
        self.scrollable_frame = tk.Frame(self.cards_canvas, bg=self.bg_color)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.cards_canvas.configure(scrollregion=self.cards_canvas.bbox("all"))
        )
        # Bind mouse wheel scrolling
        self.cards_canvas.bind_all("<MouseWheel>", self._on_mousewheel)

        self.cards_canvas_window = self.cards_canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.cards_canvas.configure(yscrollcommand=scrollbar.set)
        
        # Make the canvas window expand to fill width
        self.cards_canvas.bind('<Configure>', self._on_canvas_configure)

        self.cards_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # --- BOTTOM CONTROLS & LOG ---
        bottom_frame = tk.Frame(self, bg=self.card_bg, pady=15, padx=25)
        bottom_frame.pack(fill=tk.X, side=tk.BOTTOM)

        controls = tk.Frame(bottom_frame, bg=self.card_bg)
        controls.pack(fill=tk.X)

        self.btn_start_stop = tk.Button(
            controls, text="▶ Start Sentinel", font=self.btn_font,
            bg="#238636", fg="#ffffff", activebackground="#2ea043", activeforeground="#ffffff",
            relief=tk.FLAT, command=self.toggle_sniffing, width=20, pady=8, cursor="hand2"
        )
        self.btn_start_stop.pack(side=tk.LEFT, padx=(0, 15))

        self.btn_open_log = tk.Button(
            controls, text="📊 Open Dashboard", font=self.btn_font,
            bg="#1f6feb", fg="#ffffff", activebackground="#388bfd", activeforeground="#ffffff",
            relief=tk.FLAT, command=self.open_log, width=20, pady=8, cursor="hand2"
        )
        self.btn_open_log.pack(side=tk.LEFT)

        self.btn_clear_log = tk.Button(
            controls, text="🗑️ Clear Log", font=self.btn_font,
            bg="#21262d", fg="#ffffff", activebackground="#30363d", activeforeground="#f85149",
            relief=tk.FLAT, command=self.confirm_clear_log, width=15, pady=8, cursor="hand2"
        )
        self.btn_clear_log.pack(side=tk.LEFT, padx=(15, 0))

        # System Log area (small, to keep raw prints from cluttering)
        self.sys_log = scrolledtext.ScrolledText(
            bottom_frame, bg="#0d1117", fg="#8b949e", font=self.mono_font,
            height=4, wrap=tk.WORD, state=tk.DISABLED, relief=tk.FLAT, padx=10, pady=5
        )
        self.sys_log.pack(fill=tk.X, expand=True, pady=(15, 0))

        self.log_message("System", "VoIP Sentinel GUI initialized. Ready.")

    def _on_mousewheel(self, event):
        self.cards_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
    def _on_canvas_configure(self, event):
        self.cards_canvas.itemconfig(self.cards_canvas_window, width=event.width)

    # --- PULSING DOT ANIMATION ---
    def pulse_status_dot(self):
        if self.is_running:
            # Interpolate between dark green (#0d3a17) and bright green (#2ea043)
            r = int(13 + (46 - 13) * (self.pulse_state / 10.0))
            g = int(58 + (160 - 58) * (self.pulse_state / 10.0))
            b = int(23 + (67 - 23) * (self.pulse_state / 10.0))
            color = f"#{r:02x}{g:02x}{b:02x}"
            self.status_canvas.itemconfig(self.status_dot, fill=color)

            self.pulse_state += self.pulse_direction
            if self.pulse_state >= 10 or self.pulse_state <= 0:
                self.pulse_direction *= -1
        else:
            self.status_canvas.itemconfig(self.status_dot, fill="#555555")

        self.after(80, self.pulse_status_dot)

    # --- PROCESS MANAGEMENT ---
    def toggle_sniffing(self):
        if not self.is_running:
            self.start_sniffing()
        else:
            self.stop_sniffing()

    def start_sniffing(self):
        self.log_message("System", "Starting VoIP sniffer process...")
        self.session_start_time = datetime.now().strftime("%H:%M:%S")
        self.lbl_session_start.config(text=self.session_start_time)
        try:
            creation_flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            env = os.environ.copy()
            env["GUI_MODE"] = "1"
            base_dir = os.path.dirname(os.path.abspath(__file__))
            
            self.process = subprocess.Popen(
                [sys.executable, "-u", os.path.join(base_dir, "sniffer.py")],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                creationflags=creation_flags,
                env=env,
                cwd=base_dir
            )
            self.is_running = True
            self.status_label.config(text="Monitoring", fg="#2ea043")
            self.btn_start_stop.config(text="⏹ Stop Sentinel", bg="#da3633", activebackground="#f85149")

            self.reader_thread = threading.Thread(target=self.read_process_output, daemon=True)
            self.reader_thread.start()

        except Exception as e:
            self.log_message("Error", f"Failed to start: {e}")

    def stop_sniffing(self):
        if self.process:
            self.log_message("System", "Terminating VoIP sniffer...")
            self.process.terminate()
            self.process = None

        self.is_running = False
        self.status_label.config(text="Idle", fg="#888888")
        self.btn_start_stop.config(text="▶ Start Sentinel", bg="#238636", activebackground="#2ea043")
        self.log_message("System", "Pipeline stopped.")

    def read_process_output(self):
        if self.process:
            for line in iter(self.process.stdout.readline, ''):
                if not line and not self.is_running:
                    break
                self.log_queue.put(line)
            if self.process:
                self.process.stdout.close()

    def poll_log_queue(self):
        while not self.log_queue.empty():
            line = self.log_queue.get_nowait()
            stripped_line = line.strip()

            if stripped_line.startswith("__GUI_REVIEW_DATA__:"):
                try:
                    json_str = stripped_line.split("__GUI_REVIEW_DATA__:", 1)[1]
                    data = json.loads(json_str)
                    self.show_review_popup(data)
                except Exception as e:
                    self.log_message("Error", f"Failed to parse GUI data: {e}")
                continue

            if stripped_line:
                self.log_message("Sniffer", stripped_line)

        self.after(100, self.poll_log_queue)

    def log_message(self, source, message):
        self.sys_log.config(state=tk.NORMAL)
        self.sys_log.insert(tk.END, f"[{source}] {message}\n")
        self.sys_log.see(tk.END)
        self.sys_log.config(state=tk.DISABLED)

    # --- UI HELPERS & REVIEW LOGIC ---
    def get_app_name(self, isp_org):
        org_lower = isp_org.lower()
        if "facebook" in org_lower or "meta" in org_lower: return "WhatsApp/Meta"
        elif "telegram" in org_lower: return "Telegram"
        elif "reliance jio" in org_lower: return "Jio Network"
        elif "airtel" in org_lower: return "Airtel"
        elif any(p in org_lower for p in ["ovh", "digitalocean", "amazon", "aws", "hetzner", "linode", "choopa", "vultr"]): return "Datacenter/Hosting"
        elif any(p in org_lower for p in ["proton", "nordvpn", "expressvpn", "surfshark", "mullvad", "private internet access"]): return "VPN Provider"
        else: return f"Unknown ({isp_org})"

    def show_review_popup(self, data):
        row = data['row']
        pcap_file = data['pcap_file']
        freq = data.get('freq', 1)

        app_name = self.get_app_name(row['isp_org'])

        popup = tk.Toplevel(self)
        popup.title("Review Detection")
        popup.geometry("550x300")
        popup.configure(bg=self.card_bg)
        popup.attributes("-topmost", True)
        popup.grab_set()

        popup.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() // 2) - (popup.winfo_width() // 2)
        y = self.winfo_y() + (self.winfo_height() // 2) - (popup.winfo_height() // 2)
        popup.geometry(f"+{x}+{y}")

        lbl = tk.Label(popup, text="⚠️ New Call Intercepted", font=self.title_font, bg=self.card_bg, fg=self.accent_color)
        lbl.pack(pady=(20, 10))

        summary = (
            f"App/Service: {app_name}\n"
            f"Location: {row['country']} | Duration: {row['duration_sec']}s\n"
            f"Protocol: {row['protocol']}\n"
            f"Risk Level: {row.get('risk_level', 'Unknown')} | Score: {row.get('risk_score', 'N/A')}\n"
            f"Risk Reason: {row.get('risk_reason', 'None')}\n\n"
            f"Frequency: {freq} previous calls from this IP in the last hour."
        )
        text_area = tk.Message(popup, text=summary, font=self.normal_font, bg=self.card_bg, fg=self.fg_color, width=480, justify=tk.LEFT)
        text_area.pack(pady=10, padx=20, fill=tk.X)

        btn_frame = tk.Frame(popup, bg=self.card_bg)
        btn_frame.pack(pady=20)

        def keep_record():
            keep_btn.config(state=tk.DISABLED)
            saved = self.write_to_csv(row)
            if not saved:
                self.log_message(
                    "System",
                    f"Skipped duplicate record: {row['source_ip']} -> {row['destination_ip']} ({row['duration_sec']}s)."
                )
                popup.destroy()
                return
            try:
                import generate_dashboard
                generate_dashboard.generate()
            except Exception as e:
                self.log_message("Error", f"Failed to update dashboard: {e}")
            self.add_call_card(row, app_name)
            self.log_message("System", f"Record kept: {app_name} call ({row['duration_sec']}s).")
            popup.destroy()

        def delete_record():
            try:
                if os.path.exists(pcap_file): os.remove(pcap_file)
                self.log_message("System", "Record discarded.")
            except Exception as e:
                self.log_message("Error", f"Failed to delete {pcap_file}: {e}")
            popup.destroy()

        keep_btn = tk.Button(
            btn_frame, text="Keep Record", font=self.btn_font, bg="#238636", fg="white", 
            activebackground="#2ea043", activeforeground="white", relief=tk.FLAT, borderwidth=0, 
            command=keep_record, padx=15, pady=8, cursor="hand2"
        )
        keep_btn.pack(side=tk.LEFT, padx=10)
        
        tk.Button(
            btn_frame, text="Discard & Delete", font=self.btn_font, bg="#8b0000", fg="white", 
            activebackground="#da3633", activeforeground="white", relief=tk.FLAT, borderwidth=0, 
            command=delete_record, padx=15, pady=8, cursor="hand2"
        ).pack(side=tk.RIGHT, padx=10)

    def add_call_card(self, row, app_name):
        self.calls_monitored += 1
        self.lbl_calls.config(text=str(self.calls_monitored))

        risk_level = row.get('risk_level', '').lower()
        if risk_level in ['high', 'medium']:
            self.high_risk_count += 1
            self.lbl_high_risk.config(text=str(self.high_risk_count))

        # Create card frame
        card = tk.Frame(self.scrollable_frame, bg=self.card_bg, pady=12, padx=15, relief=tk.FLAT, borderwidth=1, highlightbackground="#30363d", highlightthickness=1)
        card.pack(fill=tk.X, padx=5, pady=5)

        # Left side: Icon/App Name
        left_frame = tk.Frame(card, bg=self.card_bg)
        left_frame.pack(side=tk.LEFT, fill=tk.Y)

        icon_text = "📱" if "WhatsApp" in app_name or "Telegram" in app_name else "🌐"
        tk.Label(left_frame, text=icon_text, font=("Segoe UI", 24), bg=self.card_bg, fg=self.fg_color).pack(side=tk.LEFT, padx=(0, 15))

        info_frame = tk.Frame(left_frame, bg=self.card_bg)
        info_frame.pack(side=tk.LEFT)

        tk.Label(info_frame, text=app_name, font=self.header_font, bg=self.card_bg, fg=self.fg_color).pack(anchor="w")
        
        # Technical detail in monospace
        tech_text = f"IP: {row['source_ip']} \u2192 {row['destination_ip']} | Protocol: {row['protocol']}"
        tk.Label(info_frame, text=tech_text, font=self.mono_font, bg=self.card_bg, fg="#8b949e").pack(anchor="w", pady=(2, 0))

        # Right side: Stats & Risk Badge
        right_frame = tk.Frame(card, bg=self.card_bg)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y)

        # Risk Badge
        risk_colors = {"low": "#2ea043", "medium": "#d29922", "high": "#f85149"}
        badge_color = risk_colors.get(risk_level, "#888888")
        
        tk.Label(right_frame, text=f"{risk_level.upper()} RISK", font=self.small_font, bg=badge_color, fg="white", padx=8, pady=2).pack(anchor="e", pady=(0, 5))

        tk.Label(right_frame, text=f"{row['duration_sec']}s | {row['country']}", font=self.header_font, bg=self.card_bg, fg=self.fg_color).pack(anchor="e")

        # Auto-scroll to bottom of cards
        self.cards_canvas.update_idletasks()
        self.cards_canvas.yview_moveto(1.0)

    def is_recent_duplicate_call(
        self,
        row,
        csv_file,
        window_seconds=DUPLICATE_WINDOW_SECONDS,
        duration_tolerance=DUPLICATE_DURATION_TOLERANCE
    ):
        if not os.path.exists(csv_file):
            return False

        try:
            new_duration = float(row.get("duration_sec", 0))
        except (TypeError, ValueError):
            new_duration = None

        try:
            new_timestamp = datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
        except Exception:
            new_timestamp = datetime.now()

        with open(csv_file, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for existing_row in reader:
                if existing_row.get("source_ip") != row.get("source_ip"):
                    continue
                if existing_row.get("destination_ip") != row.get("destination_ip"):
                    continue

                try:
                    existing_duration = float(existing_row.get("duration_sec", 0))
                except (TypeError, ValueError):
                    continue

                if new_duration is None or abs(existing_duration - new_duration) > duration_tolerance:
                    continue

                try:
                    existing_timestamp = datetime.strptime(existing_row["timestamp"], "%Y-%m-%d %H:%M:%S")
                except Exception:
                    continue

                if abs((new_timestamp - existing_timestamp).total_seconds()) <= window_seconds:
                    return True

        return False

    def write_to_csv(self, row):
        csv_file = "calls_log.csv"
        file_exists = os.path.isfile(csv_file)
        headers = ["timestamp", "call_id", "source_ip", "destination_ip", "isp_org", "country", "protocol", "duration_sec", "packet_count", "risk_score", "risk_level", "risk_reason"]

        if self.is_recent_duplicate_call(row, csv_file):
            return False

        with open(csv_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            if not file_exists: writer.writeheader()
            writer.writerow(row)
        return True

    def confirm_clear_log(self):
        confirm = messagebox.askyesno(
            "Confirm Clear", 
            "Are you sure you want to permanently delete all call records? This cannot be undone.",
            parent=self
        )
        if confirm:
            import csv
            csv_file = "calls_log.csv"
            headers = ["timestamp", "call_id", "source_ip", "destination_ip", "isp_org", "country", "protocol", "duration_sec", "packet_count", "risk_score", "risk_level", "risk_reason"]
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                
            for pcap in glob.glob("*.pcap*"):
                try:
                    os.remove(pcap)
                except OSError:
                    pass
                    
            self.calls_monitored = 0
            self.lbl_calls.config(text="0")
            
            self.high_risk_count = 0
            self.lbl_high_risk.config(text="0")
            
            # Reset active in-memory dictionary tracking for call frequencies
            if hasattr(self, 'ip_frequencies'):
                self.ip_frequencies.clear()
            else:
                self.ip_frequencies = {}
            
            for widget in self.scrollable_frame.winfo_children():
                widget.destroy()
                
            self.log_message("System", "Call log cleared. Ready for new session.")

    def open_log(self):
        import webbrowser
        try:
            import generate_dashboard
            html_file = generate_dashboard.generate()
            self.log_message("System", "Generated HTML dashboard. Opening in browser...")
            webbrowser.open("file://" + os.path.abspath(html_file).replace('\\', '/'))
        except Exception as e:
            self.log_message("Error", f"Failed to generate or open dashboard: {e}")

if __name__ == "__main__":
    app = VoIPTrackerGUI()
    app.protocol("WM_DELETE_WINDOW", lambda: (app.stop_sniffing(), app.destroy()))
    app.mainloop()
