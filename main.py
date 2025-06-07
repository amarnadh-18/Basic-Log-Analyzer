import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime
from sklearn.ensemble import IsolationForest
import re
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter
import json
import os
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import numpy as np
from PIL import Image, ImageTk
import random
import platform

class ScrollFrame(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.canvas = tk.Canvas(self, borderwidth=0, background="#ffffff")
        self.viewPort = tk.Frame(self.canvas, background="#ffffff")
        self.vsb = tk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vsb.set)
        self.vsb.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.canvas_window = self.canvas.create_window((4, 4), window=self.viewPort, anchor="nw", tags="self.viewPort")

        self.viewPort.bind("<Configure>", self.onFrameConfigure)
        self.canvas.bind("<Configure>", self.onCanvasConfigure)

        self.bind_mouse_wheel(self)
        self.bind_mouse_wheel(self.canvas)
        self.bind_mouse_wheel(self.viewPort)

    def bind_mouse_wheel(self, widget):
        if platform.system() == "Windows":
            widget.bind("<MouseWheel>", self._on_mousewheel)
        else:
            widget.bind("<Button-4>", self._on_mousewheel)
            widget.bind("<Button-5>", self._on_mousewheel)

    def _on_mousewheel(self, event):
        if platform.system() == "Windows":
            self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        else:
            if event.num == 4:
                self.canvas.yview_scroll(-1, "units")
            elif event.num == 5:
                self.canvas.yview_scroll(1, "units")

    def onFrameConfigure(self, event):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def onCanvasConfigure(self, event):
        canvas_width = event.width
        self.canvas.itemconfig(self.canvas_window, width=canvas_width)

activity_colors = {
    'malware': '#FF0000',
    'file_tampering': '#00FF00',
    'unauthorized_access': '#0000FF',
    'security_breach': '#FFFF00',
    'advanced_malware': '#FF00FF',
    'phishing': '#00FFFF',
    'data_leakage': '#FFA500',
    'dos_attack': '#800080',
    'Cross_Site_Scripting(XSS)': '#C0C0C0',
    'sql_injection': '#FF8800',
}
ansi_colors = {
    'malware': "\033[31m",
    'file_tampering': "\033[32m",
    'unauthorized_access': "\033[34m",
    'security_breach': "\033[33m",
    'advanced_malware': "\033[35m",
    'phishing': "\033[36m",
    'data_leakage': "\033[33;1m",
    'dos_attack': "\033[35;1m",
    'Cross_Site_Scripting(XSS)': "\033[38;2;192;192;192m",
    'sql_injection': "\033[38;5;208m",
    'reset': "\033[0m"
}

def get_random_color():
    return "#{:06x}".format(random.randint(0, 0xFFFFFF))

def ensure_ansi_color_for_new_patterns():
    for key in patterns:
        if key not in ansi_colors:
            ansi_colors[key] = f"\033[38;2;{random.randint(0,255)};{random.randint(0,255)};{random.randint(0,255)}m"
        if key not in activity_colors:
            activity_colors[key] = get_random_color()

# --- Patterns ---
patterns = {
    'malware': re.compile(r'\b(malware|virus|trojan|ransomware|worm|spyware|adware|rootkit|keylogger|backdoor|botnet|bot|exploit|zero-day|advanced persistent threat|APT|malicious software|malicious code)\b', re.IGNORECASE),
    'file_tampering': re.compile(r'\b(file tampering|unauthorized file modification|file modified|file altered|file changed|file tampered|file corruption|unauthorized access|unauthorized modification|file integrity failure|checksum mismatch)\b', re.IGNORECASE),
    'unauthorized_access': re.compile(r'\b(unauthorized access|login failure|invalid login|access denied|brute force|credential stuffing|account hijacking|session hijacking|incorrect password|access violation|login attempt failed|user not found|invalid credentials|authentication failure|incorrect password attempts)\b', re.IGNORECASE),
    'security_breach': re.compile(r'\b(security breach|data breach|intrusion detected|unauthorized entry|system intrusion|access breach|network breach|unauthorized system access|data exfiltration|compromise detected|confidentiality violation)\b', re.IGNORECASE),
    'advanced_malware': re.compile(r'\b(zero-day|rootkit|advanced persistent threat|APT|polymorphic malware|fileless malware|spear-phishing|advanced hacking tools|privilege escalation|stealth malware|undetectable malware|memory resident malware)\b', re.IGNORECASE),
    'phishing': re.compile(r'\b(phishing|spear phishing|fraudulent email|email scam|spoofed email|phishing attempt|fake login page|social engineering attack|phishing link|fake notification|phishing campaign|scam website|email impersonation)\b', re.IGNORECASE),
    'data_leakage': re.compile(r'\b(data leakage|data exfiltration|information leak|data breach|data theft|unauthorized data access|data loss|sensitive data leak|confidentiality breach|data disclosure|personal data leak|leak of sensitive data)\b', re.IGNORECASE),
    'dos_attack': re.compile(r'\b(Denial of Service|DoS|DDoS|distributed denial of service|flood attack|service disruption|bandwidth exhaustion|resource depletion|flooding attack|TCP SYN flood|UDP flood|ping of death|slowloris)\b', re.IGNORECASE),
    "Cross_Site_Scripting(XSS)": re.compile(r'(<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>|on\w+\s*=\s*["\']?[^"\'>]+["\']?|javascript:)', re.IGNORECASE),
    'sql_injection': re.compile(r"(\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bOR\b\s+\d+=\d+|--|#|/\*|\*/|xp_cmdshell|sp_executesql|char\(|nchar\(|varchar\(|nvarchar\(|alter\s+table|create\s+table|information_schema|sleep\(|benchmark\()", re.IGNORECASE)
}

remedies = {
    'malware': "Remedy: Run a full system antivirus scan, isolate the affected systems, and update your antivirus software.",
    'file_tampering': "Remedy: Restore the affected files from backup, change file permissions, and monitor file integrity.",
    'unauthorized_access': "Remedy: Reset passwords, implement multi-factor authentication, and review access logs.",
    'security_breach': "Remedy: Disconnect affected systems from the network, conduct a thorough investigation, and notify affected parties.",
    'advanced_malware': "Remedy: Employ advanced threat detection tools, perform a deep system scan, and update security protocols.",
    'phishing': "Remedy: Educate users about phishing, implement email filtering solutions, and report the phishing attempt.",
    'data_leakage': "Remedy: Identify the source of the leak, implement data loss prevention solutions, and review data access policies.",
    'Cross_Site_Scripting(XSS)': "Remedy: Validate and sanitize all user inputs, Implement a strict Content Security Policy (CSP).",
    'dos_attack': "Remedy: Configure firewalls to filter out malicious traffic, use rate limiting to prevent overloading, and implement robust network security measures.",
    'sql_injection': "Remedy: Sanitize all user inputs, use prepared statements, and implement web application firewalls."
}

config_file = 'log_analyzer_config.json'

def load_patterns():
    global patterns, remedies
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            config = json.load(f)
            patterns.update({k: re.compile(v, re.IGNORECASE) for k, v in config.get('patterns', {}).items()})
            remedies.update(config.get('remedies', {}))

def save_patterns():
    config = {
        'patterns': {k: v.pattern for k, v in patterns.items()},
        'remedies': {k: v for k, v in remedies.items()}
    }
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=4)

def parse_timestamp(line):
    timestamp_patterns = [
        r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',
        r'^\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}',
        r'^\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}',
        r'^[A-Za-z]{3} \d{2} \d{2}:\d{2}:\d{2}',
    ]
    timestamp_formats = [
        "%Y-%m-%d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%b %d %H:%M:%S",
    ]
    for pattern in timestamp_patterns:
        match = re.match(pattern, line)
        if match:
            timestamp_str = match.group()
            for fmt in timestamp_formats:
                try:
                    timestamp = datetime.strptime(timestamp_str, fmt)
                    return timestamp.hour
                except ValueError:
                    continue
    return None

def analyze_log_file(log_file):
    suspicious_activity = defaultdict(int)
    activity_hours = defaultdict(lambda: defaultdict(int))
    activity_line_numbers = defaultdict(list)
    total_lines = 0
    line_data = []
    with open(log_file, 'r') as f:
        for line_number, line in enumerate(f, 1):
            line_data.append((line_number, line))
    total_lines = len(line_data)
    def process_line(line_tuple):
        line_number, line = line_tuple
        result = {}
        hour = parse_timestamp(line)
        if hour is not None:
            for activity, pattern in patterns.items():
                if pattern.search(line):
                    result[activity] = hour
        return line_number, result
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(process_line, line_data))
    for line_number, activities_found in results:
        for activity, hour in activities_found.items():
            suspicious_activity[activity] += 1
            activity_hours[activity][hour] += 1
            activity_line_numbers[activity].append(line_number)
    anomalies = detect_anomalies(suspicious_activity)
    return suspicious_activity, total_lines, activity_hours, anomalies, activity_line_numbers

def detect_anomalies(suspicious_activity):
    if not suspicious_activity:
        return []
    activities = list(suspicious_activity.keys())
    counts = np.array(list(suspicious_activity.values())).reshape(-1, 1)
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(counts)
    anomalies = [activities[i] for i, label in enumerate(model.predict(counts)) if label == -1]
    return anomalies

def convert_to_12_hour_format(hour):
    if hour == 0:
        return "12 AM"
    elif hour < 12:
        return f"{hour} AM"
    elif hour == 12:
        return "12 PM"
    else:
        return f"{hour - 12} PM"

def find_max_hour(hour_data):
    max_hour = None
    max_count = 0
    for hour, count in hour_data.items():
        if count > max_count or (count == max_count and max_hour is None):
            max_hour = hour
            max_count = count
    return max_hour, max_count

def ensure_output_folder():
    if not os.path.exists("output"):
        os.makedirs("output")

def save_report(log_file, suspicious_activity, total_lines, activity_hours, anomalies, activity_line_numbers):
    ensure_output_folder()
    base = os.path.basename(log_file)
    report_file = os.path.join("output", base.replace('.log', '_output.txt'))
    with open(report_file, 'w') as f:
        f.write(f'Total lines processed: {total_lines}\n\n')
        if suspicious_activity:
            for activity, count in suspicious_activity.items():
                percentage = (count / total_lines) * 100
                f.write(f'{activity}: {percentage:.2f}%\n')
                line_numbers_str = ", ".join(map(str, activity_line_numbers[activity][:2000]))
                if len(activity_line_numbers[activity]) > 2000:
                    line_numbers_str += f" and {len(activity_line_numbers[activity]) - 2000} more"
                f.write(f'Detected at lines: {line_numbers_str}\n')
                f.write(f'{remedies[activity]}\n')
                max_hour, max_count = find_max_hour(activity_hours[activity])
                max_hour_12 = convert_to_12_hour_format(max_hour)
                f.write(f'Maximum activity occurred: {max_hour_12} (Frequency: {max_count})\n\n')
        if anomalies:
            f.write("Anomalous Activities Detected:\n")
            for anomaly in anomalies:
                f.write(f"- {anomaly}\n")
        else:
            f.write('No suspicious activity detected.\n')
    return report_file

def save_colored_html_log(log_file, activity_line_numbers):
    ensure_output_folder()
    base = os.path.basename(log_file)
    html_log_file = os.path.join("output", base + ".html")  # Save as <logfilename>.log.html

    line_to_activity = {}
    for activity, line_numbers in activity_line_numbers.items():
        for line_number in line_numbers:
            line_to_activity[line_number] = activity

    with open(log_file, 'r') as input_file, open(html_log_file, 'w', encoding='utf-8') as output_file:
        output_file.write("<html><body><pre style='font-family: monospace;'>\n")
        for line_number, line in enumerate(input_file, 1):
            activity = line_to_activity.get(line_number)
            if activity:
                color = activity_colors.get(activity, "#000000")
                output_file.write(f"<span style='color: {color};'>{line.rstrip()}</span>\n")
            else:
                output_file.write(line)
        output_file.write("</pre></body></html>\n")
    return html_log_file


def plot_suspicious_activity(log_file, suspicious_activity, total_lines):
    ensure_output_folder()
    base = os.path.basename(log_file)
    graph_file = os.path.join("output", base.replace('.log', '_suspicious_activity.png'))
    fig, ax = plt.subplots(figsize=(8, 5), dpi=100)
    ax.set_ylim(0, 100)
    ax.yaxis.set_major_formatter(PercentFormatter())
    ax.set_yticks(range(0, 101, 10))
    if suspicious_activity:
        activities = list(suspicious_activity.keys())
        percentages = [(count / total_lines) * 100 for count in suspicious_activity.values()]
        colors = [activity_colors.get(activity, "#888888") for activity in activities]
        bars = ax.bar(activities, percentages, color=colors)
        ax.set_xlabel('Malicious Activity Type')
        ax.set_ylabel('Percentage')
        ax.set_title('Suspicious Activity Detected in Logs (%)')
        if len(activities) > 4:
            plt.xticks(rotation=45, ha='right')
            plt.subplots_adjust(bottom=0.3 if len(activities) > 4 else 0.15)
        for bar, percentage in zip(bars, percentages):
            height = bar.get_height()
            label_height = height + 1 if height < 90 else height - 5
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                label_height,
                f'{percentage:.2f}%',
                ha='center',
                va='bottom' if height < 90 else 'top',
                fontsize=9 if len(activities) > 6 else 10
            )
        # Use .get to prevent KeyError!
        legend_patches = [plt.Rectangle((0, 0), 1, 1, color=activity_colors.get(activity, "#888888")) for activity in activities]
        ax.legend(legend_patches, activities, title="Activity Types")
    else:
        ax.text(0.5, 0.5, "NO SUSPICIOUS ACTIVITY DETECTED",
                ha='center', va='center', fontsize=16, color='green',
                transform=ax.transAxes, bbox=dict(facecolor='white', alpha=0.8))
        ax.set_xlabel('')
        ax.set_ylabel('Percentage')
        ax.set_title('Log Analysis Results')
        ax.set_xticks([])
    plt.tight_layout()
    fig.savefig(graph_file, bbox_inches='tight')
    plt.close(fig)
    return graph_file

def run_analysis():
    log_file = filedialog.askopenfilename(title="Select Log File", filetypes=[("Log Files", "*.log")])
    if not log_file:
        return
    suspicious_activity, total_lines, activity_hours, anomalies, activity_line_numbers = analyze_log_file(log_file)
    report_file = save_report(log_file, suspicious_activity, total_lines, activity_hours, anomalies, activity_line_numbers)
    graph_file = plot_suspicious_activity(log_file, suspicious_activity, total_lines)
    colored_log_file = save_colored_html_log(log_file, activity_line_numbers)
    result_message = f"...\nColored HTML log saved to: {colored_log_file}"
    if anomalies:
        messagebox.showwarning("Alert", f"Anomalous Activities Detected: {', '.join(anomalies)}")
    if graph_file:
        result_message += f"\nGraph saved to: {graph_file}"
        display_graph(graph_file)
    if suspicious_activity:
        alert_message = "Suspicious activity detected!"
        messagebox.showwarning("Alert", alert_message)
    messagebox.showinfo("Analysis Complete", result_message)
    update_analysis_results(suspicious_activity, total_lines, activity_hours, anomalies, activity_line_numbers)

def display_graph(graph_file):
    try:
        img = Image.open(graph_file)
        img = img.resize((600, 350), Image.LANCZOS)
        photo = ImageTk.PhotoImage(img)
        img_label.config(image=photo)
        img_label.image = photo
        img_label.config(text="")
    except Exception as e:
        img_label.config(text="Unable to display image.")

def update_analysis_results(suspicious_activity, total_lines, activity_hours, anomalies, activity_line_numbers):
    analysis_results_frame.config(state=tk.NORMAL)
    analysis_results_frame.delete(1.0, tk.END)
    for activity, color in activity_colors.items():
        analysis_results_frame.tag_configure(f"tag_{activity}", foreground=color)
    analysis_results_frame.insert(tk.END, f"Total lines processed: {total_lines}\n\n")
    if suspicious_activity:
        for activity, count in suspicious_activity.items():
            percentage = (count / total_lines) * 100
            tag_name = f"tag_{activity}"
            analysis_results_frame.insert(tk.END, f'{activity}', tag_name)
            analysis_results_frame.insert(tk.END, f': {percentage:.2f}%\n')
            line_numbers_str = ", ".join(map(str, activity_line_numbers[activity][:2000]))
            if len(activity_line_numbers[activity]) > 2000:
                line_numbers_str += f" and {len(activity_line_numbers[activity]) - 2000} more"
            analysis_results_frame.insert(tk.END, f'Detected at lines: {line_numbers_str}\n')
            analysis_results_frame.insert(tk.END, f'{remedies[activity]}\n')
            max_hour, max_count = find_max_hour(activity_hours[activity])
            max_hour_12 = convert_to_12_hour_format(max_hour)
            analysis_results_frame.insert(tk.END, f'Maximum activity occurred: {max_hour_12}\n\n')
    else:
        analysis_results_frame.insert(tk.END, 'No suspicious activity detected.\n')
    analysis_results_frame.config(state=tk.DISABLED)

def quit_application():
    root.quit()

def add_custom_pattern():
    dialog = tk.Toplevel(root)
    dialog.title("Add Custom Pattern")
    dialog.geometry("420x360")
    dialog.resizable(False, False)
    tk.Label(dialog, text="Pattern Name:", anchor="w").place(x=10, y=10, width=100, height=22)
    name_entry = tk.Entry(dialog, font=("Arial", 11))
    name_entry.place(x=120, y=10, width=280, height=22)
    tk.Label(dialog, text="Regex:", anchor="w").place(x=10, y=45, width=100, height=22)
    regex_entry = tk.Text(dialog, font=("Arial", 11), height=3, width=34)
    regex_entry.place(x=120, y=45, width=280, height=55)
    tk.Label(dialog, text="Remedy:", anchor="w").place(x=10, y=110, width=100, height=22)
    remedy_entry = tk.Text(dialog, font=("Arial", 11), height=6, width=34)
    remedy_entry.place(x=120, y=110, width=280, height=120)
    def confirm():
        name = name_entry.get().strip()
        regex = regex_entry.get("1.0", "end-1c").strip()
        remedy = remedy_entry.get("1.0", "end-1c").strip()
        if name and regex:
            try:
                patterns[name] = re.compile(regex, re.IGNORECASE)
                remedies[name] = remedy
                if name not in activity_colors:
                    r = random.randint(0, 255)
                    g = random.randint(0, 255)
                    b = random.randint(0, 255)
                    activity_colors[name] = f'#{r:02x}{g:02x}{b:02x}'
                    ansi_colors[name] = f"\033[38;2;{r};{g};{b}m"
                save_patterns()
                messagebox.showinfo("Success", "Custom pattern added successfully.")
                dialog.destroy()
            except re.error:
                messagebox.showerror("Error", "Invalid regex pattern.")
        else:
            messagebox.showerror("Error", "Pattern name and regex are required.")
    def cancel():
        dialog.destroy()
    tk.Button(dialog, text="Confirm", command=confirm, width=12).place(x=110, y=250)
    tk.Button(dialog, text="Cancel", command=cancel, width=12).place(x=230, y=250)
    dialog.transient(root)
    dialog.grab_set()
    root.wait_window(dialog)
    load_patterns()

def create_gui():
    global root, tab_analysis, tab_custom_patterns, analysis_results_frame, img_label
    
    root = tk.Tk()
    root.title("Log Analyzer")
    root.geometry("600x600")
    
    # Create styles
    style = ttk.Style()
    
    # Configure tab styles
    style.configure('TNotebook.Tab', padding=[10, 5])
    style.configure('TNotebook.Tab', font=('Arial', 12, 'bold'))
    style.map('TNotebook.Tab', foreground=[('selected', 'green')], 
              background=[('selected', 'light green')])
    
    # Create button styles
    style.configure('RunButton.TButton', font=('Arial', 12, 'bold'))
    style.map('RunButton.TButton', foreground=[('!disabled', 'blue')])
    
    style.configure('QuitButton.TButton', font=('Arial', 12, 'bold'))
    style.map('QuitButton.TButton', foreground=[('!disabled', 'red')])
    
    style.configure('AddButton.TButton', font=('Arial', 12, 'bold'))
    style.map('AddButton.TButton', foreground=[('!disabled', 'blue')])
    
    tab_control = ttk.Notebook(root)
    tab_analysis = ttk.Frame(tab_control)
    tab_custom_patterns = ttk.Frame(tab_control)
    
    tab_control.add(tab_analysis, text='Log Analysis')
    tab_control.add(tab_custom_patterns, text='Custom Patterns')
    tab_control.pack(expand=1, fill='both')
    
    # Fixed buttons using style parameter instead of font/fg
    run_button = ttk.Button(tab_analysis, text="Run Analysis", 
                           style='RunButton.TButton', command=run_analysis)
    run_button.pack(pady=10)
    
    quit_button = ttk.Button(tab_analysis, text="Quit", 
                            style='QuitButton.TButton', command=quit_application)
    quit_button.pack(pady=10)
    
    scroll_frame = ScrollFrame(tab_analysis)
    scroll_frame.pack(fill="both", expand=True, padx=10, pady=10)
    
    # Container for both graph and results
    combined_frame = tk.Frame(scroll_frame.viewPort)
    combined_frame.pack(fill="both", expand=True)
    
    # Image label for graph
    img_label = tk.Label(combined_frame)
    img_label.pack(pady=10)
    
    # Text widget for analysis results
    analysis_results_frame = tk.Text(combined_frame, wrap=tk.WORD, height=20, width=70, 
                                   background="white", font=("Times New Roman", 12))
    analysis_results_frame.pack(fill="both", expand=True, pady=0)
    analysis_results_frame.config(state=tk.DISABLED)
    
    # Custom patterns tab with fixed buttons
    add_pattern_button = ttk.Button(tab_custom_patterns, text="Add New Pattern", 
                                  style='AddButton.TButton', command=add_custom_pattern)
    add_pattern_button.pack(pady=10)
    
    # Fixed quit button in custom patterns tab
    quit_button2 = ttk.Button(tab_custom_patterns, text="Quit", 
                            style='QuitButton.TButton', command=quit_application)
    quit_button2.pack(pady=10)
    
    root.mainloop()

if __name__ == "__main__":
    create_gui()
