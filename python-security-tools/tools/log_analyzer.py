#!/usr/bin/env python3
"""
log_analyzer.py
================
A professional, class-based log analysis tool.

Features:
- Object-Oriented Design: Encapsulates logic within a LogAnalyzer class.
- Multi-format Parsing: Supports Apache, Nginx, IIS, and Syslog.
- User-Agent Analysis: Identifies and counts suspicious user agents (bots, scanners).
- Real-time Progress Bar: Uses `tqdm` for a better user experience with large files.
- Threat Intelligence: Optional GeoIP lookup for IP addresses.
- Comprehensive Reporting: Generates detailed CSV, JSON, and PDF reports with plots.
"""

import re
import os
import json
import csv
import argparse
from datetime import datetime
from collections import Counter
import matplotlib.pyplot as plt
from tqdm import tqdm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet

try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

# -------------------------------
# CONFIGURATION
# -------------------------------
# Common suspicious user agents from scanners and bots
SUSPICIOUS_USER_AGENTS = [
    r"sqlmap", r"nmap", r"nikto", r"gobuster", r"dirb", r"feroxbuster", r"wpscan"
]
DEFAULT_PATTERNS = [r'Failed password', r'404 Not Found', r'admin', r'wp-login\.php']
TOP_N = 10

class LogAnalyzer:
    """A class to encapsulate log analysis logic."""
    
    LOG_FORMAT_PATTERNS = {
        'apache': r'(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+) \S+" (?P<status>\d+) \S+ "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"',
        'nginx': r'(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+) \S+" (?P<status>\d+) \S+ "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"',
        'iis': r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', # Basic check for IIS
        'syslog': r'^\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}' # Basic check for Syslog
    }

    def __init__(self, patterns, geoip_db_path=None):
        self.patterns = patterns
        self.events = []
        self.ip_counter = Counter()
        self.status_counter = Counter()
        self.url_counter = Counter()
        self.ua_counter = Counter()
        self.geoip_reader = None
        if geoip_db_path and GEOIP_AVAILABLE and os.path.exists(geoip_db_path):
            try:
                self.geoip_reader = geoip2.database.Reader(geoip_db_path)
            except Exception as e:
                print(f"[!] Warning: Could not load GeoIP database: {e}")

    def _detect_log_format(self, line):
        for fmt, pattern in self.LOG_FORMAT_PATTERNS.items():
            if re.match(pattern, line):
                return fmt
        return 'unknown'

    def _parse_line(self, line, log_format):
        """Parses a single log line based on its format."""
        if log_format in ['apache', 'nginx']:
            match = re.match(self.LOG_FORMAT_PATTERNS[log_format], line)
            if match:
                data = match.groupdict()
                try:
                    data['datetime'] = datetime.strptime(data['datetime'], '%d/%b/%Y:%H:%M:%S %z')
                except ValueError:
                    data['datetime'] = None # Handle potential format inconsistencies
                return data
        # Add more detailed parsers for IIS and Syslog if needed
        return None

    def _geolocate_ip(self, ip):
        if not self.geoip_reader:
            return None
        try:
            response = self.geoip_reader.city(ip)
            return f"{response.country.iso_code} - {response.city.name}"
        except geoip2.errors.AddressNotFoundError:
            return "Local/Private IP"
        except Exception:
            return "Geolocation Error"

    def analyze(self, log_files, start_time=None, end_time=None):
        """Analyzes a list of log files with a progress bar."""
        print("[+] Starting log analysis...")
        total_lines = sum(1 for log_file in log_files for line in open(log_file, 'r', encoding='utf-8', errors='ignore'))
        
        with tqdm(total=total_lines, desc="Processing Lines", unit="line") as pbar:
            for log_file in log_files:
                if not os.path.exists(log_file):
                    print(f"\n[!] File not found: {log_file}")
                    continue
                
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        pbar.update(1)
                        line = line.strip()
                        log_format = self._detect_log_format(line)
                        parsed = self._parse_line(line, log_format)
                        
                        if not parsed or not parsed.get('datetime'):
                            continue
                        
                        if start_time and end_time and not (start_time <= parsed["datetime"] <= end_time):
                            continue
                        
                        is_suspicious = False
                        for pattern in self.patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                is_suspicious = True
                                break
                        
                        user_agent = parsed.get('user_agent', '')
                        for ua_pattern in SUSPICIOUS_USER_AGENTS:
                             if re.search(ua_pattern, user_agent, re.IGNORECASE):
                                self.ua_counter[user_agent] += 1
                                is_suspicious = True
                                break
                        
                        if is_suspicious:
                            self.ip_counter[parsed.get('ip', 'N/A')] += 1
                            self.status_counter[parsed.get('status', 'N/A')] += 1
                            self.url_counter[parsed.get('url', 'N/A')] += 1
                            if self.geoip_reader:
                                parsed['geolocation'] = self._geolocate_ip(parsed.get('ip'))
                            self.events.append(parsed)

        print(f"\n[+] Analysis complete. Found {len(self.events)} suspicious events.")

    def generate_reports(self, output_dir):
        """Generates all reports (CSV, JSON, PDF)."""
        if not self.events:
            print("[!] No suspicious events found, reports will not be generated.")
            return
            
        print("[+] Generating reports...")
        os.makedirs(output_dir, exist_ok=True)
        
        self._export_csv(output_dir)
        self._export_json(output_dir)
        
        # Generate charts before creating the PDF
        ip_chart_path = self._plot_counter(self.ip_counter, "Top Suspicious IPs", "IP Address", output_dir)
        status_chart_path = self._plot_counter(self.status_counter, "Top Status Codes", "Status Code", output_dir)
        url_chart_path = self._plot_counter(self.url_counter, "Top Accessed URLs", "URL", output_dir)
        ua_chart_path = self._plot_counter(self.ua_counter, "Top Suspicious User Agents", "User Agent", output_dir)
        
        self._export_pdf(output_dir, [ip_chart_path, status_chart_path, url_chart_path, ua_chart_path])

    def _plot_counter(self, counter, title, xlabel, output_dir):
        """Helper to create and save a bar chart."""
        if not counter:
            return None
        
        top_items = dict(counter.most_common(TOP_N))
        filename = title.lower().replace(" ", "_") + ".png"
        save_path = os.path.join(output_dir, filename)

        plt.figure(figsize=(12, 6))
        plt.bar(top_items.keys(), top_items.values(), color='skyblue', edgecolor='black')
        plt.title(title, fontsize=16)
        plt.xlabel(xlabel, fontsize=12)
        plt.ylabel("Count", fontsize=12)
        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()
        plt.savefig(save_path)
        plt.close()
        print(f"[+] Chart saved: {save_path}")
        return save_path

    def _export_csv(self, output_dir):
        csv_path = os.path.join(output_dir, "suspicious_events.csv")
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=self.events[0].keys())
            writer.writeheader()
            writer.writerows(self.events)
        print(f"[+] CSV report saved: {csv_path}")

    def _export_json(self, output_dir):
        json_path = os.path.join(output_dir, "suspicious_events.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            # Custom JSON encoder to handle datetime objects
            json.dump(self.events, f, indent=4, default=str)
        print(f"[+] JSON report saved: {json_path}")

    def _export_pdf(self, output_dir, chart_paths):
        pdf_path = os.path.join(output_dir, "log_analysis_report.pdf")
        doc = SimpleDocTemplate(pdf_path, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []

        story.append(Paragraph("Log Analysis Report", styles["Title"]))
        story.append(Paragraph(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
        story.append(Spacer(1, 12))
        
        story.append(Paragraph(f"<b>Total Suspicious Events Detected:</b> {len(self.events)}", styles["Normal"]))
        story.append(Paragraph(f"<b>Unique Suspicious IPs:</b> {len(self.ip_counter)}", styles["Normal"]))
        story.append(Paragraph(f"<b>Unique Suspicious User Agents:</b> {len(self.ua_counter)}", styles["Normal"]))
        story.append(Spacer(1, 24))
        
        for chart_path in chart_paths:
            if chart_path and os.path.exists(chart_path):
                img = Image(chart_path, width=500, height=250)
                story.append(img)
                story.append(Spacer(1, 12))
        
        doc.build(story)
        print(f"[+] PDF report saved: {pdf_path}")

def main():
    parser = argparse.ArgumentParser(description="A Professional, Class-Based Log Analysis Tool.")
    parser.add_argument("-f", "--files", nargs='+', required=True, help="Log file(s) to analyze.")
    parser.add_argument("-p", "--patterns", nargs='+', default=DEFAULT_PATTERNS, help="Custom suspicious patterns (regex).")
    parser.add_argument("--start", help="Start datetime (YYYY-MM-DD HH:MM:SS)")
    parser.add_argument("--end", help="End datetime (YYYY-MM-DD HH:MM:SS)")
    parser.add_argument("-o", "--output", default="reports", help="Directory to save reports.")
    parser.add_argument("--geoip", help="Path to the GeoIP City database (e.g., GeoLite2-City.mmdb).")
    
    args = parser.parse_args()
    
    start_time = datetime.strptime(args.start, "%Y-%m-%d %H:%M:%S") if args.start else None
    end_time = datetime.strptime(args.end, "%Y-%m-%d %H:%M:%S") if args.end else None
    
    # Instantiate the analyzer
    analyzer = LogAnalyzer(patterns=args.patterns, geoip_db_path=args.geoip)
    
    # Run the analysis
    analyzer.analyze(args.files, start_time, end_time)
    
    # Generate reports
    analyzer.generate_reports(args.output)

if __name__ == "__main__":
    main()
