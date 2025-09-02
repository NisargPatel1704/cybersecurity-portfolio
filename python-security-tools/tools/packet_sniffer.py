#!/usr/bin/env python3
"""
packet_sniffer.py
-----------------
A packet sniffer with live analysis and reporting capabilities.

Features:
- Live-updating console display of packet counts by protocol.
- Captures detailed information (IPs, ports, protocol).
- Supports both fixed-count and continuous capture modes.
- Generates detailed CSV and PDF reports with findings.
- Includes a pie chart visualization of protocol distribution.
"""

import argparse
import os
import csv
import sys
import threading
import time
from datetime import datetime
from scapy.all import sniff, get_if_list, IP, TCP, UDP, ICMP
import matplotlib.pyplot as plt
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet

# --- Global variables for thread-safe data handling ---
packet_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0, "Total": 0}
captured_packets_details = []
lock = threading.Lock()
stop_sniffing = threading.Event()
MAX_PACKETS_IN_REPORT = 1000 # Limit memory usage for long captures

# -------------------------
# Packet Processing
# -------------------------
def process_packet(packet):
    """Callback function to process each captured packet."""
    with lock:
        packet_counts["Total"] += 1
        protocol = "Other"
        
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            if packet.haslayer(TCP):
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                packet_info = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            elif packet.haslayer(UDP):
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                packet_info = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
                packet_info = f"{src_ip} -> {dst_ip}"
            else:
                protocol = "Other"
                packet_info = f"{src_ip} -> {dst_ip}"
        else:
            # Non-IP packets
            packet_info = packet.summary()

        packet_counts[protocol] += 1
        
        # Limit the number of detailed packets stored in memory
        if len(captured_packets_details) < MAX_PACKETS_IN_REPORT:
            captured_packets_details.append({
                "no": packet_counts["Total"],
                "time": datetime.now().strftime('%H:%M:%S'),
                "protocol": protocol,
                "details": packet_info
            })

# -------------------------
# Live Stats Display
# -------------------------
def live_stats_display(count):
    """Continuously prints updated stats to the console."""
    target = f"{count} packets" if count > 0 else "indefinitely (Ctrl+C to stop)"
    print(f"[+] Sniffing {target}...")
    print("-" * 50)
    
    while not stop_sniffing.is_set():
        time.sleep(1)
        with lock:
            stats_line = (
                f"Total: {packet_counts['Total']} | "
                f"TCP: {packet_counts['TCP']} | "
                f"UDP: {packet_counts['UDP']} | "
                f"ICMP: {packet_counts['ICMP']} | "
                f"Other: {packet_counts['Other']}"
            )
            # Use carriage return to overwrite the line
            sys.stdout.write("\r" + stats_line)
            sys.stdout.flush()
    print("\n" + "-" * 50) # Final line break after sniffing stops

# -------------------------
# Report Generation
# -------------------------
def generate_reports(output_dir="reports"):
    """Generates all output reports (CSV, PNG, PDF)."""
    print("[+] Generating reports...")
    os.makedirs(output_dir, exist_ok=True)
    
    # --- Generate CSV Report ---
    csv_file = os.path.join(output_dir, "packet_capture_details.csv")
    try:
        with open(csv_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["no", "time", "protocol", "details"])
            writer.writeheader()
            writer.writerows(captured_packets_details)
        print(f"[+] Detailed CSV report saved: {csv_file}")
    except IOError as e:
        print(f"[!] Could not save CSV report: {e}")

    # --- Generate Pie Chart ---
    chart_file = os.path.join(output_dir, "protocol_distribution.png")
    try:
        labels = [k for k, v in packet_counts.items() if v > 0 and k != "Total"]
        sizes = [v for k, v in packet_counts.items() if v > 0 and k != "Total"]
        if not sizes:
             print("[!] No packets captured to generate chart.")
             return

        plt.figure(figsize=(8, 8))
        plt.pie(sizes, labels=labels, autopct="%1.1f%%", startangle=140,
                wedgeprops={'edgecolor': 'black'})
        plt.title("Protocol Distribution")
        plt.savefig(chart_file)
        plt.close()
        print(f"[+] Chart saved: {chart_file}")
    except Exception as e:
        print(f"[!] Could not generate chart: {e}")

    # --- Generate PDF Report ---
    pdf_file = os.path.join(output_dir, "packet_sniffer_report.pdf")
    try:
        doc = SimpleDocTemplate(pdf_file, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []

        story.append(Paragraph("Packet Sniffer Report", styles["Title"]))
        story.append(Spacer(1, 12))
        story.append(Paragraph(f"Capture Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
        story.append(Paragraph(f"Total Packets Captured: {packet_counts['Total']}", styles["Normal"]))
        story.append(Spacer(1, 24))

        story.append(Paragraph("Protocol Summary", styles["h2"]))
        summary_data = [["Protocol", "Count"]] + [[proto, count] for proto, count in packet_counts.items() if proto != "Total"]
        summary_table = Table(summary_data)
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
            ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 24))
        
        if os.path.exists(chart_file):
            story.append(Paragraph("Protocol Distribution Chart", styles["h2"]))
            story.append(Image(chart_file, width=400, height=400))
            story.append(Spacer(1, 24))

        story.append(Paragraph(f"Captured Packet Details (First {len(captured_packets_details)} Packets)", styles["h2"]))
        details_data = [list(captured_packets_details[0].keys())] + [list(d.values()) for d in captured_packets_details]
        details_table = Table(details_data, colWidths=[40, 60, 60, 300])
        details_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        story.append(details_table)

        doc.build(story)
        print(f"[+] PDF report saved: {pdf_file}")
    except Exception as e:
        print(f"[!] Could not generate PDF report: {e}")


# -------------------------
# Main Execution
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="Live Packet Sniffer with Detailed Reporting")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to sniff on")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 for continuous capture)")
    parser.add_argument("-o", "--output", default="reports", help="Directory to save reports")
    args = parser.parse_args()

    # Start the live display thread
    stats_thread = threading.Thread(target=live_stats_display, args=(args.count,), daemon=True)
    stats_thread.start()
    
    try:
        sniff(iface=args.interface, prn=process_packet, count=args.count, stop_filter=lambda p: stop_sniffing.is_set())
    except KeyboardInterrupt:
        print("\n[!] Capture stopped by user.")
    except Exception as e:
        # This handles errors like "No such device" for the interface
        print(f"\n[!] An error occurred: {e}")
    finally:
        stop_sniffing.set()
        stats_thread.join(timeout=2) # Wait for the stats thread to finish
        
    generate_reports(args.output)
    print("[+] Sniffer has finished.")

if __name__ == "__main__":
    main()
