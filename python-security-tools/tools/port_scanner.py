#!/usr/bin/env python3
"""
port_scanner.py
-----------------
A multi-threaded TCP port scanner with service banner grabbing.

Features:
- Multi-threaded scanning for high performance.
- Optional service and version banner grabbing.
- Adjustable timeout for faster or more reliable scans.
- Saves detailed scan results to a structured JSON file.
"""

import socket
import json
import argparse
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# A dictionary for common ports to make the output more readable
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
    5900: "VNC", 8080: "HTTP-Proxy"
}

# Thread-safe list for storing results
open_ports = []
lock = threading.Lock()

def scan_port(host: str, port: int, timeout: float, grab_banner: bool) -> dict:
    """
    Attempts to connect to a port and optionally grabs a service banner.
    Returns a dictionary with the results for a single port.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                result = {
                    "port": port,
                    "service": COMMON_PORTS.get(port, "Unknown"),
                    "banner": ""
                }
                if grab_banner:
                    try:
                        # Attempt to receive up to 1024 bytes
                        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                        result["banner"] = banner
                    except (socket.timeout, ConnectionResetError):
                        result["banner"] = "No banner received (timeout/reset)"
                
                with lock:
                    open_ports.append(result)
                    port_info = f"{result['service']} ({result['banner']})" if result['banner'] else result['service']
                    print(f"[OPEN] Port {port}: {port_info}")
                return result
    except Exception:
        pass # Suppress other errors like host not found on a per-thread basis
    return None

def run_scan(host: str, start_port: int, end_port: int, threads: int, timeout: float, grab_banner: bool):
    """Run a multi-threaded port scan."""
    global open_ports
    open_ports = []  # Clear previous results
    
    print(f"[+] Starting scan on {host} (Ports: {start_port}-{end_port}) with {threads} threads...")
    
    ports_to_scan = range(start_port, end_port + 1)
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        # Submit all scan tasks to the thread pool
        futures = [executor.submit(scan_port, host, port, timeout, grab_banner) for port in ports_to_scan]
        
        # Process results as they complete (optional, mainly for progress)
        for future in as_completed(futures):
            future.result() # We already print and store results inside scan_port

    scan_end_time = datetime.now()
    results = {
        "host": host,
        "port_range": f"{start_port}-{end_port}",
        "timestamp": scan_end_time.strftime("%Y-%m-%d %H:%M:%S"),
        "open_ports": sorted(open_ports, key=lambda x: x['port'])
    }

    print(f"\n[+] Scan complete. Found {len(open_ports)} open ports.")
    return results

def save_results(results: dict, output_file: str):
    """Save scan results as JSON."""
    if not output_file:
        return
    try:
        with open(output_file, "w") as f:
            json.dump(results, f, indent=4)
        print(f"[+] Results saved to {output_file}")
    except IOError as e:
        print(f"[!] Error saving results to file: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-threaded TCP Port Scanner with Banner Grabbing")
    parser.add_argument("--host", required=True, help="Target host to scan (IP or hostname)")
    parser.add_argument("--start-port", type=int, default=1, help="Starting port (default: 1)")
    parser.add_argument("--end-port", type=int, default=1024, help="Ending port (default: 1024)")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads to use")
    parser.add_argument("--timeout", type=float, default=0.5, help="Timeout per port in seconds")
    parser.add_argument("-b", "--banner", action="store_true", help="Enable service banner grabbing")
    parser.add_argument("-o", "--output", help="Output file for results (JSON format)")

    args = parser.parse_args()

    scan_results = run_scan(
        args.host, args.start_port, args.end_port,
        args.threads, args.timeout, args.banner
    )
    
    save_results(scan_results, args.output)
