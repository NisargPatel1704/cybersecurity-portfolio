# 🛡️ Python Security Tools Suite

A **modular, command-line-driven suite of security tools built in Python**.
This collection is designed for **educational purposes** and **authorized security testing**, covering:

* 🔍 **Network Reconnaissance**
* 📡 **Traffic Analysis**
* 🗂 **Log Forensics**
* ⚔️ **Offensive Security Exercises**

---

## 📑 Table of Contents

* [✨ Features](#-features)

  * [📊 Professional Log Analyzer](#-professional-log-analyzer)
  * [⚡ High-Speed Port Scanner](#-high-speed-port-scanner)
  * [📡 Real-Time Packet Sniffer](#-real-time-packet-sniffer)
  * [🔑 Multithreaded Hash Cracker](#-multithreaded-hash-cracker)
* [⚙️ Installation](#️-installation)
* [▶️ Usage Examples](#️-usage-examples)
* [⚠️ Disclaimer](#️-disclaimer)

---

## ✨ Features

This suite contains **four professional-grade security tools**, each designed with performance, usability, and reporting in mind.

---

### 📊 Professional Log Analyzer

A **class-based, object-oriented** tool for deep log file analysis.

* 📝 **Multi-Format Support**: Parses Apache, Nginx, and system logs.
* 🔎 **Suspicious Pattern Detection**: Customizable regex for IOCs (e.g., nmap, sqlmap).
* 📈 **Advanced Analysis**: Stats for top IPs, URLs, status codes, and user-agents.
* 🌍 **GeoIP Enrichment**: Integrates with MaxMind DB for IP location lookup.
* 📑 **Professional Reporting**: Generates **PDF reports with charts**, plus **CSV/JSON** outputs.
* ✅ **User-Friendly**: Built-in tqdm progress bar for large log files.

---

### ⚡ High-Speed Port Scanner

A **multithreaded TCP port scanner** with advanced capabilities.

* 🚀 **High Performance**: Scans thousands of ports in seconds.
* 🏷 **Service Banner Grabbing**: Identifies running services on open ports.
* 🎯 **Flexible Targeting**: Supports single hosts and IP ranges.
* 📂 **Structured Output**: Saves results (including banners) as JSON.

---

### 📡 Real-Time Packet Sniffer

A **live network traffic monitoring tool** for analysis and reporting.

* 📊 **Live Statistics**: Real-time table of captured protocols.
* 📝 **Detailed Logging**: Source/destination IPs, ports, and metadata.
* ♾ **Continuous Mode**: Runs indefinitely until stopped.
* 📑 **Comprehensive Reports**: Exports to **CSV** and **PDF**.

---

### 🔑 Multithreaded Hash Cracker

A **parallelized tool for testing password strength**.

* ⚡ **Massively Parallel**: Cracks thousands of candidates per second.
* 🔍 **Auto-Detection**: Recognizes MD5, SHA-1, SHA-256.
* 🌐 **Intelligent Wordlists**: Streams from **SecLists** with fallback sources.
* 🔄 **Password Mutation**: Applies common mutations (Password123, Password!).
* 📂 **JSON Reporting**: Saves successful cracks in structured format.

---

## ⚙️ Installation

Run these commands inside your terminal:

bash
# Clone the repository
git clone https://github.com/your-username/CYBERSECURITY-PORTFOLIO.git

# Navigate to the project
cd CYBERSECURITY-PORTFOLIO/python-security-tools

# Create and activate virtual environment
python -m venv venv

# Windows
.\venv\Scripts\activate

# macOS/Linux
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt


---

## ▶️ Usage Examples

All tools are executed from:

bash
cd python-security-tools/tools/


📊 **Log Analyzer**

bash
# Analyze logs, search for patterns, and generate PDF report
python log_analyzer.py -f sample_apache.log /var/log/nginx/access.log -p "404" "sqlmap" --pdf


⚡ **Port Scanner**

bash
# Scan first 1024 ports on 192.168.1.101 using 100 threads
python port_scanner.py --host 192.168.1.101 --end-port 1024 --threads 100 --output scan_report.json


📡 **Packet Sniffer**

bash
# Continuous monitoring on interface eth0
python packet_sniffer.py -i eth0 --continuous

# Capture first 200 packets and export report
python packet_sniffer.py -i eth0 --count 200


🔑 **Hash Cracker**

bash
# Crack an MD5 hash using 50 threads and mutations
python online_hash_cracker.py --hash "5f4dcc3b5aa765d61d8327deb882cf99" --threads 50 --mutate


---

## ⚠️ Disclaimer

> **For Educational & Authorized Use Only**
>
> These tools are intended for **controlled lab environments** and **authorized penetration testing** where you have explicit permission.
>
> ❌ Unauthorized use against systems you do not own is **illegal**.
>
> The author assumes **no responsibility** for misuse.

---

✨ Now your README is structured like a professional open-source project, with clear sections, nice formatting, and beginner-friendly usage examples.

Do you want me to also **add badges** (like Python version, license, stars, etc.) at the top so it looks even more like a GitHub project?
