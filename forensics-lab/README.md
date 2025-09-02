# 🕵️ Forensics Lab: The Ultimate Triage Toolkit

![Language](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

A modular, command-line forensic toolkit for rapid triage of disk images, memory dumps, and file integrity verification. This toolkit is built with a professional, object-oriented design and provides a unified interface for three core analysis modules.

## Table of Contents
1. [Features](#features)
2. [Installation](#installation)
3. [Usage Examples](#usage-examples)
4. [Investigator Workflow](#investigator-workflow)

---

## Features

-   **Unified Interface**: Access all tools (`disk`, `hash`, `memory`) from a single, powerful `main.py` entry point.
-   **Class-Based Design**: Professional, object-oriented structure makes the code clean, maintainable, and easy to extend.
-   **User-Friendly Feedback**: Integrated `tqdm` progress bars provide real-time feedback during time-consuming operations like hashing and string extraction.

### Disk Analysis Module (`disk`)
-   **Full Metadata**: Extracts size, timestamps, and file type (using `python-magic`).
-   **Integrity Hashes**: Computes MD5 and SHA256 hashes for chain-of-custody.
-   **Partition Analysis**: Lists all partitions within the disk image using `pytsk3`.

### Hash Analysis Module (`hash`)
-   **Multiple Algorithms**: Supports MD5, SHA1, SHA256, and SHA512.
-   **Batch Processing**: Efficiently hashes all files within a directory, with an option for recursive analysis.
-   **Ideal for Evidence Verification**: Perfect for ensuring the integrity of forensic copies.

### Memory Analysis Module (`memory`)
-   **String Extraction**: Efficiently pulls all readable ASCII strings from a raw memory dump.
-   **IOC Searching**: Scans the extracted strings for a customizable list of Indicators of Compromise (e.g., "password", "malware").
-   **YARA Scanning**: Integrates with `yara-python` to scan memory dumps against a provided YARA rule file for malware signatures.

---

## Installation

This toolkit requires Python 3.10+ and a few external libraries.

1.  **Clone the portfolio repository:**
    bash
    git clone [https://github.com/your-username/CYBERSECURITY-PORTFOLIO.git](https://github.com/your-username/CYBERSECURITY-PORTFOLIO.git)
    

2.  **Navigate to the project directory:**
    bash
    cd CYBERSECURITY-PORTFOLIO/forensics-lab
    

3.  **Create and activate a Python virtual environment:**
    bash
    # Create the venv
    python -m venv venv

    # Activate on Windows
    .\venv\Scripts\activate

    # Activate on macOS/Linux
    source venv/bin/activate
    

4.  **Install the required libraries:**
    bash
    pip install -r requirements.txt
    

---

## Usage Examples

All tools are run from the `main.py` script. Use the `-h` flag to see all options.

bash
python main.py -h
`

### Disk Analysis

bash
# Analyze a disk image and save reports named 'case_001_report.json' and 'case_001_report.csv'
python main.py disk /path/to/disk.dd --output case_001


### Hash Analysis

bash
# Recursively hash an entire evidence folder using sha256
python main.py hash /path/to/evidence_folder -a sha256 --output evidence_hashes

# Hash a single file with md5
python main.py hash /path/to/suspicious.exe -a md5 --output suspicious_hash


### Memory Analysis

bash
# Analyze a memory dump with default IOCs
python main.py memory /path/to/memdump.raw --output mem_initial_triage

# Analyze with custom IOCs and a YARA rule file
python main.py memory /path/to/memdump.raw --ioc "evil.exe" "c2.server.com" --yara /path/to/rules.yar --output mem_malware_scan


-----

## Investigator Workflow

A typical use-case for this toolkit during an investigation:

1.  **Verify Evidence:** Use the `hash` module to verify the integrity of a forensic image copy against the original.
2.  **Initial Triage:** Run the `disk` module on the image to get a quick overview of partitions and metadata.
3.  **Memory Forensics:** Use the `memory` module on the corresponding memory dump, scanning for known IOCs and malware signatures with YARA to quickly identify suspicious activity.