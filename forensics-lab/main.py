"""
=========================================
 Forensics Lab - Ultimate Forensic Toolkit
-----------------------------------------
Author: Nisarg
Description:
    - Unified, class-based forensic toolkit integrating:
        1. Disk Image Analysis (Metadata, Hashes, Partitions, Strings)
        2. File Hash Checking (Batch processing for directories)
        3. Memory Dump Analysis (String/IOC extraction with YARA scanning)
    - Professional, modular, and extensible object-oriented design.
=========================================
"""

import os
import sys
import argparse
import hashlib
import time
import json
import csv
import re
from typing import List, Dict, Any

# Optional imports with clear user feedback
try:
    import pytsk3
except ImportError:
    pytsk3 = None

try:
    import magic
except ImportError:
    magic = None

try:
    import yara
except ImportError:
    yara = None

try:
    from tqdm import tqdm
except ImportError:
    # Provide a dummy tqdm class if it's not installed
    class TqdmDummy:
        def __init__(self, iterable, *args, **kwargs):
            self.iterable = iterable
        def __iter__(self):
            return iter(self.iterable)
        def update(self, n=1):
            pass
        def close(self):
            pass
    tqdm = TqdmDummy
    
# --- UTILITY FUNCTIONS ---

def export_report(results: List[Dict[str, Any]], filename_base: str):
    """Export analysis results to both JSON and CSV."""
    if not results:
        print("[!] No results to export.")
        return

    json_path = f"{filename_base}_report.json"
    csv_path = f"{filename_base}_report.csv"

    # Export to JSON
    with open(json_path, "w", encoding='utf-8') as jf:
        json.dump(results, jf, indent=4, default=str)
    print(f"[+] JSON report saved to: {json_path}")

    # Export to CSV
    # Flatten the dictionary for CSV export
    flat_results = []
    for result in results:
        flat_result = {}
        for key, value in result.items():
            if isinstance(value, (dict, list)):
                flat_result[key] = json.dumps(value, default=str)
            else:
                flat_result[key] = value
        flat_results.append(flat_result)

    if flat_results:
        with open(csv_path, "w", newline='', encoding='utf-8') as cf:
            writer = csv.DictWriter(cf, fieldnames=flat_results[0].keys())
            writer.writeheader()
            writer.writerows(flat_results)
        print(f"[+] CSV report saved to: {csv_path}")


# --- ANALYSIS CLASSES ---

class DiskAnalyzer:
    """Analyzes disk images for metadata, partitions, strings, and hashes."""
    def __init__(self, image_path: str):
        self.image_path = image_path
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Disk image not found: {image_path}")
        if pytsk3 is None:
            print("[Warning] pytsk3 not installed. Partition analysis will be skipped.")
        if magic is None:
            print("[Warning] python-magic not installed. File type detection will be skipped.")

    def _compute_hash(self, algo: str = "sha256") -> str:
        hasher = getattr(hashlib, algo)()
        file_size = os.path.getsize(self.image_path)
        with open(self.image_path, "rb") as f, tqdm(total=file_size, unit='B', unit_scale=True, desc=f"Hashing ({algo})") as pbar:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
                pbar.update(len(chunk))
        return hasher.hexdigest()

    def analyze(self) -> Dict[str, Any]:
        print(f"\n--- Starting Disk Analysis on {self.image_path} ---")
        stats = os.stat(self.image_path)
        
        report = {
            "file_path": self.image_path,
            "size_mb": round(stats.st_size / (1024 * 1024), 2),
            "created": time.ctime(stats.st_ctime),
            "modified": time.ctime(stats.st_mtime),
            "accessed": time.ctime(stats.st_atime),
            "hashes": {
                "md5": self._compute_hash("md5"),
                "sha256": self._compute_hash("sha256"),
            },
            "file_type": magic.from_file(self.image_path) if magic else "python-magic not installed",
            "partitions": self._analyze_partitions(),
        }
        print("--- Disk Analysis Complete ---")
        return report

    def _analyze_partitions(self) -> List[Dict[str, Any]]:
        if not pytsk3:
            return []
        
        partitions_info = []
        try:
            img = pytsk3.Img_Info(self.image_path)
            vol = pytsk3.Volume_Info(img)
            print(f"[+] Found {vol.info.part_count} partitions.")
            for part in vol:
                part_info = {
                    "address": part.addr,
                    "description": part.desc.decode(errors='ignore'),
                    "start_sector": part.start,
                    "num_sectors": part.len,
                }
                partitions_info.append(part_info)
        except Exception as e:
            print(f"[!] Error analyzing partitions: {e}")
        return partitions_info

class HashChecker:
    """Calculates and verifies file hashes for integrity."""
    SUPPORTED_ALGOS = ["md5", "sha1", "sha256", "sha512"]

    def __init__(self, path: str, algo: str = "sha256", recursive: bool = True):
        if algo not in self.SUPPORTED_ALGOS:
            raise ValueError(f"Unsupported algorithm. Choose from: {', '.join(self.SUPPORTED_ALGOS)}")
        self.path = path
        self.algo = algo
        self.recursive = recursive

    def analyze(self) -> List[Dict[str, str]]:
        print(f"\n--- Starting Hash Analysis ({self.algo}) on {self.path} ---")
        results = []
        if os.path.isfile(self.path):
            results.append(self._process_file(self.path))
        elif os.path.isdir(self.path):
            file_list = []
            if self.recursive:
                for root, _, files in os.walk(self.path):
                    for f in files:
                        file_list.append(os.path.join(root, f))
            else:
                file_list = [os.path.join(self.path, f) for f in os.listdir(self.path) if os.path.isfile(os.path.join(self.path, f))]

            for f_path in tqdm(file_list, desc="Hashing files"):
                results.append(self._process_file(f_path))
        else:
            print(f"[!] Path not found: {self.path}")
        
        print("--- Hash Analysis Complete ---")
        return results

    def _process_file(self, file_path: str) -> Dict[str, str]:
        try:
            hasher = getattr(hashlib, self.algo)()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hasher.update(chunk)
            return {"file": file_path, "algorithm": self.algo, "hash": hasher.hexdigest()}
        except Exception as e:
            return {"file": file_path, "algorithm": self.algo, "hash": "ERROR", "error_message": str(e)}

class MemoryAnalyzer:
    """Analyzes memory dumps for IOCs and YARA rule matches."""
    def __init__(self, dump_path: str, ioc_list: List[str], yara_rules_path: str = None):
        self.dump_path = dump_path
        self.ioc_list = ioc_list
        if not os.path.exists(dump_path):
            raise FileNotFoundError(f"Memory dump not found: {dump_path}")
        if yara is None and yara_rules_path:
            print("[Warning] YARA rules provided, but yara-python is not installed.")
        
        self.compiled_rules = None
        if yara and yara_rules_path:
            try:
                self.compiled_rules = yara.compile(filepath=yara_rules_path)
            except yara.Error as e:
                print(f"[!] Error compiling YARA rules: {e}")

    def analyze(self) -> Dict[str, Any]:
        print(f"\n--- Starting Memory Analysis on {self.dump_path} ---")
        strings = self._extract_strings()
        report = {
            "file_path": self.dump_path,
            "total_strings_found": len(strings),
            "ioc_matches": self._search_iocs(strings),
            "yara_matches": self._yara_scan()
        }
        print("--- Memory Analysis Complete ---")
        return report

    def _extract_strings(self) -> List[str]:
        strings = []
        file_size = os.path.getsize(self.dump_path)
        pattern = re.compile(rb'[\x20-\x7E]{4,}')
        with open(self.dump_path, "rb") as f, tqdm(total=file_size, unit='B', unit_scale=True, desc="Extracting strings") as pbar:
            for chunk in iter(lambda: f.read(8192), b""):
                for match in pattern.finditer(chunk):
                    strings.append(match.group().decode(errors='ignore'))
                pbar.update(len(chunk))
        return strings

    def _search_iocs(self, strings: List[str]) -> Dict[str, List[str]]:
        ioc_matches = {ioc: [] for ioc in self.ioc_list}
        print("[+] Searching for IOCs...")
        for s in strings:
            for ioc in self.ioc_list:
                if ioc.lower() in s.lower():
                    ioc_matches[ioc].append(s)
        return {k: v for k, v in ioc_matches.items() if v}

    def _yara_scan(self) -> List[str]:
        if not self.compiled_rules:
            return []
        
        print("[+] Performing YARA scan...")
        try:
            matches = self.compiled_rules.match(self.dump_path)
            return [m.rule for m in matches]
        except yara.Error as e:
            print(f"[!] YARA scan failed: {e}")
            return []

# --- CLI INTERFACE ---

def main():
    parser = argparse.ArgumentParser(description="Ultimate Forensic Toolkit")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Disk Analyzer CLI
    disk_parser = subparsers.add_parser("disk", help="Analyze a disk image")
    disk_parser.add_argument("image_path", help="Path to the disk image file")
    disk_parser.add_argument("--output", default="disk_analysis", help="Base name for report files (e.g., 'case1')")

    # Hash Checker CLI
    hash_parser = subparsers.add_parser("hash", help="Hash a file or directory")
    hash_parser.add_argument("path", help="Path to the file or directory")
    hash_parser.add_argument("-a", "--algorithm", default="sha256", choices=HashChecker.SUPPORTED_ALGOS)
    hash_parser.add_argument("--no-recursive", action="store_false", dest="recursive", help="Disable recursive directory hashing")
    hash_parser.add_argument("--output", default="hash_analysis", help="Base name for report files")

    # Memory Analyzer CLI
    mem_parser = subparsers.add_parser("memory", help="Analyze a memory dump")
    mem_parser.add_argument("dump_path", help="Path to the memory dump file")
    mem_parser.add_argument("-i", "--ioc", nargs="+", default=["password", "secret", "key", "malware"], help="IOC keywords to search for")
    mem_parser.add_argument("--yara", help="Path to a YARA rules file")
    mem_parser.add_argument("--output", default="memory_analysis", help="Base name for report files")

    args = parser.parse_args()
    results = []

    try:
        if args.command == "disk":
            analyzer = DiskAnalyzer(args.image_path)
            results.append(analyzer.analyze())
        
        elif args.command == "hash":
            checker = HashChecker(args.path, args.algorithm, args.recursive)
            results.extend(checker.analyze())

        elif args.command == "memory":
            analyzer = MemoryAnalyzer(args.dump_path, args.ioc, args.yara)
            results.append(analyzer.analyze())
            
        if results:
            export_report(results, args.output)

    except Exception as e:
        print(f"\n[!!!] An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()