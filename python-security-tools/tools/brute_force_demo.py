#!/usr/bin/env python3
"""
online_hash_cracker.py

A multi-threaded, online wordlist hash cracker designed for educational purposes.
- Features multithreading for significantly faster cracking.
- Streams remote wordlists to avoid saving large files locally.
- Auto-detects common hash types using regex and length.
- Applies optional mutations to password candidates.
- Includes fallback URLs for wordlist sources.
- Generates a JSON report upon finding a password.
"""
import argparse
import hashlib
import requests
import sys
import re
import time
import json
import threading
import concurrent.futures
from typing import Iterable, List

# -----------------------
# Config: Add/extend sources here
# -----------------------
WORDLIST_SOURCES = {
    "10k": [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt",
        "https://raw.githubusercontent.com/kkrypt0nn/wordlists/main/10k-most-common.txt",
    ],
    "rockyou-lite": [
        "https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Real-Passwords/Top1000.txt",
        "https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Real-Passwords/Top100.txt",
    ],
    "500": [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/top-500.txt",
    ],
}

# Regex-based detection for common hash formats
HASH_PATTERNS = {
    r"^[a-f0-9]{32}$": "MD5",
    r"^[A-F0-9]{32}$": "MD5 (uppercase)",
    r"^[a-f0-9]{40}$": "SHA-1",
    r"^[a-f0-9]{64}$": "SHA-256",
    r"^[a-f0-9]{128}$": "SHA-512",
    r"^\$2[aby]\$.{56}$": "bcrypt",
    r"^\*[A-F0-9]{40}$": "MySQL5+ (SHA1)",
    r"^[0-9A-F]{32}$": "NTLM",
}

# Hashlib-supported algorithm names for cracking
HASHLIB_ALGOS = {"md5", "sha1", "sha256", "sha512"}

# Global event to signal all threads when a password is found
password_found = threading.Event()

# -----------------------
# Utilities
# -----------------------
def normalize_hash(h: str) -> str:
    h = h.strip()
    if h.startswith("0x"):
        h = h[2:]
    return h.lower()

def identify_hash_type(hash_hex: str) -> str:
    """Try regex patterns first, then fallback to length-based guesses."""
    for pat, name in HASH_PATTERNS.items():
        if re.match(pat, hash_hex):
            return name
    length_map = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}
    hash_len = len(hash_hex)
    if hash_len in length_map:
        return f"{length_map[hash_len]} (length guess)"
    return f"Unknown (len={hash_len})"

def pick_hashlib_algo(name: str) -> str:
    """Map detection/mode name to a hashlib algorithm using a dictionary."""
    name_lower = name.lower()
    algo_map = {
        "md5": "md5", "sha-1": "sha1", "sha1": "sha1",
        "sha256": "sha256", "sha-256": "sha256",
        "sha512": "sha512", "sha-512": "sha512",
    }
    for key, value in algo_map.items():
        if key in name_lower:
            return value
    return None

def iter_online_wordlist(sources: List[str]) -> Iterable[str]:
    """Try each URL in sources, stream lines from the first successful one."""
    last_error = None
    for url in sources:
        print(f"[+] Trying source: {url}")
        try:
            resp = requests.get(url, stream=True, timeout=20)
            if resp.status_code != 200:
                print(f"[!] Source returned HTTP {resp.status_code}, trying next...")
                last_error = f"HTTP {resp.status_code}"
                continue
            
            count = 0
            for raw in resp.iter_lines(decode_unicode=True, errors="ignore"):
                if raw:
                    word = raw.strip()
                    if word:
                        yield word
                        count += 1
            
            if count > 0:
                return  # Successfully streamed this source
            else:
                last_error = "empty response"
                print("[!] Source was empty, trying next...")

        except requests.RequestException as e:
            print(f"[!] Error fetching {url}: {e}. Trying next...")
            last_error = str(e)
            
    print("[-] All wordlist sources failed.")
    if last_error:
        print(f"[-] Last error: {last_error}")
    raise SystemExit(1)

def variants(word: str, mutate: bool):
    """Yield base candidate and simple lightweight mutations."""
    yield word
    if not mutate:
        return
    yield word.capitalize()
    yield word + "1"
    yield word + "123"
    yield word + "!"
    yield word + "@123"
    yield word + "2025"

# -----------------------
# Cracking Logic (for multithreading)
# -----------------------
def check_hash(args):
    """A helper function for the thread pool to run."""
    candidate, target_hash, hash_func_ctor = args
    if password_found.is_set():
        return None
    try:
        h = hash_func_ctor(candidate.encode("utf-8", "ignore")).hexdigest()
        if h == target_hash:
            password_found.set()  # Signal other threads to stop
            return candidate
    except Exception:
        return None
    return None

def crack_streamed(target_hash, algorithm, sources, mutate, output_file, num_threads, progress_every):
    """Stream candidates and attempt to match the hash using a thread pool."""
    if algorithm not in HASHLIB_ALGOS:
        print(f"[!] Algorithm '{algorithm}' is not supported by hashlib.")
        print("[!] Supported:", ", ".join(sorted(HASHLIB_ALGOS)))
        raise SystemExit(1)

    hash_func_ctor = getattr(hashlib, algorithm)
    start_time = time.time()
    
    print(f"[+] Starting cracker with {num_threads} threads...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        tasks = []
        found_password = None
        total_attempts = 0

        for base_word in iter_online_wordlist(sources):
            if password_found.is_set():
                break

            for candidate in variants(base_word, mutate):
                total_attempts += 1
                task_args = (candidate, target_hash, hash_func_ctor)
                tasks.append(executor.submit(check_hash, task_args))
            
            if len(tasks) >= 1000 or (len(tasks) > 0 and password_found.is_set()):
                for future in concurrent.futures.as_completed(tasks):
                    result = future.result()
                    if result:
                        found_password = result
                        password_found.set()
                        break
                tasks = [] 
            
            if found_password:
                break
            
            if progress_every and total_attempts % progress_every == 0:
                elapsed = time.time() - start_time
                print(f"[...] {total_attempts} attempts | {total_attempts/elapsed:.0f}/sec | elapsed {elapsed:.1f}s")
        
        if not found_password:
            for future in concurrent.futures.as_completed(tasks):
                result = future.result()
                if result:
                    found_password = result
                    break

    executor.shutdown(wait=False, cancel_futures=True)
    elapsed = time.time() - start_time

    if found_password:
        print(f"\n[✓] Password found: {found_password}")
        print(f"[✓] Total Attempts: {total_attempts} | Speed: {total_attempts/elapsed:.0f} attempts/sec | Time: {elapsed:.2f}s")
        if output_file:
            report = {
                "target_hash": target_hash, "algorithm": algorithm,
                "password": found_password, "attempts": total_attempts,
                "time_seconds": round(elapsed, 2),
            }
            try:
                with open(output_file, 'w') as f:
                    json.dump(report, f, indent=4)
                print(f"[+] Report saved to {output_file}")
            except IOError as e:
                print(f"[!] Error saving report: {e}")
    else:
        print(f"[-] Password not found. Attempts: {total_attempts} | Time: {elapsed:.2f}s")

    password_found.clear()

# -----------------------
# CLI
# -----------------------
def main():
    parser = argparse.ArgumentParser(description="Multi-threaded Online Wordlist Hash Cracker (Educational)")
    parser.add_argument("--hash", required=True, help="Target hash (hex)")
    parser.add_argument("--algorithm", default="auto", help="Cracking algorithm (md5/sha1/sha256/sha512) or 'auto'")
    parser.add_argument("--wordlist", default="10k", choices=list(WORDLIST_SOURCES.keys()),
                        help="Which pre-configured online wordlist to stream")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads to use for cracking")
    parser.add_argument("--mutate", action="store_true", help="Apply light mutations to each candidate (slower)")
    parser.add_argument("--output", help="Output file to save result as JSON (optional)")
    parser.add_argument("--progress-every", type=int, default=5000, help="Show progress every N attempts (0 to disable)")
    args = parser.parse_args()

    target = normalize_hash(args.hash)
    hash_desc = identify_hash_type(target)
    print(f"[+] Provided hash looks like: {hash_desc}")

    algo = args.algorithm
    if algo == "auto":
        mapped = pick_hashlib_algo(hash_desc)
        if not mapped:
            print("[!] Could not auto-detect a supported algorithm from the hash.")
            print("[!] Please provide --algorithm explicitly (e.g., --algorithm md5).")
            raise SystemExit(1)
        algo = mapped
        print(f"[+] Auto-selected cracking algorithm: {algo}")

    sources = WORDLIST_SOURCES.get(args.wordlist)
    if not sources:
        print(f"[!] No configured sources for wordlist key '{args.wordlist}'")
        raise SystemExit(1)

    print(f"[+] Using wordlist key: {args.wordlist}")
    print("[!] DISCLAIMER: For educational and authorized testing only.")
    print("[!] Do not use against systems you don't own or have explicit permission to test.\n")

    crack_streamed(
        target_hash=target, algorithm=algo, sources=sources,
        mutate=args.mutate, output_file=args.output,
        num_threads=args.threads, progress_every=args.progress_every
    )

if __name__ == "__main__":
    main()
