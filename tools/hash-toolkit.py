#!/usr/bin/env python3
"""
Hash Toolkit - Security Hash Utility
====================================
Identify, generate, verify, and crack common hash types.
Designed for penetration testing and security auditing.

Features:
    - Automatic hash type identification
    - Generate hashes (MD5, SHA1, SHA256, SHA512, bcrypt)
    - Verify hash against plaintext
    - Dictionary attack mode
    - File hashing with integrity verification

Author: K.S. Akshay
License: MIT
"""

import hashlib
import argparse
import sys
import os
import re
from datetime import datetime
from typing import Optional, List, Tuple, Dict
from pathlib import Path

# Optional bcrypt support
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False


# =============================================================================
# Hash Pattern Database
# =============================================================================

HASH_PATTERNS: Dict[str, Dict] = {
    "MD5": {
        "regex": r"^[a-fA-F0-9]{32}$",
        "length": 32,
        "description": "MD5 (Message Digest 5)",
        "security": "WEAK - Vulnerable to collision attacks"
    },
    "SHA1": {
        "regex": r"^[a-fA-F0-9]{40}$",
        "length": 40,
        "description": "SHA-1 (Secure Hash Algorithm 1)",
        "security": "WEAK - Deprecated, collision attacks demonstrated"
    },
    "SHA256": {
        "regex": r"^[a-fA-F0-9]{64}$",
        "length": 64,
        "description": "SHA-256 (SHA-2 family)",
        "security": "STRONG - Currently secure"
    },
    "SHA512": {
        "regex": r"^[a-fA-F0-9]{128}$",
        "length": 128,
        "description": "SHA-512 (SHA-2 family)",
        "security": "STRONG - Currently secure"
    },
    "SHA384": {
        "regex": r"^[a-fA-F0-9]{96}$",
        "length": 96,
        "description": "SHA-384 (SHA-2 family)",
        "security": "STRONG - Currently secure"
    },
    "NTLM": {
        "regex": r"^[a-fA-F0-9]{32}$",
        "length": 32,
        "description": "NTLM (Windows NT LAN Manager)",
        "security": "WEAK - No salt, fast to crack"
    },
    "MySQL5": {
        "regex": r"^\*[a-fA-F0-9]{40}$",
        "length": 41,
        "description": "MySQL 5.x password hash",
        "security": "MODERATE - Double SHA1"
    },
    "bcrypt": {
        "regex": r"^\$2[ayb]\$[0-9]{2}\$[./A-Za-z0-9]{53}$",
        "length": 60,
        "description": "bcrypt (Blowfish-based)",
        "security": "STRONG - Adaptive, salted, slow"
    },
    "SHA3-256": {
        "regex": r"^[a-fA-F0-9]{64}$",
        "length": 64,
        "description": "SHA3-256 (Keccak)",
        "security": "STRONG - Latest standard"
    },
    "MD5-Unix": {
        "regex": r"^\$1\$[./0-9A-Za-z]{8}\$[./0-9A-Za-z]{22}$",
        "length": 34,
        "description": "MD5 Unix crypt",
        "security": "WEAK - Deprecated"
    },
    "SHA256-Unix": {
        "regex": r"^\$5\$[./0-9A-Za-z]{8,16}\$[./0-9A-Za-z]{43}$",
        "length": None,
        "description": "SHA-256 Unix crypt",
        "security": "MODERATE - Salted"
    },
    "SHA512-Unix": {
        "regex": r"^\$6\$[./0-9A-Za-z]{8,16}\$[./0-9A-Za-z]{86}$",
        "length": None,
        "description": "SHA-512 Unix crypt",
        "security": "STRONG - Salted, many rounds"
    }
}


# =============================================================================
# Logging
# =============================================================================

class Logger:
    """Timestamped logging with severity levels."""
    
    LEVELS = {"INFO": "+", "WARN": "!", "ERROR": "-", "SUCCESS": "*", "CRACK": "#"}
    
    @staticmethod
    def log(message: str, level: str = "INFO") -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        symbol = Logger.LEVELS.get(level, "+")
        print(f"[{timestamp}] [{symbol}] {message}")


log = Logger.log


# =============================================================================
# Hash Identification
# =============================================================================

def identify_hash(hash_string: str) -> List[Tuple[str, Dict]]:
    """
    Identify possible hash types based on pattern matching.
    
    Returns list of (name, info) tuples sorted by likelihood.
    """
    hash_string = hash_string.strip()
    matches = []
    
    for name, info in HASH_PATTERNS.items():
        if re.match(info["regex"], hash_string):
            matches.append((name, info))
    
    # MD5 and NTLM have same pattern - provide context
    if len(matches) > 1:
        # Sort by specificity (longer regex patterns are more specific)
        matches.sort(key=lambda x: len(x[1]["regex"]), reverse=True)
    
    return matches


def print_identification(hash_string: str) -> None:
    """Print hash identification results."""
    matches = identify_hash(hash_string)
    
    print(f"\n{'='*60}")
    print(f"Hash: {hash_string}")
    print(f"Length: {len(hash_string)} characters")
    print(f"{'='*60}\n")
    
    if not matches:
        log("No matching hash patterns found", "WARN")
        log("Could be: custom hash, encoding, or corrupted data", "INFO")
        return
    
    log(f"Found {len(matches)} possible match(es):\n", "SUCCESS")
    
    for i, (name, info) in enumerate(matches, 1):
        print(f"  [{i}] {name}")
        print(f"      Description: {info['description']}")
        print(f"      Security: {info['security']}")
        print()


# =============================================================================
# Hash Generation
# =============================================================================

HASH_FUNCTIONS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
    "sha3_256": hashlib.sha3_256,
    "sha3_512": hashlib.sha3_512,
}


def generate_hash(plaintext: str, algorithm: str) -> Optional[str]:
    """Generate hash from plaintext using specified algorithm."""
    algorithm = algorithm.lower().replace("-", "_")
    
    if algorithm == "bcrypt":
        if not BCRYPT_AVAILABLE:
            log("bcrypt not installed. Run: pip install bcrypt", "ERROR")
            return None
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(plaintext.encode(), salt).decode()
    
    if algorithm == "ntlm":
        # NTLM: MD4 of UTF-16LE encoded password
        import codecs
        return hashlib.new('md4', plaintext.encode('utf-16le')).hexdigest()
    
    if algorithm in HASH_FUNCTIONS:
        return HASH_FUNCTIONS[algorithm](plaintext.encode()).hexdigest()
    
    log(f"Unknown algorithm: {algorithm}", "ERROR")
    log(f"Supported: {', '.join(HASH_FUNCTIONS.keys())}, bcrypt, ntlm", "INFO")
    return None


def generate_all_hashes(plaintext: str) -> Dict[str, str]:
    """Generate all supported hashes for a plaintext."""
    results = {}
    
    for algo in HASH_FUNCTIONS:
        results[algo] = HASH_FUNCTIONS[algo](plaintext.encode()).hexdigest()
    
    # Add NTLM
    results["ntlm"] = hashlib.new('md4', plaintext.encode('utf-16le')).hexdigest()
    
    # Add bcrypt if available
    if BCRYPT_AVAILABLE:
        salt = bcrypt.gensalt(rounds=10)
        results["bcrypt"] = bcrypt.hashpw(plaintext.encode(), salt).decode()
    
    return results


def print_all_hashes(plaintext: str) -> None:
    """Print all hash variants of plaintext."""
    hashes = generate_all_hashes(plaintext)
    
    print(f"\n{'='*60}")
    print(f"Plaintext: {plaintext}")
    print(f"{'='*60}\n")
    
    for algo, hash_value in hashes.items():
        print(f"  {algo.upper():<12} {hash_value}")
    
    print()


# =============================================================================
# Hash Verification
# =============================================================================

def verify_hash(plaintext: str, hash_string: str, algorithm: Optional[str] = None) -> bool:
    """Verify if plaintext matches given hash."""
    hash_string = hash_string.strip()
    
    # Auto-detect algorithm if not specified
    if algorithm is None:
        matches = identify_hash(hash_string)
        if not matches:
            log("Cannot auto-detect hash type. Specify with --algo", "ERROR")
            return False
        
        # Try each potential match
        for name, _ in matches:
            algo_map = {
                "MD5": "md5", "SHA1": "sha1", "SHA256": "sha256",
                "SHA384": "sha384", "SHA512": "sha512", "NTLM": "ntlm",
                "bcrypt": "bcrypt", "SHA3-256": "sha3_256"
            }
            if name in algo_map:
                if verify_single(plaintext, hash_string, algo_map[name]):
                    return True
        return False
    
    return verify_single(plaintext, hash_string, algorithm)


def verify_single(plaintext: str, hash_string: str, algorithm: str) -> bool:
    """Verify hash with specific algorithm."""
    algorithm = algorithm.lower().replace("-", "_")
    
    if algorithm == "bcrypt":
        if not BCRYPT_AVAILABLE:
            return False
        try:
            return bcrypt.checkpw(plaintext.encode(), hash_string.encode())
        except Exception:
            return False
    
    generated = generate_hash(plaintext, algorithm)
    return generated is not None and generated.lower() == hash_string.lower()


# =============================================================================
# Dictionary Attack
# =============================================================================

def dictionary_attack(hash_string: str, wordlist_path: str, 
                      algorithm: Optional[str] = None) -> Optional[str]:
    """
    Attempt to crack hash using dictionary attack.
    
    WARNING: Only use on hashes you own or have permission to test.
    """
    hash_string = hash_string.strip().lower()
    
    if not os.path.exists(wordlist_path):
        log(f"Wordlist not found: {wordlist_path}", "ERROR")
        return None
    
    # Detect algorithm if not specified
    if algorithm is None:
        matches = identify_hash(hash_string)
        if not matches:
            log("Cannot detect hash type. Specify with --algo", "ERROR")
            return None
        # Use first match (most common)
        algo_name = matches[0][0]
        algo_map = {"MD5": "md5", "SHA1": "sha1", "SHA256": "sha256", 
                    "SHA512": "sha512", "NTLM": "ntlm"}
        algorithm = algo_map.get(algo_name)
        if not algorithm:
            log(f"Dictionary attack not supported for {algo_name}", "ERROR")
            return None
        log(f"Detected hash type: {algo_name}", "INFO")
    
    log(f"Starting dictionary attack with {wordlist_path}", "INFO")
    log(f"Algorithm: {algorithm.upper()}", "INFO")
    
    tried = 0
    start_time = datetime.now()
    
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                word = line.strip()
                if not word:
                    continue
                
                tried += 1
                generated = generate_hash(word, algorithm)
                
                if generated and generated.lower() == hash_string:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    log(f"CRACKED! Password found: {word}", "CRACK")
                    log(f"Tried {tried:,} passwords in {elapsed:.2f}s", "SUCCESS")
                    return word
                
                # Progress indicator every 100k
                if tried % 100000 == 0:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    rate = tried / elapsed if elapsed > 0 else 0
                    log(f"Tried {tried:,} passwords ({rate:,.0f}/sec)...", "INFO")
    
    except KeyboardInterrupt:
        log("Attack interrupted by user", "WARN")
        return None
    
    elapsed = (datetime.now() - start_time).total_seconds()
    log(f"Password not found. Tried {tried:,} passwords in {elapsed:.2f}s", "WARN")
    return None


# =============================================================================
# File Hashing
# =============================================================================

def hash_file(filepath: str, algorithm: str = "sha256") -> Optional[str]:
    """Calculate hash of file contents."""
    if not os.path.exists(filepath):
        log(f"File not found: {filepath}", "ERROR")
        return None
    
    algorithm = algorithm.lower().replace("-", "_")
    
    if algorithm not in HASH_FUNCTIONS:
        log(f"Unsupported algorithm: {algorithm}", "ERROR")
        return None
    
    hasher = HASH_FUNCTIONS[algorithm]()
    
    try:
        with open(filepath, 'rb') as f:
            # Read in chunks for large files
            for chunk in iter(lambda: f.read(65536), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except IOError as e:
        log(f"Error reading file: {e}", "ERROR")
        return None


def verify_file_hash(filepath: str, expected_hash: str, 
                     algorithm: str = "sha256") -> bool:
    """Verify file integrity against expected hash."""
    actual = hash_file(filepath, algorithm)
    if actual is None:
        return False
    
    return actual.lower() == expected_hash.lower().strip()


# =============================================================================
# CLI Interface
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Hash Toolkit - Security Hash Utility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Identify hash type:
    %(prog)s identify 5f4dcc3b5aa765d61d8327deb882cf99
    
  Generate hash:
    %(prog)s generate "password123" --algo sha256
    %(prog)s generate "secret" --all
    
  Verify hash:
    %(prog)s verify "password" 5f4dcc3b5aa765d61d8327deb882cf99
    
  Dictionary attack:
    %(prog)s crack 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist rockyou.txt
    
  Hash file:
    %(prog)s file document.pdf --algo sha256
    %(prog)s file installer.exe --verify abc123...

Security Note:
  Only use cracking features on hashes you own or have explicit permission to test.
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Identify command
    id_parser = subparsers.add_parser("identify", aliases=["id"], 
                                       help="Identify hash type")
    id_parser.add_argument("hash", help="Hash string to identify")
    
    # Generate command
    gen_parser = subparsers.add_parser("generate", aliases=["gen"], 
                                        help="Generate hash from plaintext")
    gen_parser.add_argument("plaintext", help="Text to hash")
    gen_parser.add_argument("--algo", "-a", default="sha256",
                           help="Algorithm (md5, sha1, sha256, sha512, bcrypt, ntlm)")
    gen_parser.add_argument("--all", action="store_true",
                           help="Generate all supported hash types")
    
    # Verify command
    ver_parser = subparsers.add_parser("verify", aliases=["ver"],
                                        help="Verify plaintext against hash")
    ver_parser.add_argument("plaintext", help="Plaintext to verify")
    ver_parser.add_argument("hash", help="Hash to verify against")
    ver_parser.add_argument("--algo", "-a", help="Algorithm (auto-detect if omitted)")
    
    # Crack command
    crack_parser = subparsers.add_parser("crack", help="Dictionary attack")
    crack_parser.add_argument("hash", help="Hash to crack")
    crack_parser.add_argument("--wordlist", "-w", required=True,
                              help="Path to wordlist file")
    crack_parser.add_argument("--algo", "-a", help="Algorithm (auto-detect if omitted)")
    
    # File command
    file_parser = subparsers.add_parser("file", help="Hash or verify file")
    file_parser.add_argument("filepath", help="Path to file")
    file_parser.add_argument("--algo", "-a", default="sha256",
                            help="Algorithm (default: sha256)")
    file_parser.add_argument("--verify", "-v", metavar="HASH",
                            help="Expected hash to verify against")
    
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        sys.exit(0)
    
    # Execute command
    if args.command in ("identify", "id"):
        print_identification(args.hash)
    
    elif args.command in ("generate", "gen"):
        if args.all:
            print_all_hashes(args.plaintext)
        else:
            result = generate_hash(args.plaintext, args.algo)
            if result:
                print(f"\n{args.algo.upper()}: {result}\n")
            else:
                sys.exit(1)
    
    elif args.command in ("verify", "ver"):
        match = verify_hash(args.plaintext, args.hash, args.algo)
        if match:
            log("Hash MATCHES plaintext", "SUCCESS")
            sys.exit(0)
        else:
            log("Hash does NOT match plaintext", "ERROR")
            sys.exit(1)
    
    elif args.command == "crack":
        result = dictionary_attack(args.hash, args.wordlist, args.algo)
        sys.exit(0 if result else 1)
    
    elif args.command == "file":
        if args.verify:
            match = verify_file_hash(args.filepath, args.verify, args.algo)
            if match:
                log(f"File integrity VERIFIED ({args.algo.upper()})", "SUCCESS")
                sys.exit(0)
            else:
                log("File integrity check FAILED", "ERROR")
                sys.exit(1)
        else:
            result = hash_file(args.filepath, args.algo)
            if result:
                filename = os.path.basename(args.filepath)
                print(f"\n{args.algo.upper()} ({filename}):")
                print(f"  {result}\n")
            else:
                sys.exit(1)


if __name__ == "__main__":
    main()
