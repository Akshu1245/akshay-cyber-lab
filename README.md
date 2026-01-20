# Akshay's Cyber Lab 

> Personal security research & penetration testing toolkit

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Security](https://img.shields.io/badge/Focus-Cybersecurity-red.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

##  Purpose

A collection of security tools built for learning offensive security, penetration testing, and security automation. Each tool is designed to be practical, educational, and production-quality.

##  Tools

### `nmap-json.py` - Network Scanner with JSON Export
Automated Nmap wrapper that outputs structured JSON for pipeline integration.

```bash
# Basic scan
python tools/nmap-json.py 192.168.1.1

# JSON only output
python tools/nmap-json.py scanme.nmap.org --json-only

# Custom output file
python tools/nmap-json.py 10.0.0.0/24 -o network_scan.json
```

**Features:**
- Automatic service version detection
- OS fingerprinting
- JSON export for automation
- Human-readable summary tables
- Timestamped logging

---

### `hash-toolkit.py` - Hash Identification & Cracking
Multi-purpose hash utility for security assessments.

```bash
# Identify hash type
python tools/hash-toolkit.py identify 5f4dcc3b5aa765d61d8327deb882cf99

# Generate hashes
python tools/hash-toolkit.py generate "password123" --algo sha256
python tools/hash-toolkit.py generate "secret" --all

# Verify hash
python tools/hash-toolkit.py verify "password" 5f4dcc3b5aa765d61d8327deb882cf99

# Dictionary attack
python tools/hash-toolkit.py crack <hash> --wordlist rockyou.txt

# File integrity
python tools/hash-toolkit.py file document.pdf --algo sha256
```

**Features:**
- Auto-detect 13+ hash types (MD5, SHA1/256/512, bcrypt, NTLM, Unix crypt)
- Generate hashes with multiple algorithms
- Dictionary attack mode with progress tracking
- File hashing and integrity verification
- Security rating for each hash type

---

##  Structure

```
 tools/
    nmap-json.py      # Network scanning
    hash-toolkit.py   # Hash utilities
 logs/
    Day1.md           # Learning journal
    Day3.md
 README.md
```

##  Getting Started

```bash
# Clone
git clone https://github.com/Akshu1245/akshay-cyber-lab.git
cd akshay-cyber-lab

# Optional: Install bcrypt for full hash support
pip install bcrypt

# Run tools
python tools/hash-toolkit.py --help
python tools/nmap-json.py --help
```

##  Legal Notice

These tools are for **educational and authorized testing only**. Only use on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal.

##  Learning Path

- [x] Network scanning fundamentals (Nmap)
- [x] Hash identification and cracking
- [x] Docker security labs (OWASP Juice Shop)
- [ ] Web vulnerability scanning
- [ ] Wireless security tools
- [ ] Privilege escalation scripts

##  Links

- [LinkedIn](https://www.linkedin.com/in/k-s-akshay-0707a42b6/)
- [GitHub](https://github.com/Akshu1245)

---

*Built for learning. Used responsibly.*
