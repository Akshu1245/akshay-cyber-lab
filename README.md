# Akshay's Cyber Lab 

> Personal security research & penetration testing toolkit

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Security](https://img.shields.io/badge/Focus-Cybersecurity-red.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security Audit](https://github.com/Akshu1245/akshay-cyber-lab/actions/workflows/security-audit.yml/badge.svg)](https://github.com/Akshu1245/akshay-cyber-lab/actions/workflows/security-audit.yml)

##  Purpose

A collection of security tools built for learning offensive security, penetration testing, and security automation. Each tool is designed to be practical, educational, and production-quality.

##  Tools

### `security-auditor.py` - Automatic Vulnerability Scanner & Fixer  NEW
Scans source code for security vulnerabilities and can automatically fix common issues.

```bash
# Scan directory
python tools/security-auditor.py ./src

# Scan and AUTO-FIX issues
python tools/security-auditor.py . --fix

# JSON output for CI/CD
python tools/security-auditor.py . --json

# SARIF output for GitHub Security tab
python tools/security-auditor.py . --sarif > results.sarif
```

**Detects 15+ vulnerability types:**

| Category | Checks |
|----------|--------|
| **Secrets** | Hardcoded API keys, passwords, tokens, AWS keys |
| **Injection** | SQL injection, command injection, eval/exec |
| **Crypto** | Weak hashes (MD5, SHA1), insecure random |
| **Config** | Debug mode, Flask debug, wildcard CORS |
| **Deserialization** | Pickle, unsafe YAML loading |
| **Other** | Path traversal, logging sensitive data |

**Auto-fixes available for:**
- eval()  ast.literal_eval()
- MD5/SHA1  SHA256
- Debug mode  environment variable
- yaml.load  yaml.safe_load

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

##  CI/CD Integration

This repo includes automatic security scanning via GitHub Actions:

- **On every push:** Scans code for vulnerabilities
- **On PRs:** Blocks merge if CRITICAL issues found
- **Weekly:** Scheduled security audit
- **SARIF:** Results appear in GitHub Security tab

---

##  Structure

```
 .github/workflows/
    security-audit.yml    # Auto security scanning
 tools/
    security-auditor.py   # Vulnerability scanner + auto-fixer
    hash-toolkit.py       # Hash utilities
    nmap-json.py          # Network scanning
 logs/
    Day1.md
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
python tools/security-auditor.py --help
python tools/hash-toolkit.py --help
python tools/nmap-json.py --help
```

##  Legal Notice

These tools are for **educational and authorized testing only**. Only use on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal.

##  Learning Path

- [x] Network scanning fundamentals (Nmap)
- [x] Hash identification and cracking
- [x] Docker security labs (OWASP Juice Shop)
- [x] Static code security analysis
- [x] CI/CD security integration
- [ ] Web vulnerability scanning
- [ ] Wireless security tools
- [ ] Privilege escalation scripts

##  Links

- [LinkedIn](https://www.linkedin.com/in/k-s-akshay-0707a42b6/)
- [GitHub](https://github.com/Akshu1245)

---

*Built for learning. Used responsibly.*
