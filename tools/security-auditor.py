#!/usr/bin/env python3
"""
Security Auditor - Automatic Vulnerability Scanner & Fixer
===========================================================
Scans source code for common security vulnerabilities and optionally
applies automatic fixes. Designed for CI/CD integration.

Checks:
    - Hardcoded secrets (API keys, passwords, tokens)
    - SQL injection vulnerabilities
    - Command injection risks
    - Insecure random number generation
    - Weak cryptography usage
    - Debug mode in production
    - Insecure deserialization
    - Path traversal vulnerabilities

Author: K.S. Akshay
License: MIT
"""

import os
import re
import sys
import json
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """Security finding with location and fix suggestion."""
    rule_id: str
    severity: Severity
    title: str
    description: str
    file_path: str
    line_number: int
    line_content: str
    fix_suggestion: str
    auto_fixable: bool
    fixed_content: Optional[str] = None


class Colors:
    """ANSI color codes for terminal output."""
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'
    
    @classmethod
    def disable(cls):
        cls.RED = cls.YELLOW = cls.GREEN = cls.BLUE = cls.CYAN = cls.BOLD = cls.END = ''


# =============================================================================
# Security Rules Database
# =============================================================================

SECURITY_RULES = {
    # Hardcoded Secrets
    "SEC001": {
        "title": "Hardcoded API Key",
        "severity": Severity.CRITICAL,
        "pattern": r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\'][a-zA-Z0-9]{16,}["\']',
        "description": "API keys should never be hardcoded. Use environment variables.",
        "fix": "Use os.environ.get('API_KEY') or load from secure vault",
        "auto_fix": lambda m: re.sub(r'["\'][a-zA-Z0-9]{16,}["\']', 'os.environ.get("API_KEY")', m)
    },
    "SEC002": {
        "title": "Hardcoded Password",
        "severity": Severity.CRITICAL,
        "pattern": r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']',
        "description": "Passwords must not be hardcoded in source code.",
        "fix": "Use environment variables or secure credential storage",
        "auto_fix": lambda m: re.sub(r'["\'][^"\']+["\']$', 'os.environ.get("PASSWORD")', m)
    },
    "SEC003": {
        "title": "Hardcoded Secret/Token",
        "severity": Severity.CRITICAL,
        "pattern": r'(?i)(secret|token|auth)[_-]?(key)?\s*[=:]\s*["\'][a-zA-Z0-9+/=]{20,}["\']',
        "description": "Secrets and tokens should be externalized.",
        "fix": "Store in environment variables or secrets manager",
        "auto_fix": None
    },
    "SEC004": {
        "title": "AWS Access Key",
        "severity": Severity.CRITICAL,
        "pattern": r'AKIA[0-9A-Z]{16}',
        "description": "AWS access keys detected. Rotate immediately if exposed.",
        "fix": "Use IAM roles or AWS Secrets Manager",
        "auto_fix": None
    },
    
    # SQL Injection
    "SEC010": {
        "title": "Potential SQL Injection",
        "severity": Severity.HIGH,
        "pattern": r'(?i)(execute|cursor\.execute|query)\s*\(\s*["\'].*%s.*["\'].*%',
        "description": "String formatting in SQL queries enables injection attacks.",
        "fix": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
        "auto_fix": None
    },
    "SEC011": {
        "title": "SQL Injection via f-string",
        "severity": Severity.HIGH,
        "pattern": r'(?i)(execute|query)\s*\(\s*f["\'].*\{.*\}.*["\']',
        "description": "f-strings in SQL queries are vulnerable to injection.",
        "fix": "Use parameterized queries instead of f-strings",
        "auto_fix": None
    },
    "SEC012": {
        "title": "SQL Injection via concatenation",
        "severity": Severity.HIGH,
        "pattern": r'(?i)(SELECT|INSERT|UPDATE|DELETE).*\+\s*\w+\s*\+',
        "description": "String concatenation in SQL enables injection.",
        "fix": "Use parameterized queries",
        "auto_fix": None
    },
    
    # Command Injection
    "SEC020": {
        "title": "Command Injection Risk",
        "severity": Severity.HIGH,
        "pattern": r'(?i)os\.system\s*\([^)]*\+|subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True',
        "description": "Shell commands with user input enable command injection.",
        "fix": "Use subprocess with shell=False and pass arguments as list",
        "auto_fix": None
    },
    "SEC021": {
        "title": "Unsafe eval() Usage",
        "severity": Severity.CRITICAL,
        "pattern": r'\beval\s*\([^)]+\)',
        "description": "eval() executes arbitrary code. Extremely dangerous with user input.",
        "fix": "Use ast.literal_eval() for safe literal parsing, or avoid eval entirely",
        "auto_fix": lambda m: m.replace('eval(', 'ast.literal_eval(')
    },
    "SEC022": {
        "title": "Unsafe exec() Usage",
        "severity": Severity.CRITICAL,
        "pattern": r'\bexec\s*\([^)]+\)',
        "description": "exec() executes arbitrary code. Major security risk.",
        "fix": "Refactor to avoid dynamic code execution",
        "auto_fix": None
    },
    
    # Weak Cryptography
    "SEC030": {
        "title": "Weak Hash Algorithm (MD5)",
        "severity": Severity.MEDIUM,
        "pattern": r'(?i)hashlib\.md5|MD5\.new|md5\(',
        "description": "MD5 is cryptographically broken. Use SHA-256 or better.",
        "fix": "Replace with hashlib.sha256()",
        "auto_fix": lambda m: m.replace('md5', 'sha256').replace('MD5', 'SHA256')
    },
    "SEC031": {
        "title": "Weak Hash Algorithm (SHA1)",
        "severity": Severity.MEDIUM,
        "pattern": r'(?i)hashlib\.sha1|SHA1\.new|sha1\(',
        "description": "SHA-1 is deprecated. Use SHA-256 or better.",
        "fix": "Replace with hashlib.sha256()",
        "auto_fix": lambda m: m.replace('sha1', 'sha256').replace('SHA1', 'SHA256')
    },
    "SEC032": {
        "title": "Insecure Random Generator",
        "severity": Severity.HIGH,
        "pattern": r'\brandom\.(random|randint|choice|randrange)\s*\(',
        "description": "random module is not cryptographically secure.",
        "fix": "Use secrets module for security-sensitive randomness",
        "auto_fix": lambda m: 'secrets.' + m.split('random.')[1] if 'random.' in m else m
    },
    
    # Debug/Development Settings
    "SEC040": {
        "title": "Debug Mode Enabled",
        "severity": Severity.HIGH,
        "pattern": r'(?i)DEBUG\s*=\s*True|debug\s*=\s*True|\.run\([^)]*debug\s*=\s*True',
        "description": "Debug mode exposes sensitive information in production.",
        "fix": "Set DEBUG = os.environ.get('DEBUG', 'False') == 'True'",
        "auto_fix": lambda m: m.replace('True', 'os.environ.get("DEBUG", "False") == "True"')
    },
    "SEC041": {
        "title": "Flask Debug Mode",
        "severity": Severity.HIGH,
        "pattern": r'app\.run\([^)]*debug\s*=\s*True',
        "description": "Flask debug mode enables code execution via debugger.",
        "fix": "Never use debug=True in production",
        "auto_fix": lambda m: m.replace('debug=True', 'debug=os.environ.get("FLASK_DEBUG", "0") == "1"')
    },
    
    # Insecure Deserialization
    "SEC050": {
        "title": "Unsafe Pickle Deserialization",
        "severity": Severity.CRITICAL,
        "pattern": r'pickle\.loads?\s*\(|cPickle\.loads?\s*\(',
        "description": "Pickle can execute arbitrary code during deserialization.",
        "fix": "Use JSON or other safe serialization formats",
        "auto_fix": None
    },
    "SEC051": {
        "title": "Unsafe YAML Loading",
        "severity": Severity.HIGH,
        "pattern": r'yaml\.load\s*\([^)]*\)(?!\s*,\s*Loader)',
        "description": "yaml.load() without Loader can execute arbitrary code.",
        "fix": "Use yaml.safe_load() or specify Loader=yaml.SafeLoader",
        "auto_fix": lambda m: m.replace('yaml.load', 'yaml.safe_load')
    },
    
    # Path Traversal
    "SEC060": {
        "title": "Potential Path Traversal",
        "severity": Severity.HIGH,
        "pattern": r'open\s*\([^)]*\+[^)]*\)|os\.path\.join\s*\([^)]*request\.',
        "description": "User input in file paths enables directory traversal attacks.",
        "fix": "Validate and sanitize file paths, use os.path.basename()",
        "auto_fix": None
    },
    
    # Information Disclosure
    "SEC070": {
        "title": "Stack Trace Exposure",
        "severity": Severity.MEDIUM,
        "pattern": r'traceback\.print_exc\s*\(\)|\.format_exc\s*\(\)',
        "description": "Stack traces can reveal sensitive system information.",
        "fix": "Log errors securely, don't expose to users",
        "auto_fix": None
    },
    
    # CORS/Security Headers
    "SEC080": {
        "title": "Wildcard CORS",
        "severity": Severity.MEDIUM,
        "pattern": r'(?i)access-control-allow-origin.*\*|cors\s*=\s*["\']?\*',
        "description": "Wildcard CORS allows any origin to access resources.",
        "fix": "Specify allowed origins explicitly",
        "auto_fix": None
    },
    
    # Logging Sensitive Data
    "SEC090": {
        "title": "Logging Sensitive Data",
        "severity": Severity.MEDIUM,
        "pattern": r'(?i)(log|print|console)\.[a-z]+\([^)]*password|token|secret|key[^)]*\)',
        "description": "Sensitive data should not be logged.",
        "fix": "Mask or remove sensitive data from logs",
        "auto_fix": None
    },
}


# =============================================================================
# Scanner Engine
# =============================================================================

class SecurityScanner:
    """Scans files for security vulnerabilities."""
    
    SUPPORTED_EXTENSIONS = {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.php', '.rb', '.go'}
    SKIP_DIRS = {'.git', 'node_modules', '__pycache__', 'venv', '.venv', 'env', 'dist', 'build'}
    
    def __init__(self, path: str, fix: bool = False, json_output: bool = False):
        self.path = Path(path)
        self.fix = fix
        self.json_output = json_output
        self.findings: List[Finding] = []
        self.files_scanned = 0
        self.fixes_applied = 0
    
    def scan(self) -> List[Finding]:
        """Scan path for vulnerabilities."""
        if self.path.is_file():
            self._scan_file(self.path)
        else:
            self._scan_directory(self.path)
        return self.findings
    
    def _scan_directory(self, directory: Path) -> None:
        """Recursively scan directory."""
        for item in directory.iterdir():
            if item.name in self.SKIP_DIRS:
                continue
            if item.is_dir():
                self._scan_directory(item)
            elif item.suffix in self.SUPPORTED_EXTENSIONS:
                self._scan_file(item)
    
    def _scan_file(self, file_path: Path) -> None:
        """Scan single file for vulnerabilities."""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            lines = content.split('\n')
            self.files_scanned += 1
            
            modified_lines = list(lines)
            file_modified = False
            
            for line_num, line in enumerate(lines, 1):
                for rule_id, rule in SECURITY_RULES.items():
                    if re.search(rule['pattern'], line):
                        finding = Finding(
                            rule_id=rule_id,
                            severity=rule['severity'],
                            title=rule['title'],
                            description=rule['description'],
                            file_path=str(file_path),
                            line_number=line_num,
                            line_content=line.strip(),
                            fix_suggestion=rule['fix'],
                            auto_fixable=rule.get('auto_fix') is not None
                        )
                        
                        # Apply auto-fix if requested
                        if self.fix and rule.get('auto_fix'):
                            try:
                                fixed = rule['auto_fix'](line)
                                if fixed != line:
                                    finding.fixed_content = fixed.strip()
                                    modified_lines[line_num - 1] = fixed
                                    file_modified = True
                                    self.fixes_applied += 1
                            except Exception:
                                pass
                        
                        self.findings.append(finding)
            
            # Write fixes back to file
            if file_modified and self.fix:
                file_path.write_text('\n'.join(modified_lines), encoding='utf-8')
                
        except Exception as e:
            if not self.json_output:
                print(f"Error scanning {file_path}: {e}")
    
    def get_summary(self) -> Dict:
        """Get scan summary statistics."""
        severity_counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            severity_counts[finding.severity.value] += 1
        
        return {
            "files_scanned": self.files_scanned,
            "total_findings": len(self.findings),
            "by_severity": severity_counts,
            "fixes_applied": self.fixes_applied,
            "scan_time": datetime.now().isoformat()
        }


# =============================================================================
# Output Formatters
# =============================================================================

def print_findings(scanner: SecurityScanner) -> None:
    """Print findings in human-readable format."""
    C = Colors
    
    print(f"\n{C.BOLD}{'='*70}{C.END}")
    print(f"{C.BOLD}SECURITY AUDIT REPORT{C.END}")
    print(f"{'='*70}\n")
    
    summary = scanner.get_summary()
    print(f"Files scanned: {summary['files_scanned']}")
    print(f"Total findings: {summary['total_findings']}")
    
    if summary['total_findings'] == 0:
        print(f"\n{C.GREEN} No security issues found!{C.END}\n")
        return
    
    # Print by severity
    for severity in Severity:
        findings = [f for f in scanner.findings if f.severity == severity]
        if not findings:
            continue
        
        color = {
            Severity.CRITICAL: C.RED,
            Severity.HIGH: C.RED,
            Severity.MEDIUM: C.YELLOW,
            Severity.LOW: C.BLUE,
            Severity.INFO: C.CYAN
        }.get(severity, C.END)
        
        print(f"\n{color}{C.BOLD}[{severity.value}] - {len(findings)} issue(s){C.END}")
        print("-" * 50)
        
        for f in findings:
            print(f"\n  {C.BOLD}{f.rule_id}: {f.title}{C.END}")
            print(f"  File: {f.file_path}:{f.line_number}")
            print(f"  Code: {f.line_content[:60]}{'...' if len(f.line_content) > 60 else ''}")
            print(f"  Issue: {f.description}")
            print(f"  Fix: {f.fix_suggestion}")
            if f.fixed_content:
                print(f"  {C.GREEN} Auto-fixed to: {f.fixed_content[:50]}...{C.END}")
    
    print(f"\n{'='*70}")
    if scanner.fixes_applied > 0:
        print(f"{C.GREEN} Applied {scanner.fixes_applied} automatic fixes{C.END}")
    print()


def output_json(scanner: SecurityScanner) -> None:
    """Output findings as JSON."""
    result = {
        "summary": scanner.get_summary(),
        "findings": [
            {
                **asdict(f),
                "severity": f.severity.value
            }
            for f in scanner.findings
        ]
    }
    print(json.dumps(result, indent=2))


def output_sarif(scanner: SecurityScanner) -> None:
    """Output in SARIF format for GitHub Security tab."""
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "security-auditor",
                    "version": "1.0.0",
                    "rules": [
                        {
                            "id": rule_id,
                            "name": rule["title"],
                            "shortDescription": {"text": rule["title"]},
                            "fullDescription": {"text": rule["description"]},
                            "defaultConfiguration": {
                                "level": "error" if rule["severity"] in [Severity.CRITICAL, Severity.HIGH] else "warning"
                            }
                        }
                        for rule_id, rule in SECURITY_RULES.items()
                    ]
                }
            },
            "results": [
                {
                    "ruleId": f.rule_id,
                    "level": "error" if f.severity in [Severity.CRITICAL, Severity.HIGH] else "warning",
                    "message": {"text": f.description},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file_path},
                            "region": {"startLine": f.line_number}
                        }
                    }]
                }
                for f in scanner.findings
            ]
        }]
    }
    print(json.dumps(sarif, indent=2))


# =============================================================================
# CLI Interface
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Security Auditor - Scan code for vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Scan current directory:
    %(prog)s .
    
  Scan and auto-fix issues:
    %(prog)s . --fix
    
  JSON output for CI/CD:
    %(prog)s src/ --json
    
  SARIF output for GitHub:
    %(prog)s . --sarif > results.sarif
    
  Scan single file:
    %(prog)s app.py

Exit Codes:
  0 - No issues found
  1 - Issues found (or critical issues if --fail-on-critical)
        """
    )
    
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--fix", action="store_true", 
                        help="Automatically fix issues where possible")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--sarif", action="store_true",
                        help="Output in SARIF format (for GitHub Security)")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable colored output")
    parser.add_argument("--fail-on-critical", action="store_true",
                        help="Exit with code 1 only for CRITICAL findings")
    
    args = parser.parse_args()
    
    if args.no_color or args.json or args.sarif:
        Colors.disable()
    
    if not os.path.exists(args.path):
        print(f"Error: Path not found: {args.path}")
        sys.exit(1)
    
    # Run scan
    scanner = SecurityScanner(
        path=args.path,
        fix=args.fix,
        json_output=args.json or args.sarif
    )
    scanner.scan()
    
    # Output results
    if args.sarif:
        output_sarif(scanner)
    elif args.json:
        output_json(scanner)
    else:
        print_findings(scanner)
    
    # Exit code
    if args.fail_on_critical:
        has_critical = any(f.severity == Severity.CRITICAL for f in scanner.findings)
        sys.exit(1 if has_critical else 0)
    else:
        sys.exit(1 if scanner.findings else 0)


if __name__ == "__main__":
    main()
