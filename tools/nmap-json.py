#!/usr/bin/env python3
"""
Nmap Scanner with JSON Export
-----------------------------
Runs Nmap service detection and outputs results in both human-readable
and JSON formats. Designed for automation pipelines.

Usage:
    python nmap-json.py <target>
    python nmap-json.py <target> --json-only
    python nmap-json.py <target> -o output.json

Author: K.S. Akshay
"""

import subprocess
import sys
import xml.etree.ElementTree as ET
import os
import json
import argparse
from datetime import datetime
from typing import Dict, List, Optional


def log(message: str, level: str = "INFO") -> None:
    """Print timestamped log message."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    symbols = {"INFO": "+", "WARN": "!", "ERROR": "-", "SUCCESS": "*"}
    symbol = symbols.get(level, "+")
    print(f"[{timestamp}] [{symbol}] {message}")


def sanitize_filename(target: str) -> str:
    """Sanitize target string for safe filename usage."""
    dangerous_chars = ["/", "\\", ":", "*", "?", '"', "<", ">", "|"]
    result = target
    for char in dangerous_chars:
        result = result.replace(char, "_")
    return result


def run_nmap_scan(target: str, output_file: str) -> bool:
    """Execute Nmap scan with service detection."""
    log(f"Starting Nmap scan on {target}")
    
    try:
        result = subprocess.run(
            ["nmap", "-sV", "-O", "--osscan-guess", "-oX", output_file, target],
            check=True,
            capture_output=True,
            text=True
        )
        log(f"Scan complete. XML saved to {output_file}", "SUCCESS")
        return True
    except subprocess.CalledProcessError as e:
        log(f"Nmap scan failed: {e}", "ERROR")
        if e.stderr:
            log(f"stderr: {e.stderr.strip()}", "ERROR")
        return False
    except FileNotFoundError:
        log("Nmap not found. Please install: apt install nmap", "ERROR")
        return False


def parse_nmap_xml(xml_file: str) -> Optional[Dict]:
    """Parse Nmap XML output into structured dictionary."""
    if not os.path.exists(xml_file):
        log(f"XML file not found: {xml_file}", "ERROR")
        return None
    
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError as e:
        log(f"Failed to parse XML: {e}", "ERROR")
        return None
    
    # Extract scan metadata
    scan_info = {
        "scanner": root.attrib.get("scanner", "nmap"),
        "args": root.attrib.get("args", ""),
        "start_time": root.attrib.get("startstr", ""),
        "version": root.attrib.get("version", "")
    }
    
    hosts = []
    
    for host in root.findall("host"):
        host_data = {"addresses": [], "hostnames": [], "ports": [], "os": []}
        
        # Get addresses
        for addr in host.findall("address"):
            host_data["addresses"].append({
                "addr": addr.attrib.get("addr", ""),
                "type": addr.attrib.get("addrtype", "")
            })
        
        # Get hostnames
        hostnames = host.find("hostnames")
        if hostnames is not None:
            for hostname in hostnames.findall("hostname"):
                host_data["hostnames"].append({
                    "name": hostname.attrib.get("name", ""),
                    "type": hostname.attrib.get("type", "")
                })
        
        # Get ports
        ports = host.find("ports")
        if ports is not None:
            for port in ports.findall("port"):
                state_elem = port.find("state")
                service_elem = port.find("service")
                
                port_data = {
                    "port": port.attrib.get("portid", ""),
                    "protocol": port.attrib.get("protocol", "tcp"),
                    "state": state_elem.attrib.get("state", "") if state_elem is not None else "",
                    "service": {
                        "name": service_elem.attrib.get("name", "unknown") if service_elem is not None else "unknown",
                        "product": service_elem.attrib.get("product", "") if service_elem is not None else "",
                        "version": service_elem.attrib.get("version", "") if service_elem is not None else ""
                    }
                }
                host_data["ports"].append(port_data)
        
        # Get OS detection
        os_elem = host.find("os")
        if os_elem is not None:
            for osmatch in os_elem.findall("osmatch"):
                host_data["os"].append({
                    "name": osmatch.attrib.get("name", ""),
                    "accuracy": osmatch.attrib.get("accuracy", "0")
                })
        
        hosts.append(host_data)
    
    return {
        "scan_info": scan_info,
        "hosts": hosts,
        "generated_at": datetime.now().isoformat()
    }


def print_summary(scan_data: Dict) -> None:
    """Print human-readable scan summary."""
    print("\n" + "=" * 60)
    print("SCAN SUMMARY")
    print("=" * 60)
    
    for i, host in enumerate(scan_data["hosts"]):
        ip = next((a["addr"] for a in host["addresses"] if a["type"] == "ipv4"), "Unknown")
        print(f"\nHost: {ip}")
        
        # Print hostnames
        if host["hostnames"]:
            names = ", ".join(h["name"] for h in host["hostnames"])
            print(f"  Hostnames: {names}")
        
        # Print OS
        if host["os"]:
            best_os = max(host["os"], key=lambda x: int(x["accuracy"]))
            print(f"  OS Guess: {best_os['name']} ({best_os['accuracy']}% confidence)")
        
        # Print open ports
        open_ports = [p for p in host["ports"] if p["state"] == "open"]
        if open_ports:
            print(f"\n  Open Ports ({len(open_ports)}):")
            print(f"  {'PORT':<10} {'SERVICE':<15} {'VERSION'}")
            print(f"  {'-'*10} {'-'*15} {'-'*20}")
            for port in open_ports:
                svc = port["service"]
                version = f"{svc['product']} {svc['version']}".strip() or "-"
                print(f"  {port['port']}/{port['protocol']:<6} {svc['name']:<15} {version}")
        else:
            print("  No open ports found")
    
    print("\n" + "=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Nmap scanner with JSON export",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.1
  %(prog)s scanme.nmap.org --json-only
  %(prog)s 10.0.0.0/24 -o network_scan.json
        """
    )
    parser.add_argument("target", help="Target IP, hostname, or CIDR range")
    parser.add_argument("--json-only", action="store_true", help="Output only JSON, no summary")
    parser.add_argument("-o", "--output", help="JSON output file path")
    parser.add_argument("--keep-xml", action="store_true", help="Keep intermediate XML file")
    
    args = parser.parse_args()
    
    # Setup filenames
    safe_target = sanitize_filename(args.target)
    xml_file = f"nmap-{safe_target}.xml"
    json_file = args.output or f"nmap-{safe_target}.json"
    
    # Run scan
    if not run_nmap_scan(args.target, xml_file):
        sys.exit(1)
    
    # Parse results
    scan_data = parse_nmap_xml(xml_file)
    if scan_data is None:
        sys.exit(1)
    
    # Output JSON
    with open(json_file, "w") as f:
        json.dump(scan_data, f, indent=2)
    log(f"JSON results saved to {json_file}", "SUCCESS")
    
    # Print summary unless json-only
    if not args.json_only:
        print_summary(scan_data)
    else:
        print(json.dumps(scan_data, indent=2))
    
    # Cleanup XML if not keeping
    if not args.keep_xml and os.path.exists(xml_file):
        os.remove(xml_file)
        log(f"Cleaned up {xml_file}")
    
    # Exit with appropriate code
    total_open = sum(len([p for p in h["ports"] if p["state"] == "open"]) for h in scan_data["hosts"])
    log(f"Scan complete. Found {total_open} open ports across {len(scan_data['hosts'])} hosts", "SUCCESS")
    sys.exit(0)


if __name__ == "__main__":
    main()
