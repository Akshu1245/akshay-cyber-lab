#!/usr/bin/env python3
import subprocess
import sys
import xml.etree.ElementTree as ET
import os

if len(sys.argv) != 2:
    print("Usage: ./nmap-json.py <target>")
    sys.exit(1)

target = sys.argv[1]
# sanitize filename for common characters
safe_target = target.replace("/", "_").replace(":", "_")
output_file = f"nmap-{safe_target}.xml"

print(f"[+] Scanning {target} with Nmap...")
try:
    subprocess.run(["nmap", "-sV", "-oX", output_file, target], check=True)
except subprocess.CalledProcessError as e:
    print(f"[-] Nmap failed: {e}")
    sys.exit(1)

if not os.path.exists(output_file):
    print(f"[-] Expected output file not found: {output_file}")
    sys.exit(1)

print(f"[+] Scan complete. Output saved to {output_file}")

# parse xml and print open ports summary
try:
    tree = ET.parse(output_file)
    root = tree.getroot()
except ET.ParseError as e:
    print(f"[-] Failed to parse XML: {e}")
    sys.exit(0)

print("\n[+] Open Ports:")
for host in root.findall("host"):
    ports = host.find("ports")
    if ports is None:
        continue
    for port in ports.findall("port"):
        state = port.find("state").attrib.get("state", "")
        if state == "open":
            portid = port.attrib.get("portid", "unknown")
            service = port.find("service").attrib.get("name", "unknown") if port.find("service") is not None else "unknown"
            print(f"Port {portid}/tcp - {service}")

