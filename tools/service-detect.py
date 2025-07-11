import socket
from typing import Dict, List, Optional
import nmap
import argparse
from sys import exit
import json

# Predefined list of problematic services and their associated risks
PROBLEMATIC_SERVICES = {
    "ftp": "FTP - Unencrypted file transfer",
    "telnet": "Telnet - Unencrypted communication",
    "http": "HTTP - Vulnerable web server",
    "smtp": "SMTP - Open relay or misconfigurations",
    "rdp": "RDP - Weak credentials or misconfigurations",
    "vnc": "VNC - Unencrypted remote access",
}

def scan_port(target: str, port: int) -> Optional[str]:
    """Scan a single port and return the service name if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((target, port)) == 0:
                try:
                    service_name = socket.getservbyport(port)
                    return service_name
                except:
                    return "Unknown"
    except Exception as e:
        print(f"Error scanning port {port}: {e}")
    return None

def scan_services(target: str, enable_version_detection: bool = False) -> List[Dict]:
    """Scan for open ports and services, optionally detecting service versions."""
    scan_results = []
    common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 5900, 8080]

    if enable_version_detection:
        # Use nmap for version detection
        try:
            nm = nmap.PortScanner()
            nm.scan(target, arguments="-sV")  # -sV for version detection
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        service = nm[host][proto][port]
                        risk = PROBLEMATIC_SERVICES.get(service["name"].lower(), "No known risks")
                        scan_results.append({
                            "Port": port,
                            "Service": service["name"],
                            "Version": service["version"],
                            "State": service["state"],
                            "Risk": risk
                        })
        except Exception as e:
            print(json.dumps({"error": f"Error during version detection: {e}"}))
    else:
        # Use basic socket scanning
        for port in common_ports:
            service = scan_port(target, port)
            if service:
                risk = PROBLEMATIC_SERVICES.get(service.lower(), "No known risks")
                scan_results.append({
                    "Port": port,
                    "Service": service,
                    # "Version": "Not detected",
                    "State": "Open",
                    "Risk": risk
                })

    return scan_results

if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Service and Version Scanner")
    parser.add_argument("target", help="Target IP address or domain name")
    parser.add_argument(
        "--version-detection", 
        action="store_true",
        help="Enable service version detection (uses nmap)"
    )
    args = parser.parse_args()

    try:
        scan_results = scan_services(args.target, args.version_detection)
        print(json.dumps(scan_results, indent=4))
    except Exception as e:
        print(json.dumps({"error": f"Unexpected error: {e}"}))
        exit(1)