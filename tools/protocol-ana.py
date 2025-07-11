import socket
import argparse
import json
from typing import List, Dict, Optional

# Predefined list of insecure or outdated protocols and their associated risks
INSECURE_PROTOCOLS = {
    "ftp": "FTP - Unencrypted file transfer",
    "telnet": "Telnet - Unencrypted communication",
    "smtp": "SMTP - Open relay or misconfigurations",
    "http": "HTTP - Vulnerable web server",  # HTTP is flagged as insecure
    "snmp": "SNMP - Weak community strings",
    "rdp": "RDP - Weak credentials or misconfigurations",
    "vnc": "VNC - Unencrypted remote access",
    "ssh1": "SSHv1 - Insecure and outdated",
}

def detect_protocol(target: str, port: int) -> Optional[str]:
    """Detect the protocol running on a specific port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((target, port)) == 0:
                try:
                    protocol = socket.getservbyport(port)
                    return protocol
                except:
                    return "Unknown"
    except Exception as e:
        pass
    return None

def scan_protocols(target: str) -> List[Dict]:
    """Scan for supported protocols on a target system."""
    scan_results = []
    common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 5900, 8080, 161]

    for port in common_ports:
        protocol = detect_protocol(target, port)
        if protocol:
            risk = INSECURE_PROTOCOLS.get(protocol.lower(), "No known risks")
            scan_results.append({
                "Port": port,
                "Protocol": protocol,
                "Risk": risk
            })

    return scan_results

if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Protocol Scanner")
    parser.add_argument("target", help="Target IP address or domain name")
    args = parser.parse_args()

    try:
        scan_results = scan_protocols(args.target)
        # Output only JSON
        print(json.dumps(scan_results, indent=4))
    except Exception as e:
        # Output errors in JSON format
        print(json.dumps({"error": f"Unexpected error: {e}"}))