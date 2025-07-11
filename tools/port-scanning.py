import socket
from typing import Tuple
from socket import getservbyport
import logging
import sys
import json

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def scan_port(target: str, port: int, protocol: str) -> Tuple[int, str, str]:
    """Scan a single port and return its status and name."""
    try:
        sock_type = socket.SOCK_STREAM if protocol == "TCP" else socket.SOCK_DGRAM
        with socket.socket(socket.AF_INET, sock_type) as s:
            s.settimeout(1)
            if protocol == "TCP":
                result = s.connect_ex((target, port))
                if result == 0:
                    service_name = getservbyport(port, "tcp") if port < 65536 else "Unknown"
                    return port, "Open", service_name
            elif protocol == "UDP":
                s.sendto(b"", (target, port))
                try:
                    data, _ = s.recvfrom(1024)
                    if data:
                        service_name = getservbyport(port, "udp") if port < 65536 else "Unknown"
                        return port, "Open", service_name
                except socket.timeout:
                    return port, "Closed", "Unknown"
            return port, "Closed", "Unknown"
    except Exception as e:
        logging.error(f"Error scanning port {port} ({protocol}): {e}")
        return port, f"Error: {e}", "Unknown"

def port_scanner(target: str, start_port: int, end_port: int) -> dict:
    """Scan a range of ports and return results as a JSON-compatible dict."""
    try:
        ip = socket.gethostbyname(target)
        open_ports_list = []
        total_open_tcp_ports = 0
        total_open_udp_ports = 0

        for protocol in ["TCP", "UDP"]:
            for port in range(start_port, end_port + 1):
                port_status = scan_port(target, port, protocol)
                if port_status[1] == "Open":
                    open_ports_list.append({
                        "Port": port_status[0],
                        "Protocol": protocol,
                        "Service": port_status[2],
                        "Status": port_status[1]
                    })
                    if protocol == "TCP":
                        total_open_tcp_ports += 1
                    else:
                        total_open_udp_ports += 1
                logging.info(f"Scanned {protocol} port {port}: {port_status[1]}")

        return {
            "target": target,
            "total open tcp ports": total_open_tcp_ports,
            "total open udp ports": total_open_udp_ports,
            "open ports": open_ports_list
        }

    except socket.gaierror:
        return {"error": "Unable to resolve target address."}
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return {"error": f"Scan failed: {str(e)}"}

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(json.dumps({"error": "Usage: port_scanner.py <target> <port-range> (e.g., port_scanner.py example.com 20-80)"}))
        sys.exit(1)
    
    target = sys.argv[1]
    port_range = sys.argv[2]
    
    try:
        # Parse port range (expecting format like "20-80")
        start_port, end_port = map(int, port_range.split('-'))
        
        # Validate ports
        if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port):
            print(json.dumps({"error": "Ports must be between 1 and 65535, and start_port must be <= end_port."}))
            sys.exit(1)
            
        # Run scanner and print results as JSON
        result = port_scanner(target, start_port, end_port)
        print(json.dumps(result, indent=4))
        
    except ValueError:
        print(json.dumps({"error": "Invalid port range format. Expected format: start-end (e.g., 20-80)"}))
        sys.exit(1)
