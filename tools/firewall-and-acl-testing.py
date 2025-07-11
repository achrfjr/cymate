import socket
import argparse
import json
from typing import List, Dict

def test_port(target: str, port: int, protocol: str) -> Dict:
    """Test if a port is open or blocked."""
    try:
        if protocol.lower() == "tcp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                return {"Port": port, "Protocol": protocol, "Status": "Open", "Issue": "None"}
            else:
                return {"Port": port, "Protocol": protocol, "Status": "Blocked", "Issue": "Port blocked by firewall"}
        elif protocol.lower() == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            try:
                sock.sendto(b"", (target, port))
                sock.recvfrom(1024)
                return {"Port": port, "Protocol": protocol, "Status": "Open", "Issue": "None"}
            except socket.timeout:
                return {"Port": port, "Protocol": protocol, "Status": "Blocked", "Issue": "Port blocked by firewall"}
            finally:
                sock.close()
        else:
            return {"Port": port, "Protocol": protocol, "Status": "Unknown", "Issue": "Invalid protocol"}
    except socket.gaierror:
        return {"Port": port, "Protocol": protocol, "Status": "Error", "Issue": "Invalid target address"}
    except socket.error as e:
        return {"Port": port, "Protocol": protocol, "Status": "Error", "Issue": f"Socket error: {e}"}
    except Exception as e:
        return {"Port": port, "Protocol": protocol, "Status": "Error", "Issue": f"Unexpected error: {e}"}

def test_ports(target: str, ports: List[int], protocol: str) -> List[Dict]:
    """Test multiple ports on a target."""
    results = []
    for port in ports:
        result = test_port(target, port, protocol)
        results.append(result)
    return results

def print_results(target: str, protocol: str, port_results: List[Dict]):
    """Convert the port test results to JSON format with individual keys and values."""
    results = []
    for result in port_results:
        results.append({
            "Target": target,
            "Protocol": protocol.upper(),
            "Port": result["Port"],
            "Status": result["Status"],
            "Issue": result["Issue"]
        })
    return results

if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Firewall and ACL Testing Tool")
    parser.add_argument("target", help="Target IP address or domain name")
    parser.add_argument("protocol", choices=["tcp", "udp"], help="Protocol to test (TCP/UDP)")
    parser.add_argument("ports", help="Comma-separated list of ports (e.g., 80,443,22)")
    args = parser.parse_args()

    try:
        # Parse the ports input
        ports = [int(port.strip()) for port in args.ports.split(",")]

        # Test the ports
        port_results = test_ports(args.target, ports, args.protocol)
        if port_results:
            # Output results in JSON format
            print(json.dumps(print_results(args.target, args.protocol, port_results), indent=4))
        else:
            print(json.dumps({"error": "No ports were tested."}))
    except ValueError:
        print(json.dumps({"error": "Invalid port list. Please enter comma-separated port numbers."}))
    except Exception as e:
        print(json.dumps({"error": f"Unexpected error: {e}"}))