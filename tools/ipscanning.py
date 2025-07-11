import socket
import ipaddress
import sys
import json
from typing import List, Dict

def check_host(ip: str, port: int = 80, timeout: float = 1) -> bool:
    """Check if a host is live by attempting to connect to a specific port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                return True
    except Exception:
        pass
    return False

def scan_network(cidr: str) -> List[Dict]:
    """Scan a network range (CIDR format) for live hosts."""
    live_hosts = []
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return {"error": "Invalid CIDR format."}
    for ip in network.hosts():
        ip_str = str(ip)
        if check_host(ip_str):
            live_hosts.append({"IP": ip_str, "Status": "Live"})
    return live_hosts

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: python ipscanning.py <CIDR_RANGE>"}))
        sys.exit(1)

    cidr = sys.argv[1].strip()
    try:
        live_hosts = scan_network(cidr)
        if isinstance(live_hosts, dict) and "error" in live_hosts:
            print(json.dumps(live_hosts))
        else:
            # Flatten the list of live hosts into a dict with keys as IPs and values as status
            hosts_dict = {host["IP"]: host["Status"] for host in live_hosts}
            print(json.dumps({"network": cidr, "live hosts": hosts_dict}, indent=4))
    except Exception as e:
        print(json.dumps({"error": f"Unexpected error: {e}"}))