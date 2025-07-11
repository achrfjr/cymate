from scapy.all import ARP, Ether, srp
import argparse
from typing import List, Dict
import json

def scan_subnet(subnet: str) -> List[Dict]:
    """Scan a subnet to detect active devices."""
    try:
        # Create an ARP request packet
        arp = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        # Send the packet and receive the response
        result = srp(packet, timeout=2, verbose=0)[0]

        # Parse the results
        devices = []
        for sent, received in result:
            devices.append({
                "IP": received.psrc,
                "MAC": received.hwsrc,
                "Status": "Active"
            })
        return devices
    except PermissionError:
        return "Error: Permission denied. Please run the script as an administrator."
    except Exception as e:
        return f"Error scanning subnet {subnet}: {e}"

def check_segmentation(devices: List[Dict], vlan_id: str) -> List[Dict]:
    """Check for improper network segmentation (e.g., devices in the wrong VLAN)."""
    results = []
    try:
        for device in devices:
            # Example: Assume VLAN 10 is the correct VLAN for the subnet
            if vlan_id != "10":  # Replace "10" with your correct VLAN ID
                device["Issue"] = f"Device in incorrect VLAN {vlan_id}"
            else:
                device["Issue"] = "None"
            results.append(device)
    except Exception as e:
        return f"Error checking network segmentation: {e}"
    return results

def generate_terminal_report(subnet: str, vlan_id: str, devices: List[Dict]) -> str:
    """Generate a terminal report with the scan results."""
    try:
        report = f"Network Segmentation Report for Subnet {subnet} (VLAN {vlan_id})\n"
        report += "=" * 60 + "\n"
        report += f"{'IP':<15} {'MAC':<20} {'Status':<10} {'Issue':<20}\n"
        report += "-" * 60 + "\n"

        for device in devices:
            report += f"{device['IP']:<15} {device['MAC']:<20} {device['Status']:<10} {device['Issue']:<20}\n"

        report += "=" * 60 + "\n"
        return report
    except Exception as e:
        return f"Error generating terminal report: {e}"

if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Network Segmentation Tool")
    parser.add_argument("subnet", help="Subnet to scan (e.g., 192.168.1.0/24)")
    parser.add_argument("vlan_id", help="VLAN identifier (e.g., 10)")
    args = parser.parse_args()

    try:
        # Scan the subnet for active devices
        devices = scan_subnet(args.subnet)
        if isinstance(devices, list):
            # Check for improper network segmentation
            devices_with_issues = check_segmentation(devices, args.vlan_id)
            if isinstance(devices_with_issues, list):
                # Output as a list of device dicts, each with IP, MAC, Status, Issue
                print(json.dumps(devices_with_issues, indent=4))
            else:
                print(json.dumps({"error": devices_with_issues}))  # Segmentation error
        else:
            print(json.dumps({"error": devices}))  # Scan error
    except Exception as e:
        print(json.dumps({"error": f"Unexpected error: {e}"}))