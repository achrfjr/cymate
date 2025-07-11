#!/usr/bin/env python3
import requests
import argparse
import os
import json
from packaging import version

def fetch_cve_data(package_name, package_version):
    """Check for CVEs related to a package using OSV API. Only return 'id', 'summary', and 'details'."""
    url = "https://api.osv.dev/v1/query"
    payload = {
        "version": package_version,
        "package": {
            "name": package_name,
            "ecosystem": "PyPI"
        }
    }
    
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulns", [])
            # Only keep 'id', 'summary', and 'details' fields
            filtered = []
            for v in vulns:
                filtered.append({
                    "id": v.get("id"),
                    "summary": v.get("summary"),
                    "details": v.get("details")
                })
            return filtered
        else:
            return []
    except Exception as e:
        return [{"id": "fetch_error", "details": str(e)}]

def scan_requirements(file_path="requirements.txt"):
    """Scan a requirements file for vulnerable packages."""
    results = {
        "file_scanned": file_path,
        "vulnerable_packages": [],
        "status": "success",
        "errors": []
    }

    if not os.path.exists(file_path):
        results["status"] = "error"
        results["errors"].append(f"File '{file_path}' not found in {os.getcwd()}")
        return results

    try:
        with open(file_path, "r") as file:
            for line in file:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Extract package name and version
                if "==" in line:
                    package_name, package_version = line.split("==")
                elif "@" in line:
                    continue  # Ignore VCS-style installs
                else:
                    package_name = line.split(">")[0].split("<")[0].split("~")[0].strip()
                    package_version = "latest"

                vulns = fetch_cve_data(package_name, package_version)
                if vulns:
                    results["vulnerable_packages"].append({
                        "package": package_name,
                        "version": package_version,
                        "vulnerabilities": vulns
                    })
    except Exception as e:
        results["status"] = "error"
        results["errors"].append(str(e))

    return results

def main():
    parser = argparse.ArgumentParser(description="Vulnerable Dependency Scanner (JSON Output)")
    parser.add_argument("--file", default="requirements.txt", 
                        help="Path to requirements file (default: requirements.txt)")
    args = parser.parse_args()

    result = scan_requirements(args.file)
    print(json.dumps(result, indent=4))

if __name__ == "__main__":
    main()

