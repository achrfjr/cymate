import dns.resolver
import dns.rdatatype
import argparse
import json
from typing import List, Dict

# Predefined list of common DNS record types to check
DNS_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]

def query_dns_records(domain: str, record_type: str) -> List[str]:
    """Query DNS records for a given domain and record type."""
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(r) for r in answers]
    except dns.resolver.NoAnswer:
        return []  # No records found
    except dns.resolver.NXDOMAIN:
        raise ValueError(f"The domain {domain} does not exist.")
    except dns.resolver.Timeout:
        raise TimeoutError(f"DNS query for {record_type} records timed out for {domain}.")
    except dns.resolver.NoNameservers:
        raise ConnectionError(f"No nameservers found for {domain}.")
    except Exception as e:
        raise RuntimeError(f"Unexpected error querying {record_type} records for {domain}: {e}")

def analyze_dns(domain: str) -> List[Dict]:
    """Analyze DNS records for a domain and identify subdomains or misconfigurations."""
    results = []

    # Query common DNS record types
    for record_type in DNS_RECORD_TYPES:
        records = query_dns_records(domain, record_type)
        if records:
            for record in records:
                results.append({
                    "Domain": domain,
                    "Record Type": record_type,
                    "Record Value": record,
                    "Issue": "None"
                })

    # Check for common DNS misconfigurations
    # Example: Missing SPF or DMARC records
    try:
        spf_records = query_dns_records(domain, "TXT")
        has_spf = any("v=spf1" in record for record in spf_records)
        if not has_spf:
            results.append({
                "Domain": domain,
                "Record Type": "SPF",
                "Record Value": "Missing",
                "Issue": "No SPF record found"
            })
    except Exception as e:
        print(f"Error checking SPF records for {domain}: {e}")

    try:
        dmarc_records = query_dns_records(f"_dmarc.{domain}", "TXT")
        has_dmarc = any("v=DMARC1" in record for record in dmarc_records)
        if not has_dmarc:
            results.append({
                "Domain": domain,
                "Record Type": "DMARC",
                "Record Value": "Missing",
                "Issue": "No DMARC record found"
            })
    except Exception as e:
        print(f"Error checking DMARC records for {domain}: {e}")

    return results

if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(description="DNS Analysis Tool")
    parser.add_argument("domain", help="Domain name to analyze (e.g., example.com)")
    args = parser.parse_args()

    if args.domain:
        try:
            dns_results = analyze_dns(args.domain)
            # Output results in JSON format
            print(json.dumps(dns_results, indent=4))
        except ValueError as ve:
            print(json.dumps({"error": str(ve)}))
        except TimeoutError as te:
            print(json.dumps({"error": str(te)}))
        except ConnectionError as ce:
            print(json.dumps({"error": str(ce)}))
        except Exception as e:
            # Output other errors in JSON format
            print(json.dumps({"error": f"Unexpected error: {e}"}))
    else:
        print(json.dumps({"error": "Domain name cannot be empty."}))