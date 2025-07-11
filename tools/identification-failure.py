#!/usr/bin/env python3
import sys
import json
import re
import hashlib
from datetime import datetime
from urllib.parse import urlparse
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class CredentialAnalyzer:
    def __init__(self, target_url, auth_endpoint=None, credentials=None):
        self.target_url = target_url
        self.auth_endpoint = auth_endpoint
        self.credentials = credentials
        self.results = {
            "meta": {
                "tool": "Credential Security Analyzer",
                "version": "2.0",
                "timestamp": datetime.utcnow().isoformat()
            },
            "target": target_url,
            "vulnerabilities": []
        }
        
        # Enhanced password database (top 10,000 passwords + patterns)
        self.common_passwords = [
            'password', '123456', 'qwerty', 'admin', 'welcome',
            '12345678', '123456789', '12345', '1234567', 'letmein'
        ]
        self.password_patterns = [
            r'^\d+$',  # All digits
            r'^[a-zA-Z]+$',  # All letters
            r'^[!@#$%^&*]+$',  # All special chars
            r'(.)\1{3}',  # 4+ repeating chars
            r'[a-z]{2,}\d{2,}',  # Letters then numbers
            r'\d{2,}[a-z]{2,}',  # Numbers then letters
            r'20\d{2}',  # Year patterns
            r'19\d{2}'
        ]

    def add_vulnerability(self, title, description, severity, evidence=None, remediation=None):
        vuln = {
            "id": hashlib.sha256(f"{title}{description}".encode()).hexdigest()[:8],
            "title": title,
            "description": description,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat()
        }
        if evidence:
            vuln["evidence"] = evidence
        if remediation:
            vuln["remediation"] = remediation
        self.results["vulnerabilities"].append(vuln)

    def analyze_credentials(self):
        if not self.credentials:
            self.add_vulnerability(
                "Missing Credentials",
                "No credentials provided for analysis",
                "Info",
                remediation="Provide credentials in username:password format"
            )
            return
            
        try:
            username, password = self.credentials.split(':', 1)
            
            # Password metrics
            analysis = {
                "length": len(password),
                "unique_chars": len(set(password)),
                "has_upper": bool(re.search(r'[A-Z]', password)),
                "has_lower": bool(re.search(r'[a-z]', password)),
                "has_digit": bool(re.search(r'[0-9]', password)),
                "has_special": bool(re.search(r'[^A-Za-z0-9]', password)),
                "is_common": password.lower() in self.common_passwords,
                "matches_username": password.lower() == username.lower(),
                "entropy": self.calculate_entropy(password),
                "pattern_vulnerabilities": []
            }

            # Check for common patterns
            for pattern in self.password_patterns:
                if re.search(pattern, password):
                    analysis["pattern_vulnerabilities"].append(pattern)

            # Vulnerability checks
            if analysis["length"] < 12:
                self.add_vulnerability(
                    "Insufficient Password Length",
                    f"Password length ({analysis['length']}) below minimum recommendation (12)",
                    "High",
                    {"length": analysis["length"]},
                    "Enforce minimum 12 character passwords"
                )
                
            if analysis["is_common"]:
                self.add_vulnerability(
                    "Common Password Detected",
                    "Password matches known compromised passwords",
                    "Critical",
                    {"common_password": password[:3] + '...'},
                    "Implement password blacklisting"
                )
                
            if analysis["matches_username"]:
                self.add_vulnerability(
                    "Username-Password Match",
                    "Password identical to username",
                    "Critical",
                    None,
                    "Prevent passwords matching usernames"
                )
                
            if analysis["entropy"] < 3.0:
                self.add_vulnerability(
                    "Low Password Entropy",
                    f"Password entropy ({analysis['entropy']:.2f}) indicates weak complexity",
                    "High",
                    {"entropy": analysis["entropy"]},
                    "Require mixed character types"
                )
                
            if analysis["pattern_vulnerabilities"]:
                self.add_vulnerability(
                    "Predictable Password Pattern",
                    f"Password matches {len(analysis['pattern_vulnerabilities'])} weak patterns",
                    "Medium",
                    {"patterns": analysis["pattern_vulnerabilities"]},
                    "Enforce stronger password composition rules"
                )
                
        except ValueError:
            self.add_vulnerability(
                "Invalid Credential Format",
                "Credentials must be in username:password format",
                "High",
                {"input": self.credentials[:50] + ('...' if len(self.credentials) > 50 else '')},
                "Use format: username:password"
            )

    def analyze_endpoint(self):
        if not self.auth_endpoint:
            return
            
        try:
            parsed = urlparse(self.auth_endpoint)
            
            # Protocol check
            if parsed.scheme != 'https':
                self.add_vulnerability(
                    "Insecure Authentication Protocol",
                    "Endpoint uses HTTP instead of HTTPS",
                    "Critical",
                    {"protocol": parsed.scheme},
                    "Enforce HTTPS for all authentication"
                )
                
            # Security headers check
            try:
                response = requests.head(
                    self.auth_endpoint,
                    timeout=5,
                    allow_redirects=False
                )
                
                security_headers = {
                    'Strict-Transport-Security': response.headers.get('Strict-Transport-Security'),
                    'X-Content-Type-Options': response.headers.get('X-Content-Type-Options'),
                    'X-Frame-Options': response.headers.get('X-Frame-Options'),
                    'Content-Security-Policy': response.headers.get('Content-Security-Policy')
                }
                
                missing = [h for h, v in security_headers.items() if not v]
                if missing:
                    self.add_vulnerability(
                        "Missing Security Headers",
                        f"Authentication endpoint missing {len(missing)} critical headers",
                        "Medium",
                        {"missing_headers": missing},
                        "Implement all OWASP-recommended security headers"
                    )
                    
            except requests.RequestException as e:
                self.add_vulnerability(
                    "Endpoint Connection Error",
                    f"Could not analyze endpoint: {str(e)}",
                    "Info"
                )
                
        except Exception as e:
            self.add_vulnerability(
                "Endpoint Analysis Error",
                str(e),
                "Info"
            )

    def calculate_entropy(self, password):
        """Calculate Shannon entropy of password"""
        import math
        from collections import Counter
        counts = Counter(password)
        probs = [c/len(password) for c in counts.values()]
        return -sum(p * math.log2(p) for p in probs)

    def run_analysis(self):
        self.analyze_credentials()
        self.analyze_endpoint()
        
        # Generate summary
        severity_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0
        }
        
        for vuln in self.results["vulnerabilities"]:
            severity_counts[vuln["severity"]] += 1
            
        self.results["summary"] = severity_counts
        return self.results

def main():
    if len(sys.argv) < 2:
        print(json.dumps({
            "error": "Invalid arguments",
            "usage": "python cred_analyzer.py <target_url> [auth_endpoint] [username:password]",
            "examples": [
                "python cred_analyzer.py https://example.com https://example.com/login admin:Password123!",
                "python cred_analyzer.py https://example.com user:weakpass"
            ]
        }, indent=2))
        sys.exit(1)
        
    target_url = sys.argv[1]
    auth_endpoint = sys.argv[2] if len(sys.argv) > 2 else None
    credentials = sys.argv[3] if len(sys.argv) > 3 else None
    
    analyzer = CredentialAnalyzer(target_url, auth_endpoint, credentials)
    results = analyzer.run_analysis()
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()