#!/usr/bin/env python3
import re
import sys
import json
import logging
from uuid import uuid4

# Configure logging
logging.basicConfig(
    filename='design_checker.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

INSECURE_PATTERNS = [
    {
        "issue": "Plain Text Password Storage",
        "pattern": r"(password|credential).*(plain\s*text|unencrypted|clear\s*text)",
        "recommendation": "Use secure hashing (bcrypt, Argon2) with salt"
    },
    {
        "issue": "No Rate Limiting",
        "pattern": r"(no|without)\s+rate\s+limiting",
        "recommendation": "Implement rate limiting (e.g., 5 attempts per minute)"
    },
    {
        "issue": "SQL Injection Risk",
        "pattern": r"(sql|query).*(concatenat|directly|string\s*build)",
        "recommendation": "Use parameterized queries/prepared statements"
    },
    {
        "issue": "HTTP Used",
        "pattern": r"http(?!s)\b",
        "recommendation": "Enforce HTTPS everywhere (HSTS header)"
    },
    {
        "issue": "Sensitive Data in URLs",
        "pattern": r"(url|query).*(password|token|secret|id)\b",
        "recommendation": "Move sensitive data to headers/POST body"
    },
    {
        "issue": "Unrestricted File Upload",
        "pattern": r"(upload|file).*(any\s*type|no\s*restriction)",
        "recommendation": "Restrict extensions, scan files, store securely"
    }
]

def analyze_design(spec):
    """Analyze design specification for security issues."""
    findings = []
    for rule in INSECURE_PATTERNS:
        try:
            if re.search(rule["pattern"], spec, re.IGNORECASE):
                findings.append({
                    "issue": rule["issue"],
                    "recommendation": rule["recommendation"],
                    "severity": "High"
                })
        except re.error as e:
            error_id = str(uuid4())
            logging.error(f"Regex error in '{rule['issue']}': {e} (ID: {error_id})")
    return findings

def main():
    if len(sys.argv) < 2:
        print(json.dumps({
            "error": "Usage: python design_checker.py \"<Your design specification text>\""
        }))
        sys.exit(1)

    design_spec = sys.argv[1]
    logging.info(f"Analyzing: {design_spec[:100]}...")

    results = {
        "input_snippet": design_spec[:100],
        "issues": [],
        "status": "success"
    }

    try:
        findings = analyze_design(design_spec)
        results["issues"] = findings
    except Exception as e:
        error_id = str(uuid4())
        logging.critical(f"CRASH: {str(e)} (ID: {error_id})")
        results["status"] = "error"
        results["error_id"] = error_id
        results["error"] = str(e)

    print(json.dumps(results, indent=4))

if __name__ == "__main__":
    main()

