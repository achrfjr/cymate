#!/usr/bin/env python3
import json
import sys
import os
import re
from datetime import datetime
from typing import Dict, List, Any, Optional
import stat
import hashlib

class LoggingFailureAnalyzer:
    """Advanced analyzer for insufficient logging in a single log file."""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.results: Dict[str, Any] = {
            "meta": {
                "analyzer": "LoggingFailures",
                "version": "1.2.0",
                "timestamp": datetime.utcnow().isoformat(),
                "file_analyzed": file_path,
                "file_size": os.path.getsize(file_path) if os.path.exists(file_path) else 0,
            },
            "findings": [],
            "summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "total_findings": 0
            }
        }
        
    def analyze(self) -> Dict[str, Any]:
        """Run all checks on the specified log file."""
        if not os.path.exists(self.file_path):
            self._add_finding("FileNotFound", f"Log file not found: {self.file_path}", "high")
            return self.results

        try:
            self._check_permissions()
            self._check_sensitive_data()
            self._check_integrity()
            self._check_retention()
            self._check_verbosity()
            self._generate_summary()
        except Exception as e:
            self._add_finding("AnalysisError", f"Analysis failed: {str(e)}", "high")
        
        return self.results
    
    def _add_finding(self, id: str, description: str, severity: str, details: Optional[Dict] = None) -> None:
        """Add a finding to the results."""
        finding = {
            "id": id,
            "description": description,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat(),
            "details": details or {}
        }
        self.results["findings"].append(finding)
        self.results["summary"][severity] += 1
    
    def _generate_summary(self) -> None:
        """Update total findings count."""
        self.results["summary"]["total_findings"] = len(self.results["findings"])
    
    def _check_permissions(self) -> None:
        """Check if log file permissions are insecure."""
        st = os.stat(self.file_path)
        mode = st.st_mode
        issues = []

        if mode & stat.S_IROTH:
            issues.append("World-readable (others can read)")
        if mode & stat.S_IWOTH:
            issues.append("World-writable (others can modify)")
        if st.st_uid == 0 and not self.file_path.startswith('/var/log/'):
            issues.append("Owned by root outside system log dir")

        if issues:
            self._add_finding(
                "InsecurePermissions",
                "File has insecure permissions",
                "high",
                {"issues": issues, "mode": oct(mode)}
            )
    
    def _check_sensitive_data(self) -> None:
        """Check for passwords, tokens, etc. in logs."""
        # Map pattern to type
        sensitive_patterns = [
            (r'password[=:]\s*\S+', "password"),
            (r'api[-_]?key[=:]\s*\S+', "api key"),
            (r'secret[=:]\s*\S+', "secret"),
            (r'\b\d{3}[- ]?\d{2}[- ]?\d{4}\b', "ssn")
        ]
        found_types = set()

        with open(self.file_path, 'r', errors='ignore') as f:
            for line in f:
                for pattern, ptype in sensitive_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        found_types.add(ptype)
                        break  # Avoid duplicate matches per line

        if found_types:
            self._add_finding(
                "SensitiveDataExposed",
                "Sensitive data detected in logs",
                "critical",
                {"types": list(found_types)}
            )
    
    def _check_integrity(self) -> None:
        """Check if logs are tamper-proof."""
        try:
            # Check if file is append-only (a typical secure setting)
            st = os.stat(self.file_path)
            if not st.st_mode & stat.S_IAPPEND:
                self._add_finding(
                    "NoAppendOnlyFlag",
                    "File is not append-only (can be truncated/modified)",
                    "medium"
                )
        except Exception as e:
            self._add_finding("IntegrityCheckError", str(e), "medium")

def main():
    if len(sys.argv) != 2:
        print(json.dumps({
            "error": "Usage: python logging_failures.py <file_path>",
            "example": "python logging_failures.py /var/log/auth.log"
        }, indent=2))
        sys.exit(1)
    
    analyzer = LoggingFailureAnalyzer(sys.argv[1])
    results = analyzer.analyze()
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()