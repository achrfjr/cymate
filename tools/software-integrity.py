import json
import hashlib
import os
import sys
from pathlib import Path
import warnings
from datetime import datetime
import yaml  # pyyaml package needed

warnings.filterwarnings('ignore')  # Disable SSL warnings for demo purposes

class SoftwareIntegrityAnalyzer:
    def __init__(self, target_path):
        self.target_path = Path(target_path)
        self.results = {
            "analysis_timestamp": datetime.utcnow().isoformat(),
            "target_path": str(self.target_path),
            "integrity_checks": {}
        }

    def analyze(self):
        """Run all integrity checks on a single file"""
        if not self.target_path.is_file():
            self.results['error'] = f"Provided path is not a file: {self.target_path}"
            return self.results
        self._check_file_integrity()
        self._check_sensitive_data()
        self._check_dependencies()
        self._check_build_process()
        return self.results

    def _check_file_integrity(self):
        checks = {}
        file_path = self.target_path
        checks['file_exists'] = file_path.exists()
        checks['file_size'] = file_path.stat().st_size if file_path.exists() else 0
        checks['file_name'] = file_path.name
        # Optionally, compute hash
        if file_path.exists():
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                    checks['sha256'] = hashlib.sha256(data).hexdigest()
            except Exception as e:
                checks['hash_error'] = str(e)
        self.results['integrity_checks']['file_integrity'] = checks

    def _check_sensitive_data(self):
        checks = {}
        file_path = self.target_path
        sensitive_keywords = ['password', 'secret', 'api_key', 'token']
        found_keywords = []
        if file_path.exists():
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read()
                    for keyword in sensitive_keywords:
                        if keyword in content:
                            found_keywords.append(keyword)
            except Exception as e:
                checks['read_error'] = str(e)
        checks['found_sensitive_keywords'] = found_keywords
        self.results['integrity_checks']['sensitive_data'] = checks

    def _check_dependencies(self):
        checks = {}
        file_path = self.target_path
        # Check for pinned dependencies if it's a requirements.txt or package.json
        integrity_issues = []
        if file_path.name == 'requirements.txt':
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                    if '==' not in content:
                        integrity_issues.append('requirements.txt: Unpinned dependencies detected')
            except Exception as e:
                checks['requirements_read_error'] = str(e)
        if file_path.name == 'package.json':
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                    if not any(char.isdigit() for char in content):
                        integrity_issues.append('package.json: Unpinned dependencies detected')
            except Exception as e:
                checks['packagejson_read_error'] = str(e)
        checks['dependency_integrity_issues'] = integrity_issues
        self.results['integrity_checks']['dependencies'] = checks

    def _check_build_process(self):
        checks = {}
        file_path = self.target_path
        # Check for verification steps in build files
        integrity_issues = []
        if file_path.name in ['Makefile', 'build.sh', 'Dockerfile', 'Jenkinsfile']:
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read()
                    if 'verify' not in content.lower() and 'check' not in content.lower():
                        integrity_issues.append(f"{file_path.name}: Missing verification steps in build process")
            except Exception as e:
                checks['buildfile_read_error'] = str(e)
        checks['build_integrity_issues'] = integrity_issues
        self.results['integrity_checks']['build_process'] = checks

def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: python software_integrity.py <file_to_analyze>"}, indent=2))
        sys.exit(1)
    target_path = sys.argv[1]
    if not os.path.exists(target_path):
        print(json.dumps({"error": f"Path does not exist: {target_path}"}, indent=2))
        sys.exit(1)
    analyzer = SoftwareIntegrityAnalyzer(target_path)
    results = analyzer.analyze()
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()