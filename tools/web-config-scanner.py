#!/usr/bin/env python3
import requests
import sys
import json
from urllib.parse import urlparse, urljoin
from requests.packages.urllib3.exceptions import InsecureRequestWarning

class SecurityMisconfigScanner:
    def __init__(self, url, username='admin', password='admin', timeout=10, verify_ssl=False):
        if not url.startswith(('http://', 'https://')):
            url = f'http://{url}'
        
        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValueError("Invalid URL format - missing hostname")
        
        self.url = url
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.username = username
        self.password = password
        self.timeout = timeout
        self.verify_ssl = verify_ssl

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecurityConfigScanner/1.0',
            'Accept': 'text/html,application/xhtml+xml'
        })

        if not verify_ssl:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            self.session.verify = False

        self.results = {
            "target": self.base_url,
            "issues": [],
            "status": "success"
        }

    def _safe_request(self, url, method='GET', data=None):
        try:
            if method.upper() == 'GET':
                return self.session.get(url, timeout=self.timeout, allow_redirects=True)
            else:
                return self.session.post(url, data=data, timeout=self.timeout, allow_redirects=True)
        except Exception as e:
            return None

    def check_default_configurations(self):
        cred_combinations = [
            ('admin', 'admin'),
            ('admin', 'password'),
            (self.username, self.password)
        ]

        endpoints = [
            '/admin/login',
            '/wp-login.php',
            '/administrator/index.php',
            '/user/login'
        ]

        for endpoint in endpoints:
            login_url = urljoin(self.base_url, endpoint)
            res = self._safe_request(login_url)
            if res and res.status_code == 200:
                self.results["issues"].append({
                    "type": "Login Page Found",
                    "url": login_url,
                    "status_code": res.status_code
                })
                for uname, pwd in cred_combinations:
                    login_attempt = self._safe_request(login_url, 'POST', {'username': uname, 'password': pwd, 'login': 'submit'})
                    if login_attempt and any(x in login_attempt.text.lower() for x in ['logout', 'welcome']):
                        self.results["issues"].append({
                            "type": "Default Credentials Working",
                            "url": login_url,
                            "credentials": f"{uname}/{pwd}"
                        })

    def check_improper_configurations(self):
        res = self._safe_request(self.base_url)
        if res:
            if 'debug' in res.text.lower() or 'x-debug' in res.headers:
                self.results["issues"].append({
                    "type": "Debug Mode Detected",
                    "url": self.base_url
                })

        for directory in ['/images/', '/uploads/', '/backup/']:
            dir_url = urljoin(self.base_url, directory)
            dir_res = self._safe_request(dir_url)
            if dir_res and 'index of' in dir_res.text.lower():
                self.results["issues"].append({
                    "type": "Directory Listing Enabled",
                    "url": dir_url
                })

    def scan(self):
        try:
            self.check_default_configurations()
            self.check_improper_configurations()
        except Exception as e:
            self.results["status"] = "error"
            self.results["error"] = str(e)
        finally:
            print(json.dumps(self.results, indent=4))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python scanner.py <url> [username] [password] [--verify-ssl]"}))
        sys.exit(1)

    url = sys.argv[1]
    username = 'admin'
    password = 'admin'
    verify_ssl = False

    for arg in sys.argv[2:]:
        if arg == '--verify-ssl':
            verify_ssl = True
        elif username == 'admin':
            username = arg
        else:
            password = arg

    try:
        scanner = SecurityMisconfigScanner(url, username, password, verify_ssl=verify_ssl)
        scanner.scan()
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

