import re
import requests
import urllib.parse
import sys
import json
from requests.exceptions import RequestException, Timeout, ConnectionError

class URLScanner:
    def __init__(self):
        # Suspicious URL keywords for heuristic analysis
        self.suspicious_keywords = [
            'login', 'signin', 'bank', 'password', 
            'update', 'verify', 'account', 'free', 'download'
        ]

    def scan_url(self, url):
        """Check if a URL is potentially malicious with enhanced error handling"""
        result = {
            "url": url,
            "is_suspicious": False,
            "details": []
        }

        # Basic URL structure validation
        if not url.startswith(('http://', 'https://')):
            result["is_suspicious"] = True
            result["details"].append("Invalid URL scheme")
            return result

        # Parse URL for heuristic analysis
        try:
            parsed_url = urllib.parse.urlparse(url.lower())
            path = parsed_url.path
            query = parsed_url.query
            domain = parsed_url.netloc
        except ValueError:
            result["details"].append("Error: Invalid URL format")
            return result

        # Check for suspicious keywords
        for keyword in self.suspicious_keywords:
            if keyword in path or keyword in query:
                result["is_suspicious"] = True
                result["details"].append(f"Suspicious keyword found in URL: {keyword}")

        # Check for encoded characters
        if re.search(r'%[0-9A-Fa-f]{2}', url):
            result["is_suspicious"] = True
            result["details"].append("URL contains encoded characters, possible obfuscation")

        # Check domain for suspicious patterns
        if domain.count('-') > 3 or sum(c.isdigit() for c in domain) > 5:
            result["is_suspicious"] = True
            result["details"].append("Suspicious domain name (too many hyphens or numbers)")

        try:
            # Attempt to fetch URL headers with specific exception handling
            response = requests.head(url, timeout=5, allow_redirects=True)
            
            # Check for suspicious redirects
            if len(response.history) > 3:
                result["is_suspicious"] = True
                result["details"].append("Excessive redirects detected")

            # Check content-type
            content_type = response.headers.get('content-type', '').lower()
            if any(t in content_type for t in ['executable', 'application/octet-stream']):
                result["is_suspicious"] = True
                result["details"].append("Suspicious content type detected")

            # Check for missing security headers
            if 'strict-transport-security' not in response.headers and url.startswith('https://'):
                result["details"].append("Missing HSTS header (less secure)")
            
        except Timeout:
            result["details"].append("Error: Request timed out")
        except ConnectionError:
            result["details"].append("Error: Connection failed (check network or URL)")
        except RequestException as e:
            result["details"].append(f"Error: Request failed - {str(e)}")
        except Exception as e:
            result["details"].append(f"Error: Unexpected error checking URL - {str(e)}")

        if not result["details"]:
            result["details"].append("No suspicious patterns detected")

        return result

def main():
    scanner = URLScanner()
    
    # Check for command-line argument
    if len(sys.argv) != 2:
        error = {
            "error": "Usage: python url_scanner.py <url>",
            "example": "python url_scanner.py https://example.com"
        }
        print(json.dumps(error, indent=2))
        sys.exit(1)
    
    url = sys.argv[1].strip()
    
    if not url:
        error = {"error": "URL cannot be empty"}
        print(json.dumps(error, indent=2))
        sys.exit(1)
    
    try:
        result = scanner.scan_url(url)
        print(json.dumps(result, indent=2))
    except KeyboardInterrupt:
        error = {"error": "Scan interrupted by user"}
        print(json.dumps(error, indent=2))
    except Exception as e:
        error = {"error": f"Unexpected error in main process - {str(e)}"}
        print(json.dumps(error, indent=2))
        sys.exit(1)

if __name__ == "__main__":
    main()