import os
import hashlib
import re
import sys
import json

class FileScanner:
    def __init__(self):
        # Sample malicious patterns for file scanning
        self.malicious_patterns = [
            r'eval\s*\(',  # Common in malicious JavaScript
            r'exec\s*\(',  # Potential code execution
            r'cmd\.exe',   # Windows command shell
            r'powershell', # PowerShell commands
        ]

    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file with error handling"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except FileNotFoundError:
            return "Error: File not found"
        except PermissionError:
            return "Error: Permission denied to access file"
        except IOError as e:
            return f"Error: IO issue while reading file - {str(e)}"
        except Exception as e:
            return f"Error: Unexpected error calculating hash - {str(e)}"

    def scan_file(self, file_path):
        """Scan a file for potential malware patterns with enhanced error handling"""
        result = {
            "file": file_path,
            "hash": "Not calculated",
            "is_suspicious": False,
            "details": []
        }

        try:
            if not os.path.exists(file_path):
                result["details"].append("Error: File not found")
                return result

            result["hash"] = self.calculate_file_hash(file_path)
            if "Error" in result["hash"]:
                result["details"].append(result["hash"])
                return result

            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
                
                # Check for malicious patterns
                for pattern in self.malicious_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        result["is_suspicious"] = True
                        result["details"].append(f"Found suspicious pattern: {pattern}")

                # Check file size
                file_size = os.path.getsize(file_path)
                if file_size > 100 * 1024 * 1024:  # 100MB
                    result["is_suspicious"] = True
                    result["details"].append("File size exceeds 100MB")

        except PermissionError:
            result["details"].append("Error: Permission denied to read file")
        except UnicodeDecodeError:
            result["details"].append("Error: Unable to decode file content (binary file?)")
        except Exception as e:
            result["details"].append(f"Error: Unexpected error scanning file - {str(e)}")

        return result

def main():
    scanner = FileScanner()
    
    # Check for command-line argument
    if len(sys.argv) != 2:
        error = {
            "error": "Usage: python file_scanner.py <file_path>",
            "example": "python file_scanner.py /path/to/file.txt"
        }
        print(json.dumps(error, indent=2))
        sys.exit(1)
    
    file_path = sys.argv[1].strip()
    
    if not file_path:
        error = {"error": "File path cannot be empty"}
        print(json.dumps(error, indent=2))
        sys.exit(1)
    
    try:
        result = scanner.scan_file(file_path)
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