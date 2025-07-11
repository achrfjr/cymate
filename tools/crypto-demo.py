import hashlib
import sys
from cryptography.fernet import Fernet, InvalidToken
import base64
import re
import json
from typing import Optional, Dict

class CryptoDemoError(Exception):
    """Base exception for cryptographic demo failures"""
    pass

def insecure_hash(password: str) -> Dict:
    """Demonstrate insecure password hashing and return results in JSON format"""
    result = {
        "type": "password",
        "input": password,
        "md5": None,
        "sha1": None,
        "warnings": [],
        "status": "failed"
    }
    try:
        if not password:
            raise ValueError("Empty password provided")
        if len(password) < 4:
            result["warnings"].append("Very short password (minimum 4 characters recommended)")

        md5_hash = hashlib.md5(password.encode()).hexdigest()
        sha1_hash = hashlib.sha1(password.encode()).hexdigest()

        result.update({
            "md5": md5_hash,
            "sha1": sha1_hash,
            "warnings": [
                *result["warnings"],
                "Using MD5/SHA1 for passwords is insecure!"
            ],
            "status": "success"
        })
    except Exception as e:
        result["error"] = str(e)
    return result

def weak_encrypt(message: str) -> Dict:
    """Demonstrate weak encryption and return results in JSON format"""
    result = {
        "type": "message",
        "input": message,
        "encrypted": None,
        "warnings": [],
        "status": "failed"
    }
    try:
        if not message:
            raise ValueError("Empty message provided")
        if len(message) > 1000:
            raise ValueError("Message too long (max 1000 characters)")

        key = base64.urlsafe_b64encode(b"insecure_key_1234567890123456")
        cipher = Fernet(key)
        encrypted = cipher.encrypt(message.encode())

        result.update({
            "encrypted": encrypted.decode(),
            "warnings": ["Hard-coded keys are insecure!"],
            "status": "success"
        })
    except Exception as e:
        result["error"] = str(e)
    return result

def check_url(url: str) -> Dict:
    """Check URL security and return results in JSON format"""
    result = {
        "type": "url",
        "input": url,
        "valid": False,
        "secure": False,
        "warnings": [],
        "status": "failed"
    }
    try:
        if not url:
            raise ValueError("Empty URL provided")

        if not re.match(r"^https?://.+", url, re.IGNORECASE):
            raise ValueError("Invalid URL format (must start with http:// or https://)")

        result["valid"] = True
        if url.startswith("http://"):
            result["warnings"].append("Using insecure HTTP URL – data may be intercepted")
        else:
            result["secure"] = True
        result["status"] = "success"
    except Exception as e:
        result["error"] = str(e)
    return result

def detect_input_type(input_text: str) -> Optional[str]:
    """Detect if the input is a password, message, or URL"""
    if not input_text:
        return None
    if any(x in input_text.lower() for x in ('http://', 'https://', '.com', '.org', '.net')):
        return "url"
    elif ' ' in input_text:
        return "message"
    return "password"

def main() -> None:
    try:
        if len(sys.argv) < 2:
            print(json.dumps({
                "status": "error",
                "error": "Usage: python script.py [input]",
                "examples": [
                    "python script.py password123",
                    "python script.py 'credit card 1234'",
                    "python script.py http://example.com"
                ]
            }, indent=4))
            sys.exit(1)

        input_text = ' '.join(sys.argv[1:]).strip()
        if not input_text:
            raise CryptoDemoError("Empty input provided")

        input_type = detect_input_type(input_text)
        if not input_type:
            raise CryptoDemoError("Could not determine input type")

        if input_type == "password":
            output = insecure_hash(input_text)
        elif input_type == "message":
            output = weak_encrypt(input_text)
        elif input_type == "url":
            output = check_url(input_text)
        else:
            raise CryptoDemoError("Unhandled input type")

        print(json.dumps(output, indent=4))
        if output.get("status") != "success":
            sys.exit(1)

    except CryptoDemoError as cde:
        print(json.dumps({"status": "error", "error": str(cde)}, indent=4))
        sys.exit(1)
    except Exception as e:
        print(json.dumps({"status": "error", "error": str(e)}, indent=4))
        sys.exit(1)

if __name__ == "__main__":
    main()

