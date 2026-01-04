import hashlib
import requests
from typing import Dict

def check_password_pwned(password: str) -> Dict:
    """
    Check if password has been exposed in data breaches using HaveIBeenPwned API
    Uses k-anonymity model - only sends first 5 chars of SHA1 hash
    """
    try:
        # Hash password with SHA-1
        sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        # Query HIBP API with hash prefix
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=10)
        
        if response.status_code != 200:
            return {
                "pwned": None,
                "count": 0,
                "error": f"API returned status code {response.status_code}"
            }

        # Check if our hash suffix appears in results
        for line in response.text.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return {
                    "pwned": True,
                    "count": int(count),
                    "message": f"⚠️ This password has been exposed {int(count):,} times in data breaches!",
                    "recommendation": "Choose a different, unique password"
                }

        return {
            "pwned": False,
            "count": 0,
            "message": "✅ Password not found in known data breaches",
            "recommendation": "Password appears safe, but ensure it's unique and strong"
        }
    
    except requests.RequestException as e:
        return {
            "pwned": None,
            "count": 0,
            "error": f"Network error: {str(e)}"
        }
    except Exception as e:
        return {
            "pwned": None,
            "count": 0,
            "error": f"Unexpected error: {str(e)}"
        }