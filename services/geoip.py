import requests
from typing import Dict, Optional

def get_country(ip: str) -> str:
    """
    Get country code from IP address
    Simple version that returns just country code
    """
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if response.status_code == 200:
            return response.json().get("country", "Unknown")
        return "Unknown"
    except:
        return "Unknown"


def get_ip_details(ip: str) -> Dict:
    """
    Get detailed geolocation information for an IP address
    Returns comprehensive data including city, region, coordinates, etc.
    """
    try:
        # Using ipinfo.io (free tier: 50k requests/month)
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        
        if response.status_code != 200:
            return {
                "error": f"API returned status {response.status_code}",
                "ip": ip
            }
        
        data = response.json()
        
        # Parse location data
        loc = data.get("loc", "0,0").split(",")
        latitude = float(loc[0]) if len(loc) > 0 else 0
        longitude = float(loc[1]) if len(loc) > 1 else 0
        
        return {
            "ip": ip,
            "city": data.get("city", "Unknown"),
            "region": data.get("region", "Unknown"),
            "country": data.get("country", "Unknown"),
            "country_name": get_country_name(data.get("country", "")),
            "latitude": latitude,
            "longitude": longitude,
            "postal": data.get("postal", "Unknown"),
            "timezone": data.get("timezone", "Unknown"),
            "org": data.get("org", "Unknown"),
            "hostname": data.get("hostname", "Unknown"),
            "location_string": f"{data.get('city', 'Unknown')}, {data.get('region', 'Unknown')}, {data.get('country', 'Unknown')}"
        }
    
    except requests.RequestException as e:
        return {
            "error": f"Network error: {str(e)}",
            "ip": ip
        }
    except Exception as e:
        return {
            "error": f"Unexpected error: {str(e)}",
            "ip": ip
        }


def get_country_name(country_code: str) -> str:
    """Convert country code to full country name"""
    countries = {
        "US": "United States",
        "GB": "United Kingdom",
        "IN": "India",
        "CA": "Canada",
        "AU": "Australia",
        "DE": "Germany",
        "FR": "France",
        "JP": "Japan",
        "CN": "China",
        "BR": "Brazil",
        "RU": "Russia",
        "MX": "Mexico",
        "ES": "Spain",
        "IT": "Italy",
        "NL": "Netherlands",
        "SG": "Singapore",
        "KR": "South Korea",
        # Add more as needed
    }
    return countries.get(country_code, country_code)


def is_ip_from_suspicious_location(ip: str, allowed_countries: Optional[list] = None) -> Dict:
    """
    Check if IP is from a suspicious or unexpected location
    """
    details = get_ip_details(ip)
    
    if "error" in details:
        return {"suspicious": None, "error": details["error"]}
    
    country = details.get("country", "Unknown")
    
    # If allowed countries specified, check against them
    if allowed_countries and country != "Unknown":
        is_allowed = country in allowed_countries
        return {
            "suspicious": not is_allowed,
            "country": country,
            "message": f"IP from {country}" + (" (not in allowed list)" if not is_allowed else " (allowed)"),
            "details": details
        }
    
    # Default suspicious countries (known for high abuse rates)
    high_risk_countries = ["CN", "RU", "KP"]  # Add more based on your risk profile
    
    return {
        "suspicious": country in high_risk_countries,
        "country": country,
        "message": f"IP from {details.get('country_name', country)}",
        "details": details
    }