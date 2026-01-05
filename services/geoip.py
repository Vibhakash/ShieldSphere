import requests
from typing import Dict, Optional
import os

def get_country(ip: str) -> str:
    """
    Get country code from IP address
    Simple version that returns just country code
    BACKWARD COMPATIBLE - keeps existing behavior
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
    ENHANCED - Now tries multiple APIs for better accuracy
    BACKWARD COMPATIBLE - returns same structure as before
    """
    
    # Try multiple services for best accuracy
    location = None
    
    # 1. Try IP-API.com first (free, no key needed, good accuracy)
    location = _try_ip_api(ip)
    if location and location.get("city") != "Unknown":
        return location
    
    # 2. Try IPGeolocation.io if API key available
    location = _try_ipgeolocation_io(ip)
    if location and location.get("city") != "Unknown":
        return location
    
    # 3. Fallback to IPInfo.io (existing service)
    location = _try_ipinfo(ip)
    if location and location.get("city") != "Unknown":
        return location
    
    # 4. Last resort - return error
    return {
        "error": "All geolocation services failed",
        "ip": ip,
        "city": "Unknown",
        "region": "Unknown",
        "country": "Unknown"
    }


def _try_ip_api(ip: str) -> Optional[Dict]:
    """
    IP-API.com - Good accuracy, completely free
    No API key needed! 45 requests/minute
    """
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as"
        response = requests.get(url, timeout=5)
        
        if response.status_code != 200:
            return None
        
        data = response.json()
        
        if data.get("status") != "success":
            return None
        
        # Return in same structure as original get_ip_details
        return {
            "ip": ip,
            "city": data.get("city", "Unknown"),
            "region": data.get("regionName", "Unknown"),
            "country": data.get("countryCode", "Unknown"),
            "country_name": data.get("country", "Unknown"),
            "latitude": float(data.get("lat", 0)),
            "longitude": float(data.get("lon", 0)),
            "postal": data.get("zip", "Unknown"),
            "timezone": data.get("timezone", "Unknown"),
            "org": data.get("org", "Unknown"),
            "hostname": data.get("as", "Unknown"),
            "location_string": f"{data.get('city', 'Unknown')}, {data.get('regionName', 'Unknown')}, {data.get('countryCode', 'Unknown')}",
            "accuracy": "high",
            "source": "ip-api.com"
        }
    except Exception as e:
        print(f"IP-API error: {e}")
        return None


def _try_ipgeolocation_io(ip: str) -> Optional[Dict]:
    """
    IPGeolocation.io - Most accurate (city-level)
    Requires API key: https://ipgeolocation.io/
    Free: 1,000 requests/day
    """
    api_key = os.getenv("IPGEOLOCATION_API_KEY")
    if not api_key:
        return None
    
    try:
        url = f"https://api.ipgeolocation.io/ipgeo?apiKey={api_key}&ip={ip}"
        response = requests.get(url, timeout=5)
        
        if response.status_code != 200:
            return None
        
        data = response.json()
        
        # Return in same structure as original get_ip_details
        return {
            "ip": ip,
            "city": data.get("city", "Unknown"),
            "region": data.get("state_prov", "Unknown"),
            "country": data.get("country_code2", "Unknown"),
            "country_name": data.get("country_name", "Unknown"),
            "latitude": float(data.get("latitude", 0)),
            "longitude": float(data.get("longitude", 0)),
            "postal": data.get("zipcode", "Unknown"),
            "timezone": data.get("time_zone", {}).get("name", "Unknown"),
            "org": data.get("organization", "Unknown"),
            "hostname": data.get("isp", "Unknown"),
            "location_string": f"{data.get('city', 'Unknown')}, {data.get('state_prov', 'Unknown')}, {data.get('country_code2', 'Unknown')}",
            "accuracy": "very-high",
            "source": "ipgeolocation.io"
        }
    except Exception as e:
        print(f"IPGeolocation.io error: {e}")
        return None


def _try_ipinfo(ip: str) -> Optional[Dict]:
    """
    IPInfo.io - Your original service (fallback)
    Free: 50,000 requests/month
    """
    try:
        token = os.getenv("IPINFO_TOKEN")
        url = f"https://ipinfo.io/{ip}/json"
        
        if token:
            url += f"?token={token}"
        
        response = requests.get(url, timeout=10)
        
        if response.status_code != 200:
            return None
        
        data = response.json()
        
        # Parse location data
        loc = data.get("loc", "0,0").split(",")
        latitude = float(loc[0]) if len(loc) > 0 else 0
        longitude = float(loc[1]) if len(loc) > 1 else 0
        
        # Return in same structure as original
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
            "location_string": f"{data.get('city', 'Unknown')}, {data.get('region', 'Unknown')}, {data.get('country', 'Unknown')}",
            "accuracy": "medium",
            "source": "ipinfo.io"
        }
    except Exception as e:
        print(f"IPInfo error: {e}")
        return None


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
        "SE": "Sweden",
        "NO": "Norway",
        "DK": "Denmark",
        "FI": "Finland",
        "BE": "Belgium",
        "CH": "Switzerland",
        "AT": "Austria",
        "PL": "Poland",
        "TR": "Turkey",
        "SA": "Saudi Arabia",
        "AE": "United Arab Emirates",
        "ZA": "South Africa",
        "AR": "Argentina",
        "CL": "Chile"
    }
    return countries.get(country_code, country_code)


def is_ip_from_suspicious_location(ip: str, allowed_countries: Optional[list] = None) -> Dict:
    """
    Check if IP is from a suspicious or unexpected location
    UNCHANGED - keeps existing behavior
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


# NEW FUNCTION - Additional utility
def get_detailed_location_with_fallback(ip: str) -> Dict:
    """
    Get most detailed location possible with multiple fallbacks
    Includes accuracy rating and data source
    """
    location = get_ip_details(ip)
    
    # Add helpful metadata
    if "error" not in location:
        location["coordinates"] = {
            "lat": location.get("latitude", 0),
            "lng": location.get("longitude", 0)
        }
        location["full_address"] = location.get("location_string", "Unknown")
        
    return location


# NEW FUNCTION - Bulk IP lookup
def get_multiple_ip_details(ips: list) -> Dict[str, Dict]:
    """
    Get details for multiple IPs efficiently
    Useful for batch processing login history
    """
    results = {}
    
    for ip in ips:
        if ip and ip != "Unknown":
            results[ip] = get_ip_details(ip)
    
    return results