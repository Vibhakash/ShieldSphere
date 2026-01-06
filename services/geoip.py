import requests
from typing import Dict, Optional
import os

def get_country(ip: str) -> str:
    """
    Get country code from IP address
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
    """
    
    # Try multiple services for best accuracy
    location = None
    
    # 1. Try IPGeolocation.io first (MOST ACCURATE - city-level precision)
    location = _try_ipgeolocation_io(ip)
    if location and location.get("city") != "Unknown":
        return location
    
    # 2. Try IP-API.com (free, good accuracy)
    location = _try_ip_api(ip)
    if location and location.get("city") != "Unknown":
        return location
    
    # 3. Try IPStack (good for mobile IPs)
    location = _try_ipstack(ip)
    if location and location.get("city") != "Unknown":
        return location
    
    # 4. Fallback to IPInfo.io
    location = _try_ipinfo(ip)
    if location and location.get("city") != "Unknown":
        return location
    
    # 5. Last resort - return error
    return {
        "error": "All geolocation services failed",
        "ip": ip,
        "city": "Unknown",
        "region": "Unknown",
        "country": "Unknown"
    }


def _try_ipgeolocation_io(ip: str) -> Optional[Dict]:
    """
    IPGeolocation.io - MOST ACCURATE (city-level precision)
    FREE: 1,000 requests/day
    SIGN UP: https://ipgeolocation.io/signup.html
    """
    api_key = os.getenv("IPGEOLOCATION_API_KEY")
    if not api_key:
        return None
    
    try:
        url = f"https://api.ipgeolocation.io/ipgeo?apiKey={api_key}&ip={ip}&fields=city,state_prov,country_code2,country_name,latitude,longitude,zipcode,time_zone,isp,organization"
        response = requests.get(url, timeout=5)
        
        if response.status_code != 200:
            return None
        
        data = response.json()
        
        return {
            "ip": ip,
            "city": data.get("city", "Unknown"),
            "region": data.get("state_prov", "Unknown"),
            "country": data.get("country_code2", "Unknown"),
            "country_name": data.get("country_name", "Unknown"),
            "latitude": float(data.get("latitude", 0)),
            "longitude": float(data.get("longitude", 0)),
            "postal": data.get("zipcode", "Unknown"),
            "timezone": data.get("time_zone", {}).get("name", "Unknown") if isinstance(data.get("time_zone"), dict) else data.get("time_zone", "Unknown"),
            "org": data.get("organization", "Unknown"),
            "hostname": data.get("isp", "Unknown"),
            "location_string": f"{data.get('city', 'Unknown')}, {data.get('state_prov', 'Unknown')}, {data.get('country_code2', 'Unknown')}",
            "accuracy": "very-high",
            "source": "ipgeolocation.io"
        }
    except Exception as e:
        print(f"IPGeolocation.io error: {e}")
        return None


def _try_ip_api(ip: str) -> Optional[Dict]:
    """
    IP-API.com - Good accuracy, completely free
    FREE: 45 requests/minute (no key needed)
    """
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        response = requests.get(url, timeout=5)
        
        if response.status_code != 200:
            return None
        
        data = response.json()
        
        if data.get("status") != "success":
            return None
        
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
            "hostname": data.get("isp", "Unknown"),
            "location_string": f"{data.get('city', 'Unknown')}, {data.get('regionName', 'Unknown')}, {data.get('countryCode', 'Unknown')}",
            "accuracy": "high",
            "source": "ip-api.com"
        }
    except Exception as e:
        print(f"IP-API error: {e}")
        return None


def _try_ipstack(ip: str) -> Optional[Dict]:
    """
    IPStack - Good for mobile IPs
    FREE: 100 requests/month
    SIGN UP: https://ipstack.com/signup/free
    """
    api_key = os.getenv("IPSTACK_API_KEY")
    if not api_key:
        return None
    
    try:
        url = f"http://api.ipstack.com/{ip}?access_key={api_key}&fields=city,region_name,country_code,country_name,latitude,longitude,zip,time_zone,connection"
        response = requests.get(url, timeout=5)
        
        if response.status_code != 200:
            return None
        
        data = response.json()
        
        if data.get("success") == False:
            return None
        
        return {
            "ip": ip,
            "city": data.get("city", "Unknown"),
            "region": data.get("region_name", "Unknown"),
            "country": data.get("country_code", "Unknown"),
            "country_name": data.get("country_name", "Unknown"),
            "latitude": float(data.get("latitude", 0)),
            "longitude": float(data.get("longitude", 0)),
            "postal": data.get("zip", "Unknown"),
            "timezone": data.get("time_zone", {}).get("id", "Unknown") if isinstance(data.get("time_zone"), dict) else "Unknown",
            "org": data.get("connection", {}).get("isp", "Unknown") if isinstance(data.get("connection"), dict) else "Unknown",
            "hostname": data.get("connection", {}).get("isp", "Unknown") if isinstance(data.get("connection"), dict) else "Unknown",
            "location_string": f"{data.get('city', 'Unknown')}, {data.get('region_name', 'Unknown')}, {data.get('country_code', 'Unknown')}",
            "accuracy": "high",
            "source": "ipstack.com"
        }
    except Exception as e:
        print(f"IPStack error: {e}")
        return None


def _try_ipinfo(ip: str) -> Optional[Dict]:
    """
    IPInfo.io - Original service (fallback)
    FREE: 50,000 requests/month
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
        "US": "United States", "GB": "United Kingdom", "IN": "India",
        "CA": "Canada", "AU": "Australia", "DE": "Germany",
        "FR": "France", "JP": "Japan", "CN": "China",
        "BR": "Brazil", "RU": "Russia", "MX": "Mexico",
        "ES": "Spain", "IT": "Italy", "NL": "Netherlands",
        "SG": "Singapore", "KR": "South Korea", "SE": "Sweden",
        "NO": "Norway", "DK": "Denmark", "FI": "Finland",
        "BE": "Belgium", "CH": "Switzerland", "AT": "Austria",
        "PL": "Poland", "TR": "Turkey", "SA": "Saudi Arabia",
        "AE": "United Arab Emirates", "ZA": "South Africa",
        "AR": "Argentina", "CL": "Chile"
    }
    return countries.get(country_code, country_code)


def is_ip_from_suspicious_location(ip: str, allowed_countries: Optional[list] = None) -> Dict:
    """Check if IP is from a suspicious or unexpected location"""
    details = get_ip_details(ip)
    
    if "error" in details:
        return {"suspicious": None, "error": details["error"]}
    
    country = details.get("country", "Unknown")
    
    if allowed_countries and country != "Unknown":
        is_allowed = country in allowed_countries
        return {
            "suspicious": not is_allowed,
            "country": country,
            "message": f"IP from {country}" + (" (not in allowed list)" if not is_allowed else " (allowed)"),
            "details": details
        }
    
    high_risk_countries = ["CN", "RU", "KP"]
    
    return {
        "suspicious": country in high_risk_countries,
        "country": country,
        "message": f"IP from {details.get('country_name', country)}",
        "details": details
    }


def get_multiple_ip_details(ips: list) -> Dict[str, Dict]:
    """Get details for multiple IPs efficiently"""
    results = {}
    for ip in ips:
        if ip and ip != "Unknown":
            results[ip] = get_ip_details(ip)
    return results