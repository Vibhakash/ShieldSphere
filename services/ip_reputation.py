import requests
import os
from typing import Dict
import ipaddress

def check_ip(ip: str) -> Dict:
    """
    Check IP reputation using AbuseIPDB API
    Returns abuse confidence score and country information
    """
    
    # Validate IP address format
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return {
            "error": "Invalid IP address format",
            "is_malicious": None,
            "ip": ip
        }
    
    # Check for private/local IPs
    if ip_obj.is_private or ip_obj.is_loopback:
        return {
            "ip": ip,
            "is_malicious": False,
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "country": "Local/Private",
            "threat_level": "✅ Private/Local IP",
            "message": "This is a private or local IP address",
            "is_private": True
        }
    
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    
    if not api_key:
        return {
            "error": "AbuseIPDB API key not configured",
            "is_malicious": None
        }
    
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": ""
        }

        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        if response.status_code == 429:
            return {
                "error": "Rate limit exceeded. Free tier allows 1000 checks per day.",
                "is_malicious": None,
                "ip": ip
            }
        
        if response.status_code != 200:
            return {
                "error": f"API returned status {response.status_code}",
                "is_malicious": None,
                "ip": ip
            }
        
        data = response.json().get("data", {})
        
        # Parse results
        abuse_score = data.get("abuseConfidenceScore", 0)
        is_whitelisted = data.get("isWhitelisted", False)
        total_reports = data.get("totalReports", 0)
        num_distinct_users = data.get("numDistinctUsers", 0)
        last_reported = data.get("lastReportedAt", None)
        country = data.get("countryCode", "Unknown")
        usage_type = data.get("usageType", "Unknown")
        isp = data.get("isp", "Unknown")
        domain = data.get("domain", "Unknown")
        is_tor = data.get("isTor", False)
        
        # Determine threat level with more nuance
        if is_whitelisted:
            threat_level = "✅ Whitelisted"
            is_malicious = False
        elif is_tor:
            threat_level = "⚠️ Tor Exit Node"
            is_malicious = True
        elif abuse_score >= 75:
            threat_level = "🚨 High Risk"
            is_malicious = True
        elif abuse_score >= 50:
            threat_level = "⚠️ Moderate Risk"
            is_malicious = True
        elif abuse_score >= 25:
            threat_level = "⚠️ Suspicious"
            is_malicious = True
        elif total_reports > 0:
            threat_level = "⚠️ Some Reports"
            is_malicious = False
        else:
            threat_level = "✅ Clean"
            is_malicious = False
        
        # Build recommendation
        if abuse_score >= 75:
            recommendation = "BLOCK this IP immediately - high abuse confidence"
        elif abuse_score >= 50:
            recommendation = "Strongly consider blocking this IP"
        elif abuse_score >= 25:
            recommendation = "Monitor activity from this IP closely"
        elif total_reports > 0:
            recommendation = "IP has some reports but low abuse score - monitor"
        else:
            recommendation = "IP appears clean with no abuse reports"
        
        return {
            "ip": ip,
            "is_malicious": is_malicious,
            "abuse_confidence_score": abuse_score,
            "total_reports": total_reports,
            "num_distinct_users": num_distinct_users,
            "last_reported": last_reported,
            "country": country,
            "country_name": get_country_name(country),
            "isp": isp,
            "domain": domain,
            "usage_type": usage_type,
            "is_whitelisted": is_whitelisted,
            "is_tor": is_tor,
            "threat_level": threat_level,
            "message": f"IP has {abuse_score}% abuse confidence score with {total_reports} reports from {num_distinct_users} users",
            "recommendation": recommendation,
            "details": f"{isp} ({usage_type})" if usage_type != "Unknown" else isp
        }
    
    except requests.RequestException as e:
        return {
            "error": f"Network error: {str(e)}",
            "is_malicious": None,
            "ip": ip
        }
    except Exception as e:
        return {
            "error": f"Unexpected error: {str(e)}",
            "is_malicious": None,
            "ip": ip
        }


def get_country_name(country_code: str) -> str:
    """Convert country code to full country name"""
    countries = {
        "US": "United States", "GB": "United Kingdom", "IN": "India",
        "CA": "Canada", "AU": "Australia", "DE": "Germany",
        "FR": "France", "JP": "Japan", "CN": "China",
        "BR": "Brazil", "RU": "Russia", "MX": "Mexico",
        "ES": "Spain", "IT": "Italy", "NL": "Netherlands",
        "SG": "Singapore", "KR": "South Korea", "SE": "Sweden",
        "NO": "Norway", "DK": "Denmark", "FI": "Finland"
    }
    return countries.get(country_code, country_code)


def is_ip_safe(ip: str) -> bool:
    """
    Simple boolean check if IP is safe
    """
    result = check_ip(ip)
    return not result.get("is_malicious", False)