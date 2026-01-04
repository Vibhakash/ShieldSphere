import requests
import os
import time
from typing import Dict
import base64

def scan_url(url_to_scan: str) -> Dict:
    """
    Scan URL for malicious content using VirusTotal API
    Returns analysis results with threat detection
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    
    if not api_key:
        return {
            "error": "VirusTotal API key not configured",
            "safe": None
        }
    
    try:
        headers = {"x-apikey": api_key}
        
        # Step 1: Check if URL exists in database first (faster)
        url_id = base64.urlsafe_b64encode(url_to_scan.encode()).decode().strip("=")
        check_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        
        check_response = requests.get(check_url, headers=headers, timeout=10)
        
        # If URL exists in database, use those results
        if check_response.status_code == 200:
            data = check_response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            timeout = stats.get("timeout", 0)
            
            total_scans = malicious + suspicious + harmless + undetected + timeout
            
            # Check if URL is actually reachable
            last_http_code = attributes.get("last_http_response_code", 0)
            
            # If no scan results or URL doesn't exist (404, etc), mark as suspicious
            if total_scans == 0 or last_http_code in [404, 0]:
                return {
                    "url": url_to_scan,
                    "safe": False,
                    "malicious_detections": 0,
                    "suspicious_detections": 0,
                    "harmless": 0,
                    "undetected": 0,
                    "total_scans": 0,
                    "status": "⚠️ URL Not Reachable",
                    "message": f"URL returned HTTP {last_http_code} (Not Found or Unreachable)",
                    "http_status": last_http_code,
                    "recommendation": "This URL does not exist or is not accessible",
                    "analysis_date": attributes.get("last_analysis_date", "Unknown")
                }
            
            is_safe = malicious == 0 and suspicious == 0
            
            return {
                "url": url_to_scan,
                "safe": is_safe,
                "malicious_detections": malicious,
                "suspicious_detections": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total_scans": total_scans,
                "status": "✅ Safe" if is_safe else "🚨 Threat Detected",
                "message": f"Detected by {malicious} security vendors as malicious" if malicious > 0 else "No threats detected",
                "http_status": last_http_code,
                "categories": attributes.get("categories", {}),
                "analysis_date": attributes.get("last_analysis_date", "Unknown")
            }
        
        # Step 2: URL not in database, submit for scanning
        submit_url = "https://www.virustotal.com/api/v3/urls"
        data = {"url": url_to_scan}
        
        submit_response = requests.post(submit_url, headers=headers, data=data, timeout=10)
        
        if submit_response.status_code != 200:
            return {
                "error": f"Failed to submit URL: {submit_response.status_code}",
                "safe": None
            }
        
        submit_data = submit_response.json()
        analysis_id = submit_data.get("data", {}).get("id")
        
        if not analysis_id:
            return {
                "error": "Failed to get analysis ID",
                "safe": None
            }
        
        # Step 3: Poll for results (wait for scan to complete)
        max_attempts = 10
        for attempt in range(max_attempts):
            time.sleep(3)  # Wait 3 seconds between checks
            
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            analysis_response = requests.get(analysis_url, headers=headers, timeout=10)
            
            if analysis_response.status_code != 200:
                continue
            
            result = analysis_response.json()
            attributes = result.get("data", {}).get("attributes", {})
            status = attributes.get("status", "")
            
            # Check if scan is complete
            if status == "completed":
                stats = attributes.get("stats", {})
                
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                timeout = stats.get("timeout", 0)
                
                total_scans = malicious + suspicious + harmless + undetected + timeout
                
                # Get URL analysis results
                results = attributes.get("results", {})
                
                # Check if URL actually exists
                url_accessible = harmless > 0 or undetected > 0
                
                if not url_accessible and total_scans == 0:
                    return {
                        "url": url_to_scan,
                        "safe": False,
                        "malicious_detections": 0,
                        "suspicious_detections": 0,
                        "harmless": 0,
                        "undetected": 0,
                        "total_scans": 0,
                        "status": "⚠️ URL Not Found",
                        "message": "URL does not exist or is not accessible",
                        "recommendation": "Verify the URL is correct",
                        "scan_complete": True
                    }
                
                is_safe = malicious == 0 and suspicious == 0
                
                # Get detailed detection info
                detections = []
                for engine, result in results.items():
                    if result.get("category") in ["malicious", "suspicious"]:
                        detections.append({
                            "engine": engine,
                            "category": result.get("category"),
                            "result": result.get("result")
                        })
                
                return {
                    "url": url_to_scan,
                    "safe": is_safe,
                    "malicious_detections": malicious,
                    "suspicious_detections": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "total_scans": total_scans,
                    "status": "✅ Safe" if is_safe else "🚨 Threat Detected",
                    "message": f"Detected by {malicious} security vendors as malicious" if malicious > 0 else "No threats detected",
                    "analysis_id": analysis_id,
                    "scan_date": attributes.get("date", time.time()),
                    "detections": detections[:5] if detections else [],  # Top 5 detections
                    "scan_complete": True
                }
        
        # If we get here, scan didn't complete in time
        return {
            "url": url_to_scan,
            "safe": None,
            "status": "⏳ Scan In Progress",
            "message": "Scan is still in progress. Please check back in a moment.",
            "analysis_id": analysis_id,
            "recommendation": "The scan may take up to 1 minute to complete. You can check status with analysis_id."
        }
    
    except requests.RequestException as e:
        return {
            "error": f"Network error: {str(e)}",
            "safe": None
        }
    except Exception as e:
        return {
            "error": f"Unexpected error: {str(e)}",
            "safe": None
        }


def check_url_exists(url: str) -> Dict:
    """
    Quick check if URL is reachable without full security scan
    """
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        return {
            "url": url,
            "reachable": True,
            "status_code": response.status_code,
            "exists": response.status_code < 400
        }
    except requests.RequestException:
        return {
            "url": url,
            "reachable": False,
            "exists": False
        }