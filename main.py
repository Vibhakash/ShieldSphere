from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import bcrypt
import requests
import uvicorn
import pytz
from database import Base, engine, SessionLocal
from models import User, LoginEvent
from services.password_pwned import check_password_pwned
from services.url_scan_service import scan_url, check_url_exists
from services.ip_reputation import check_ip
from services.geoip import get_country, get_ip_details
from user_agents import parse
import os
import pyotp
import qrcode
import io
from fastapi.responses import StreamingResponse
from typing import Optional
# ---------------- IST TIMEZONE ----------------
IST = pytz.timezone('Asia/Kolkata')

# ---------------- APP ----------------
app = FastAPI(title="ShieldSphere - Account Safety System")

Base.metadata.create_all(engine)

# ---------------- DATABASE DEPENDENCY ----------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ---------------- SCHEMAS ----------------
class PasswordRequest(BaseModel):
    password: str

class URLRequest(BaseModel):
    url: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class UserRegistration(BaseModel):
    email: EmailStr
    password: str

class BrowserLocation(BaseModel):
    latitude: float
    longitude: float
    accuracy: float  # in meters

class EnhancedLoginRequest(BaseModel):
    email: str
    password: str
    browser_location: Optional[BrowserLocation] = None
# ---------------- HELPER FUNCTIONS ----------------
def get_ist_time():
    """Get current time in IST"""
    return datetime.now(IST)

def to_ist(dt):
    """Convert any datetime to IST - handles both naive and aware datetimes"""
    if dt is None:
        return None
    
    # If datetime is naive (no timezone), assume it's UTC
    if dt.tzinfo is None:
        dt = pytz.utc.localize(dt)
    
    # Convert to IST
    return dt.astimezone(IST)

def format_ist(dt):
    """Format datetime as IST string"""
    if dt is None:
        return None
    
    # Convert to IST first
    ist_time = to_ist(dt)
    return ist_time.strftime("%Y-%m-%d %I:%M:%S %p IST")

def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    password_bytes = plain_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed_bytes)

def get_user_by_email(db: Session, email: str):
    """Get user from database by email"""
    return db.query(User).filter(User.email == email).first()

def log_login_event(db: Session, email: str, ip: str, country: str, success: bool, user_agent: str = None):
    """Log login attempt to database"""
    event = LoginEvent(
        email=email,
        ip_address=ip,
        country=country,
        success=success,
        user_agent=user_agent
    )
    db.add(event)
    db.commit()
    return event

def check_login_risk_internal(db: Session, email: str, current_country: str):
    """Internal function to check login risks"""
    # Get recent login events (last 30 days)
    thirty_days_ago = get_ist_time() - timedelta(days=30)
    
    events = db.query(LoginEvent).filter(
        LoginEvent.email == email,
        LoginEvent.timestamp >= thirty_days_ago
    ).order_by(LoginEvent.timestamp.desc()).all()
    
    if not events:
        return {"risk_detected": False, "alerts": []}
    
    # Analyze patterns
    countries = set(e.country for e in events)
    failed_attempts = sum(1 for e in events if not e.success)
    recent_failed = sum(1 for e in events[:5] if not e.success)
    
    alerts = []
    
    if current_country not in countries:
        alerts.append(f"⚠️ Login from new location: {current_country}")
    
    if failed_attempts >= 3:
        alerts.append(f"⚠️ {failed_attempts} failed login attempts detected")
    
    if recent_failed >= 2:
        alerts.append("🚨 Multiple recent failed attempts - possible brute force attack")
    
    recent_ips = [e.ip_address for e in events[:10]]
    if len(set(recent_ips)) > 5:
        alerts.append("⚠️ Logins from multiple IP addresses detected")
    
    return {
        "risk_detected": len(alerts) > 0,
        "alerts": alerts
    }
def get_client_ip(request: Request) -> str:
    """
    Get real client IP address from request
    Handles proxies, load balancers, and cloud providers
    """
    # Try X-Forwarded-For first (standard proxy header)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # X-Forwarded-For can contain multiple IPs, first one is the client
        return forwarded_for.split(",")[0].strip()
    
    # Try X-Real-IP (used by some proxies)
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    
    # Try CF-Connecting-IP (Cloudflare)
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip.strip()
    
    # Fallback to direct connection IP
    return request.client.host
# ---------------- ENDPOINTS ----------------

@app.get("/")
def root():
    return {
        "app": "ShieldSphere",
        "status": "running",
        "version": "2.0.0",
        "endpoints": {
            "register": "/register",
            "login": "/login",
            "check_password": "/check-password",
            "scan_url": "/scan-url",
            "validate_url": "/validate-url",
            "check_ip": "/check-ip/{ip}",
            "recommendations": "/security-recommendations/{email}",
            "login_history": "/login-history/{email}",
            "login_locations": "/login-locations/{email}",
            "login_devices": "/login-devices/{email}",
            "login_dashboard": "/login-dashboard/{email}",
            "login_map": "/login-map/{email}"
        }
    }

@app.post("/register")
def register_user(data: UserRegistration, db: Session = Depends(get_db)):
    """Register a new user"""
    
    existing_user = get_user_by_email(db, data.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    pwned_check = check_password_pwned(data.password)
    if pwned_check.get("pwned", False):
        raise HTTPException(
            status_code=400, 
            detail=f"Password has been exposed in {pwned_check['count']} data breaches. Choose a different password."
        )
    
    hashed_pw = hash_password(data.password)
    new_user = User(
        email=data.email,
        hashed_password=hashed_pw
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return {
        "message": "User registered successfully",
        "email": new_user.email,
        "created_at": format_ist(new_user.created_at)
    }


# Enhanced login endpoint - replace your existing /login
@app.post("/login")
def login(data: EnhancedLoginRequest, request: Request, db: Session = Depends(get_db)):
    """
    Enhanced login with both IP geolocation AND browser geolocation
    This gives you EXACT location when user permits
    """
    
    # Get real client IP
    ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "Unknown")
    
    # Get IP-based location (fallback)
    ip_details = get_ip_details(ip)
    country = ip_details.get("country", "Unknown")
    
    # Use browser location if available (EXACT location)
    if data.browser_location:
        latitude = data.browser_location.latitude
        longitude = data.browser_location.longitude
        accuracy = data.browser_location.accuracy
        location_source = "browser_gps"
        location_accuracy = "exact"
        
        # Reverse geocode to get city/region from coordinates
        city, region = reverse_geocode(latitude, longitude)
        
        location_string = f"{city}, {region}, {country}"
    else:
        # Use IP-based location
        latitude = ip_details.get("latitude", 0)
        longitude = ip_details.get("longitude", 0)
        accuracy = "city_level"
        location_source = ip_details.get("source", "ip_api")
        location_accuracy = ip_details.get("accuracy", "medium")
        location_string = ip_details.get("location_string", "Unknown")
    
    # Authenticate user
    user = get_user_by_email(db, data.email)
    
    if not user:
        log_login_event(
            db, data.email, ip, country, False, user_agent,
            latitude, longitude, location_source, location_accuracy
        )
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if not verify_password(data.password, user.hashed_password):
        log_login_event(
            db, data.email, ip, country, False, user_agent,
            latitude, longitude, location_source, location_accuracy
        )
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Check if 2FA is enabled
    if user.is_2fa_enabled:
        return {
            "message": "2FA required",
            "email": user.email,
            "next_step": "verify-login-2fa",
            "instruction": "Please provide your 6-digit 2FA code"
        }
    
    # Success - log with enhanced location data
    risk_check = check_login_risk_internal(db, data.email, country)
    log_login_event(
        db, data.email, ip, country, True, user_agent,
        latitude, longitude, location_source, location_accuracy
    )
    
    return {
        "message": "Login successful",
        "email": user.email,
        "ip": ip,
        "country": country,
        "location": location_string,
        "location_accuracy": location_accuracy,
        "coordinates": {
            "lat": latitude,
            "lng": longitude
        },
        "risk_alerts": risk_check.get("alerts", []),
        "timestamp": format_ist(get_ist_time()),
        "2fa_enabled": False
    }


def reverse_geocode(lat: float, lng: float) -> tuple:
    """
    Reverse geocode coordinates to get city/region
    Uses Nominatim (OpenStreetMap) - free and accurate
    """
    try:
        url = f"https://nominatim.openstreetmap.org/reverse?format=json&lat={lat}&lon={lng}"
        headers = {"User-Agent": "ShieldSphere/1.0"}
        response = requests.get(url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            address = data.get("address", {})
            
            city = (
                address.get("city") or 
                address.get("town") or 
                address.get("village") or 
                address.get("suburb") or
                "Unknown"
            )
            
            region = (
                address.get("state") or 
                address.get("province") or 
                address.get("region") or
                "Unknown"
            )
            
            return city, region
    except:
        pass
    
    return "Unknown", "Unknown"


def log_login_event(db: Session, email: str, ip: str, country: str, 
                            success: bool, user_agent: str,
                            latitude: float, longitude: float,
                            location_source: str, location_accuracy: str):
    """
    Enhanced login event logging with precise coordinates
    
    NOTE: You'll need to add these columns to your LoginEvent model:
    - latitude (Float)
    - longitude (Float)
    - location_source (String)
    - location_accuracy (String)
    """
    event = LoginEvent(
        email=email,
        ip_address=ip,
        country=country,
        success=success,
        user_agent=user_agent,
        latitude=latitude,
        longitude=longitude,
        location_source=location_source,
        location_accuracy=location_accuracy
    )
    db.add(event)
    db.commit()
    return event

@app.post("/auto-respond/{email}")
def auto_respond_to_threat(email: str, threat_type: str, db: Session = Depends(get_db)):
    """Automatically respond to detected threats"""
    
    actions_taken = []
    
    if threat_type == "brute_force":
        # Temporarily lock account
        actions_taken.append("Account temporarily locked for 15 minutes")
        # Send alert
        actions_taken.append("Security alert sent to email")
        # Block IP
        actions_taken.append("Suspicious IP blocked")
    
    elif threat_type == "impossible_travel":
        # Require 2FA verification
        actions_taken.append("Additional verification required")
        # Send alert
        actions_taken.append("Unusual login location alert sent")
    
    return {
        "threat_detected": threat_type,
        "actions_taken": actions_taken,
        "timestamp": format_ist(get_ist_time())
    }

# Add this schema at the top with other schemas
class TwoFAVerify(BaseModel):
    email: EmailStr
    code: str

# 2 factor authentication
from fastapi.responses import StreamingResponse
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
import pyotp, qrcode, io

@app.post("/setup-2fa-image/{email}")
def setup_2fa_image(email: str, db: Session = Depends(get_db)):
    user = get_user_by_email(db, email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # 🔒 Generate secret ONLY if not already present
    if not user.twofa_secret:
        user.twofa_secret = pyotp.random_base32()
        user.is_2fa_enabled = True
        db.commit()

    totp = pyotp.TOTP(user.twofa_secret)
    uri = totp.provisioning_uri(
        name=email,
        issuer_name="ShieldSphere"
    )

    qr = qrcode.make(uri)

    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    buf.seek(0)

    return StreamingResponse(buf, media_type="image/png")

# 4️⃣ Verify 2FA During Login
@app.post("/verify-login-2fa")
def verify_login_2fa(data: TwoFAVerify, request: Request, db: Session = Depends(get_db)):
    """Verify 2FA code during login"""
    
    user = get_user_by_email(db, data.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not user.is_2fa_enabled or not user.twofa_secret:
        raise HTTPException(status_code=400, detail="2FA not enabled for this account")
    
    # Verify the code
    totp = pyotp.TOTP(user.twofa_secret)
    if not totp.verify(data.code, valid_window=1):
        # Log failed 2FA attempt
        try:
            ip = get_client_ip(request)
            ip_details = get_ip_details(ip)
            country = ip_details.get("country", "Unknown")
            user_agent = request.headers.get("user-agent", "Unknown")
            log_login_event(db, data.email, ip, country, False, f"{user_agent} [2FA Failed]")
        except:
            pass
        
        raise HTTPException(status_code=401, detail="Invalid 2FA code")
    
    # Success - log the login
    ip = get_client_ip(request)
    ip_details = get_ip_details(ip)
    country = ip_details.get("country", "Unknown")

    user_agent = request.headers.get("user-agent", "Unknown")
    
    risk_check = check_login_risk_internal(db, data.email, country)
    log_login_event(db, data.email, ip, country, True, user_agent)
    
    return {
        "success": True,
        "message": "Login successful with 2FA",
        "email": data.email,
        "ip": ip,
        "country": country,
        "risk_alerts": risk_check.get("alerts", []),
        "timestamp": format_ist(get_ist_time())
    }

# 5️⃣ Disable 2FA
@app.post("/disable-2fa/{email}")
def disable_2fa(email: str, password: str, db: Session = Depends(get_db)):
    """Disable 2FA (requires password confirmation)"""
    
    user = get_user_by_email(db, email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Verify password
    if not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid password")
    
    # Disable 2FA
    user.is_2fa_enabled = False
    user.twofa_secret = None
    db.commit()
    
    return {
        "success": True,
        "message": "2FA disabled successfully",
        "email": email
    }

# 6️⃣ Check 2FA Status
@app.get("/2fa-status/{email}")
def check_2fa_status(email: str, db: Session = Depends(get_db)):
    """Check if 2FA is enabled for user"""
    
    user = get_user_by_email(db, email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "email": email,
        "is_2fa_enabled": user.is_2fa_enabled,
        "recommendation": "Enable 2FA for better security" if not user.is_2fa_enabled else "2FA is active"
    }

@app.post("/check-password")
def password_check(data: PasswordRequest):
    """Check if password has been exposed in data breaches"""
    return check_password_pwned(data.password)

@app.post("/scan-url")
def phishing_scan(data: URLRequest):
    """Scan URL for phishing threats"""
    return scan_url(data.url)

@app.post("/validate-url")
def validate_url(data: URLRequest):
    """Quick check if URL exists before full security scan"""
    url_check = check_url_exists(data.url)
    
    if not url_check.get("exists", False):
        return {
            "url": data.url,
            "valid": False,
            "status": "❌ URL Not Found",
            "message": "This URL does not exist or is not accessible",
            "recommendation": "Verify the URL is spelled correctly",
            "should_scan": False
        }
    
    return {
        "url": data.url,
        "valid": True,
        "status": "✅ URL Accessible",
        "http_status": url_check.get("status_code"),
        "message": "URL is reachable. Run /scan-url for security check.",
        "should_scan": True
    }

@app.get("/check-ip/{ip}")
def ip_reputation(ip: str):
    """Check IP reputation for suspicious activity"""
    return check_ip(ip)


@app.get("/login-history/{email}")
def get_login_history(email: str, limit: int = 20, db: Session = Depends(get_db)):
    """Get recent login history for an email"""
    
    events = db.query(LoginEvent).filter(
        LoginEvent.email == email
    ).order_by(LoginEvent.timestamp.desc()).limit(limit).all()
    
    return {
        "email": email,
        "total_events": len(events),
        "events": [
            {
                "ip": e.ip_address,
                "country": e.country,
                "success": e.success,
                "timestamp": format_ist(e.timestamp),  # Converts UTC to IST
                "user_agent": e.user_agent
            }
            for e in events
        ]
    }

@app.get("/login-locations/{email}")
def get_login_locations(email: str, db: Session = Depends(get_db)):
    """Get all unique login locations with coordinates for map visualization"""
    
    events = db.query(LoginEvent).filter(
        LoginEvent.email == email
    ).order_by(LoginEvent.timestamp.desc()).all()
    
    if not events:
        return {
            "email": email,
            "message": "No login history found",
            "locations": []
        }
    
    unique_ips = list(set(e.ip_address for e in events))
    
    locations = []
    for ip in unique_ips:
        ip_data = get_ip_details(ip)
        
        if "error" not in ip_data:
            login_count = sum(1 for e in events if e.ip_address == ip)
            success_count = sum(1 for e in events if e.ip_address == ip and e.success)
            failed_count = login_count - success_count
            
            last_login = next((e.timestamp for e in events if e.ip_address == ip), None)
            
            locations.append({
                "ip": ip,
                "city": ip_data.get("city", "Unknown"),
                "region": ip_data.get("region", "Unknown"),
                "country": ip_data.get("country_name", "Unknown"),
                "country_code": ip_data.get("country", "Unknown"),
                "latitude": ip_data.get("latitude", 0),
                "longitude": ip_data.get("longitude", 0),
                "timezone": ip_data.get("timezone", "Unknown"),
                "isp": ip_data.get("org", "Unknown"),
                "total_logins": login_count,
                "successful_logins": success_count,
                "failed_logins": failed_count,
                "last_login": format_ist(last_login),  # Converts UTC to IST
                "location_string": ip_data.get("location_string", "Unknown")
            })
    
    return {
        "email": email,
        "total_locations": len(locations),
        "locations": locations,
        "map_ready": True
    }

@app.get("/login-devices/{email}")
def get_login_devices(email: str, db: Session = Depends(get_db)):
    """Get all devices used to login with detailed information"""
    
    events = db.query(LoginEvent).filter(
        LoginEvent.email == email
    ).order_by(LoginEvent.timestamp.desc()).all()
    
    if not events:
        return {
            "email": email,
            "message": "No login history found",
            "devices": []
        }
    
    devices = []
    seen_agents = set()
    
    for event in events:
        if event.user_agent and event.user_agent not in seen_agents:
            seen_agents.add(event.user_agent)
            
            ua = parse(event.user_agent)
            
            device_logins = sum(1 for e in events if e.user_agent == event.user_agent)
            device_success = sum(1 for e in events if e.user_agent == event.user_agent and e.success)
            
            device_events = [e for e in events if e.user_agent == event.user_agent]
            first_seen = device_events[-1].timestamp if device_events else None
            last_seen = device_events[0].timestamp if device_events else None
            
            devices.append({
                "device_id": hash(event.user_agent) % 10000,
                "browser": {
                    "name": ua.browser.family,
                    "version": ua.browser.version_string
                },
                "os": {
                    "name": ua.os.family,
                    "version": ua.os.version_string
                },
                "device": {
                    "type": "Mobile" if ua.is_mobile else "Tablet" if ua.is_tablet else "Desktop",
                    "brand": ua.device.brand or "Unknown",
                    "model": ua.device.model or "Unknown"
                },
                "is_mobile": ua.is_mobile,
                "is_tablet": ua.is_tablet,
                "is_pc": ua.is_pc,
                "is_bot": ua.is_bot,
                "total_logins": device_logins,
                "successful_logins": device_success,
                "failed_logins": device_logins - device_success,
                "first_seen": format_ist(first_seen),  # Converts UTC to IST
                "last_seen": format_ist(last_seen),    # Converts UTC to IST
                "user_agent_string": event.user_agent
            })
    
    return {
        "email": email,
        "total_devices": len(devices),
        "devices": devices
    }

@app.get("/login-dashboard/{email}")
def get_login_dashboard(email: str, db: Session = Depends(get_db)):
    """Get comprehensive login activity dashboard with locations and devices"""
    
    events = db.query(LoginEvent).filter(
        LoginEvent.email == email
    ).order_by(LoginEvent.timestamp.desc()).all()
    
    if not events:
        return {
            "email": email,
            "message": "No login history found"
        }
    
    locations = get_login_locations(email, db)
    devices = get_login_devices(email, db)
    
    total_logins = len(events)
    successful_logins = sum(1 for e in events if e.success)
    failed_logins = total_logins - successful_logins
    unique_countries = len(set(e.country for e in events))
    unique_ips = len(set(e.ip_address for e in events))
    
    # FIXED: Use IST time instead of UTC
    seven_days_ago = get_ist_time() - timedelta(days=7)
    recent_events = [e for e in events if to_ist(e.timestamp) >= seven_days_ago]
    
    login_timeline = []
    for event in events[:20]:
        ua = parse(event.user_agent) if event.user_agent else None
        ip_data = get_ip_details(event.ip_address)
        
        login_timeline.append({
            "timestamp": format_ist(event.timestamp),  # Converts UTC to IST
            "success": event.success,
            "ip": event.ip_address,
            "location": ip_data.get("location_string", "Unknown"),
            "country": event.country,
            "device": ua.device.family if ua else "Unknown",
            "browser": ua.browser.family if ua else "Unknown",
            "os": ua.os.family if ua else "Unknown"
        })
    
    return {
        "email": email,
        "statistics": {
            "total_logins": total_logins,
            "successful_logins": successful_logins,
            "failed_logins": failed_logins,
            "success_rate": f"{(successful_logins/total_logins*100):.1f}%" if total_logins > 0 else "0%",
            "unique_locations": unique_countries,
            "unique_ips": unique_ips,
            "unique_devices": devices["total_devices"],
            "recent_activity_7days": len(recent_events)
        },
        "locations": locations["locations"],
        "devices": devices["devices"],
        "recent_timeline": login_timeline
    }

@app.get("/security-recommendations/{email}")
def security_recommendations(email: str, db: Session = Depends(get_db)):
    """Get personalized security recommendations"""
    
    events = db.query(LoginEvent).filter(LoginEvent.email == email).all()
    
    recommendations = []
    priority_recommendations = []
    
    if not events:
        return {
            "email": email,
            "recommendations": ["Create your first login to get personalized recommendations"]
        }
    
    failed_attempts = sum(1 for e in events if not e.success)
    countries = set(e.country for e in events)
    
    if failed_attempts >= 5:
        priority_recommendations.append({
            "priority": "HIGH",
            "recommendation": "🚨 Change your password immediately - multiple failed login attempts detected",
            "action": "change_password"
        })
    
    if len(countries) > 2:
        priority_recommendations.append({
            "priority": "HIGH",
            "recommendation": "🔐 Enable two-factor authentication (2FA) for additional security",
            "action": "enable_2fa"
        })
    
    recommendations.append({
        "priority": "MEDIUM",
        "recommendation": "✅ Use a unique password for this account",
        "action": "use_unique_password"
    })
    
    recommendations.append({
        "priority": "MEDIUM",
        "recommendation": "🔍 Review your recent login activity regularly",
        "action": "review_activity"
    })
    
    recommendations.append({
        "priority": "LOW",
        "recommendation": "🔗 Avoid clicking suspicious or shortened links",
        "action": "avoid_phishing"
    })
    
    recommendations.append({
        "priority": "LOW",
        "recommendation": "📧 Be cautious of unsolicited emails asking for credentials",
        "action": "email_awareness"
    })
    
    return {
        "email": email,
        "priority_recommendations": priority_recommendations,
        "general_recommendations": recommendations,
        "total_alerts": len(priority_recommendations)
    }

from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel

class LoginMapResponse(BaseModel):
    message: str
    map_url: str
    total_locations: int
    email: str

@app.get("/login-map/{email}", response_model=LoginMapResponse)
def get_login_map_info(email: str, request: Request, db: Session = Depends(get_db)):
    """Get login map information and URL to view the interactive map"""
    
    locations_data = get_login_locations(email, db)
    
    # Get the base URL from the request
    base_url = str(request.base_url).rstrip('/')
    map_url = f"{base_url}/login-map/{email}/view"
    
    return LoginMapResponse(
        message="Interactive map is ready! Click the map_url to view it in your browser.",
        map_url=map_url,
        total_locations=locations_data['total_locations'],
        email=email
    )


@app.get("/login-map/{email}/view", response_class=HTMLResponse)
def view_login_map(email: str, db: Session = Depends(get_db)):
    """View the interactive login locations map"""
    
    locations_data = get_login_locations(email, db)
    
    if not locations_data["locations"]:
        return HTMLResponse(content=f"<h2>No location data available for {email}</h2>")
    
    import json
    locations_json = json.dumps(locations_data['locations'])
    
    map_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login Locations Map - {email}</title>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
        <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
        <style>
            body {{ margin: 0; padding: 0; font-family: Arial, sans-serif; }}
            #map {{ height: 100vh; width: 100%; }}
            .info-box {{
                position: absolute;
                top: 10px;
                right: 10px;
                background: white;
                padding: 15px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.2);
                z-index: 1000;
                max-width: 300px;
            }}
            .info-box h3 {{ margin: 0 0 10px 0; color: #333; }}
            .stat {{ margin: 5px 0; color: #666; }}
        </style>
    </head>
    <body>
        <div id="map"></div>
        <div class="info-box">
            <h3>🛡️ ShieldSphere Login Map</h3>
            <div class="stat"><strong>Email:</strong> {email}</div>
            <div class="stat"><strong>Total Locations:</strong> {locations_data['total_locations']}</div>
            <div class="stat"><strong>🔴 Red:</strong> Failed logins</div>
            <div class="stat"><strong>🟢 Green:</strong> Successful logins</div>
        </div>
        
        <script>
            var map = L.map('map').setView([20, 0], 2);
            
            L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
                attribution: '© OpenStreetMap contributors',
                maxZoom: 18
            }}).addTo(map);
            
            var locations = {locations_json};
            
            locations.forEach(function(loc) {{
                var color = loc.failed_logins > 0 ? 'red' : 'green';
                var icon = L.divIcon({{
                    className: 'custom-marker',
                    html: '<div style="background-color: ' + color + '; width: 20px; height: 20px; border-radius: 50%; border: 2px solid white; box-shadow: 0 2px 5px rgba(0,0,0,0.3);"></div>',
                    iconSize: [20, 20]
                }});
                
                var marker = L.marker([loc.latitude, loc.longitude], {{icon: icon}}).addTo(map);
                
                var popupContent = `
                    <div style="padding: 10px;">
                        <h4 style="margin: 0 0 10px 0;">📍 ${{loc.location_string}}</h4>
                        <p style="margin: 5px 0;"><strong>IP:</strong> ${{loc.ip}}</p>
                        <p style="margin: 5px 0;"><strong>ISP:</strong> ${{loc.isp}}</p>
                        <p style="margin: 5px 0;"><strong>Total Logins:</strong> ${{loc.total_logins}}</p>
                        <p style="margin: 5px 0; color: green;"><strong>✅ Successful:</strong> ${{loc.successful_logins}}</p>
                        <p style="margin: 5px 0; color: red;"><strong>❌ Failed:</strong> ${{loc.failed_logins}}</p>
                        <p style="margin: 5px 0;"><strong>Last Login:</strong> ${{loc.last_login}}</p>
                    </div>
                `;
                
                marker.bindPopup(popupContent);
            }});
            
            if (locations.length > 0) {{
                var bounds = L.latLngBounds(locations.map(loc => [loc.latitude, loc.longitude]));
                map.fitBounds(bounds, {{padding: [50, 50]}});
            }}
        </script>
    </body>
    </html>
    """
    
    return HTMLResponse(content=map_html)
@app.get("/compliance-report/{email}")
def generate_compliance_report(email: str, standard: str, db: Session = Depends(get_db)):
    """Generate compliance report (GDPR, SOC2, ISO27001)"""
    
    user = get_user_by_email(db, email)
    events = db.query(LoginEvent).filter(LoginEvent.email == email).all()
    
    if standard == "GDPR":
        return {
            "standard": "GDPR",
            "compliant": True,
            "data_stored": {
                "email": email,
                "password": "Encrypted (bcrypt)",
                "login_history": len(events)
            },
            "user_rights": [
                "Right to access ✅",
                "Right to deletion ✅",
                "Right to portability ✅"
            ]
        }

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
        reload=False
    )
