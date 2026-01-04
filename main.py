from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import bcrypt
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

@app.post("/login")
def login(data: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """Authenticate user and log login attempt"""
    
    ip = request.client.host
    user_agent = request.headers.get("user-agent", "Unknown")
    country = get_country(ip)
    
    user = get_user_by_email(db, data.email)
    
    if not user:
        log_login_event(db, data.email, ip, country, False, user_agent)
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if not verify_password(data.password, user.hashed_password):
        log_login_event(db, data.email, ip, country, False, user_agent)
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    risk_check = check_login_risk_internal(db, data.email, country)
    log_login_event(db, data.email, ip, country, True, user_agent)
    
    return {
        "message": "Login successful",
        "email": user.email,
        "ip": ip,
        "country": country,
        "risk_alerts": risk_check.get("alerts", []),
        "timestamp": format_ist(get_ist_time())
    }

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

@app.get("/login-map/{email}")
def get_login_map(email: str, db: Session = Depends(get_db)):
    """Generate an interactive map showing login locations"""
    
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

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
        reload=False
    )
