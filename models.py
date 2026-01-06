from sqlalchemy import Column, Integer, String, DateTime, JSON,Boolean,Float
from database import Base
from sqlalchemy import Column, Integer, String, Boolean, DateTime, func
from datetime import datetime, timedelta, timezone
import pytz

class BreachCheck(Base):
    __tablename__ = "breach_checks"

    id = Column(Integer, primary_key=True)
    email = Column(String)
    breach_data = Column(JSON)
    checked_at = Column(DateTime, default=datetime.utcnow)


class URLScan(Base):
    __tablename__ = "url_scans"

    id = Column(Integer, primary_key=True)
    url = Column(String)
    scan_result = Column(JSON)
    scanned_at = Column(DateTime, default=datetime.utcnow)
# ---------------- DATABASE MODELS ----------------

IST = pytz.timezone('Asia/Kolkata')

def get_ist_time():
    """Get current time in IST"""
    return datetime.now(IST)

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=get_ist_time)  # IST time
    is_active = Column(Boolean, default=True)


    # 2FA columns
    twofa_secret = Column(String, nullable=True)  # Stores the 2FA secret
    is_2fa_enabled = Column(Boolean, default=False)  # Whether 2FA is enabled

class LoginEvent(Base):
    __tablename__ = "login_events"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, index=True)
    ip_address = Column(String)
    country = Column(String)
    success = Column(Boolean)
    timestamp = Column(DateTime, default=get_ist_time)  # IST time
    user_agent = Column(String, nullable=True)
