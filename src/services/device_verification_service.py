from datetime import datetime
from typing import Dict, List, Tuple
import hashlib

# Simulated database (replace with real database in production)
user_devices_db = {}
user_ips_db = {}
login_attempts_db = []

def generate_device_id(device_fingerprint: str, user_agent: str) -> str:
    """Generate unique device ID from fingerprint + user agent"""
    combined = f"{device_fingerprint}:{user_agent}"
    return hashlib.sha256(combined.encode()).hexdigest()[:16]

def is_known_device(user_id: int, device_fingerprint: str, user_agent: str) -> bool:
    """Check if device is recognized for this user"""
    if user_id not in user_devices_db:
        return False
    
    device_id = generate_device_id(device_fingerprint, user_agent)
    return device_id in user_devices_db[user_id]

def is_known_ip(user_id: int, ip_address: str) -> bool:
    """Check if IP address is recognized for this user"""
    if user_id not in user_ips_db:
        return False
    
    return ip_address in user_ips_db[user_id]

def register_device(user_id: int, device_fingerprint: str, user_agent: str, 
                   ip_address: str, location: str = None):
    """Register new device for user"""
    if user_id not in user_devices_db:
        user_devices_db[user_id] = {}
    
    device_id = generate_device_id(device_fingerprint, user_agent)
    user_devices_db[user_id][device_id] = {
        "fingerprint": device_fingerprint,
        "user_agent": user_agent,
        "ip_address": ip_address,
        "location": location,
        "first_seen": datetime.now().isoformat(),
        "last_seen": datetime.now().isoformat(),
        "trust_score": 100
    }

def register_ip(user_id: int, ip_address: str, location: str = None):
    """Register new IP address for user"""
    if user_id not in user_ips_db:
        user_ips_db[user_id] = {}
    
    user_ips_db[user_id][ip_address] = {
        "location": location,
        "first_seen": datetime.now().isoformat(),
        "last_seen": datetime.now().isoformat(),
        "login_count": 1
    }

def calculate_risk_score(user_id: int, device_fingerprint: str, user_agent: str,
                        ip_address: str, location: str = None) -> Tuple[int, List[str]]:
    """
    Calculate risk score (0-100, higher = more risky)
    Returns: (risk_score, list_of_warnings)
    """
    risk_score = 0
    warnings = []
    
    # Check 1: Unknown device? (+40 risk)
    if not is_known_device(user_id, device_fingerprint, user_agent):
        risk_score += 40
        warnings.append("⚠️ Login from UNRECOGNIZED DEVICE")
    
    # Check 2: Unknown IP? (+30 risk)
    if not is_known_ip(user_id, ip_address):
        risk_score += 30
        warnings.append("⚠️ Login from UNKNOWN IP ADDRESS")
    
    # Check 3: Both unknown? (+20 extra risk) = CRITICAL
    if not is_known_device(user_id, device_fingerprint, user_agent) and \
       not is_known_ip(user_id, ip_address):
        risk_score += 20
        warnings.append("🚨 CRITICAL: Both device AND IP are unknown!")
    
    # Check 4: Rapid location change (impossible travel)
    if user_id in user_ips_db and location:
        last_locations = [ip_info.get("location") for ip_info in user_ips_db[user_id].values()]
        if last_locations and location not in last_locations:
            risk_score += 15
            warnings.append("⚠️ Geographic location changed")
    
    # Check 5: Check recent failed attempts
    recent_failures = count_recent_failed_attempts(user_id, minutes=10)
    if recent_failures >= 3:
        risk_score += 25
        warnings.append(f"⚠️ {recent_failures} failed login attempts in last 10 minutes")
    
    return risk_score, warnings

def count_recent_failed_attempts(user_id: int, minutes: int = 10) -> int:
    """Count failed login attempts in last N minutes"""
    cutoff_time = datetime.now().timestamp() - (minutes * 60)
    count = 0
    
    for attempt in login_attempts_db:
        if attempt["user_id"] == user_id and \
           attempt["success"] == False and \
           attempt["timestamp"] > cutoff_time:
            count += 1
    
    return count

def log_login_attempt(user_id: int, success: bool, device_fingerprint: str,
                     ip_address: str, risk_score: int):
    """Log all login attempts for forensics"""
    login_attempts_db.append({
        "user_id": user_id,
        "success": success,
        "device_fingerprint": device_fingerprint,
        "ip_address": ip_address,
        "risk_score": risk_score,
        "timestamp": datetime.now().timestamp(),
        "datetime": datetime.now().isoformat()
    })

def determine_action(risk_score: int) -> Tuple[str, bool, str]:
    """
    Determine what action to take based on risk score
    Returns: (action, requires_2fa, risk_level)
    """
    if risk_score >= 70:
        return "DENY", True, "critical"
    elif risk_score >= 50:
        return "CHALLENGE", True, "high"
    elif risk_score >= 30:
        return "ALLOW_WITH_2FA", True, "medium"
    else:
        return "ALLOW", False, "low"

def get_user_devices(user_id: int) -> Dict:
    """Get all registered devices for user"""
    return user_devices_db.get(user_id, {})

def get_user_ips(user_id: int) -> Dict:
    """Get all registered IPs for user"""
    return user_ips_db.get(user_id, {})
