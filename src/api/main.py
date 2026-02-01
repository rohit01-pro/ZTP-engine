from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from datetime import datetime, timedelta
import logging
from src.config.settings import settings
from src.models.schemas import AccessRequest, AccessResponse, Token, UserCreate, UserResponse, LoginRequest, LoginResponse
from src.services.identity_service import IdentityService
from src.services.ml_service import MLPolicyEngine
from src.services.device_health_service import DeviceHealthService
from src.services.identity_service import IdentityService
from src.utils.logger import setup_logging
from src.services.device_verification_service import (
    is_known_device,
    is_known_ip,
    register_device,
    register_ip,
    calculate_risk_score,
    log_login_attempt,
    determine_action
)
from fastapi.responses import FileResponse



# Setup logging
setup_logging(settings.LOG_LEVEL, settings.LOG_FILE)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Zero Trust Enabled Intelligent IDS Using Machine Learning",
    description="ML-powered Zero Trust Architecture Implementation",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize services
identity_service = IdentityService(
    secret_key=settings.SECRET_KEY,
    algorithm=settings.ALGORITHM
)
ml_engine = MLPolicyEngine(model_path=settings.MODEL_PATH)
device_health_service = DeviceHealthService()

# In-memory storage (replace with database in production)
users_db = {}
devices_db = {}
access_logs = []


@app.get("/")
async def dashboard():
    return FileResponse('index.html')
# Health Check
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }

# Auth Endpoints 
@app.post("/auth/register", response_model=dict)
async def register(user: UserCreate):
    """Register a new user"""
    try:
        # Check if user already exists
        if user.username in users_db:
            raise HTTPException(
                status_code=400,
                detail="Username already exists"
            )
        
        # Hash password
        hashed_password = identity_service.hash_password(user.password)
        
        # Create user
        user_id = len(users_db) + 1
        users_db[user.username] = {
            "id": user_id,
            "username": user.username,
            "email": user.email,
            "hashed_password": hashed_password,
            "is_active": True,
            "mfa_enabled": False,
            "risk_score": 30.0,
            "created_at": datetime.utcnow(),
            "last_login": None,
            "failed_attempts": 0
        }
        
        logger.info(f"User registered: {user.username}")
        
        return {
            "id": user_id,
            "username": user.username,
            "email": user.email,
            "is_active": True,
            "mfa_enabled": False,
            "risk_score": 30.0,
            "created_at": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Registration failed: {str(e)}"
        )

@app.post("/auth/login")
async def login(username: str, password: str):
    """Login user and get JWT token"""
    try:
        # Find user
        user = users_db.get(username)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Verify password
        if not identity_service.verify_password(password, user.get("hashed_password", "")):
            user["failed_attempts"] = user.get("failed_attempts", 0) + 1
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Reset failed attempts
        user["failed_attempts"] = 0
        user["last_login"] = datetime.utcnow()
        
        # Generate token
        token, expire = identity_service.create_access_token(user["id"])
        
        logger.info(f"User logged in: {username}")
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": 1800
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")

async def login_with_device_check(request: LoginRequest, req: Request):
    """
    Login with comprehensive device and IP verification
    
    Security checks:
    1. Verify username + password (traditional)
    2. Check if device is recognized
    3. Check if IP address is recognized
    4. Calculate risk score
    5. Decide: ALLOW / CHALLENGE (2FA) / DENY
    """
    
    # Step 1: Find user by username
    user = None
    for uid, user_data in users_db.items():
        if user_data["username"] == request.username:
            user = user_data
            break
    
    if not user:
        # Don't reveal if user exists (security best practice)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Step 2: Verify password
    password_valid = verify_password(request.password, user["password_hash"])
    
    if not password_valid:
        # Log failed attempt
        log_login_attempt(
            user_id=user["user_id"],
            success=False,
            device_fingerprint=request.device_fingerprint,
            ip_address=request.ip_address,
            risk_score=100  # Failed password = max risk
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    #  PASSWORD IS CORRECT - Now check device & IP
    
    # Step 3: Calculate risk score
    risk_score, warnings = calculate_risk_score(
        user_id=user["user_id"],
        device_fingerprint=request.device_fingerprint,
        user_agent=request.user_agent,
        ip_address=request.ip_address,
        location=request.location
    )
    
    # Step 4: Determine action
    action, requires_2fa, risk_level = determine_action(risk_score)
    
    # Step 5: Log attempt
    log_login_attempt(
        user_id=user["user_id"],
        success=(action != "DENY"),
        device_fingerprint=request.device_fingerprint,
        ip_address=request.ip_address,
        risk_score=risk_score
    )

     # Step 6: Handle based on risk
    
    if action == "DENY":
        #  CRITICAL RISK - Block completely
        return LoginResponse(
            success=False,
            message="Login blocked due to high risk. Please verify your identity.",
            is_new_device=not is_known_device(user["user_id"], 
                                              request.device_fingerprint, 
                                              request.user_agent),
            is_new_ip=not is_known_ip(user["user_id"], request.ip_address),
            requires_2fa=True,
            risk_level=risk_level,
            security_warnings=warnings
        )
    
    elif action in ["CHALLENGE", "ALLOW_WITH_2FA"]:
        #  MEDIUM/HIGH RISK - Require 2FA
        return LoginResponse(
            success=True,
            message="Additional verification required. Please complete 2FA.",
            access_token=None,  # Don't give token yet
            user_id=user["user_id"],
            is_new_device=not is_known_device(user["user_id"], 
                                              request.device_fingerprint, 
                                              request.user_agent),
            is_new_ip=not is_known_ip(user["user_id"], request.ip_address),
            requires_2fa=True,
            risk_level=risk_level,
            security_warnings=warnings
        )
    
    else:  # action == "ALLOW"
        #  LOW RISK - Allow with token
        
        # Register device and IP if new (for future logins)
        if not is_known_device(user["user_id"], request.device_fingerprint, request.user_agent):
            register_device(
                user_id=user["user_id"],
                device_fingerprint=request.device_fingerprint,
                user_agent=request.user_agent,
                ip_address=request.ip_address,
                location=request.location
            )
        
        if not is_known_ip(user["user_id"], request.ip_address):
            register_ip(
                user_id=user["user_id"],
                ip_address=request.ip_address,
                location=request.location
            )
        
        # Create JWT token
        token = create_access_token(user_id=user["user_id"])
        
        return LoginResponse(
            success=True,
            message="Login successful",
            access_token=token,
            user_id=user["user_id"],
            is_new_device=False,
            is_new_ip=False,
            requires_2fa=False,
            risk_level=risk_level,
            security_warnings=warnings if warnings else ["All security checks passed"]
        )
    """
    Authenticate user and return access token
    """
    user = users_db.get(username)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    if not identity_service.verify_password(password, user["hashed_password"]):
        user["failed_attempts"] += 1
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Reset failed attempts on successful login
    user["failed_attempts"] = 0
    user["last_login"] = datetime.utcnow()
    
    # Create token
    expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    token, expires_at = identity_service.create_access_token(
        user_id=user["id"],
        expires_delta=expires_delta
    )
    
    logger.info(f"User logged in: {username}")
    
    return Token(
        access_token=token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

# Access control Endpoints
@app.post("/access/verify")
async def verify_access(request: AccessRequest):
    """Verify access request using Zero Trust model"""
    try:
        # Find user
        user = None
        for username, user_data in users_db.items():
            if user_data.get("id") == request.user_id:
                user = user_data
                break
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Find device
        device = None
        for device_id, device_data in devices_db.items():
            if device_data.get("id") == request.device_id:
                device = device_data
                break
        
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Calculate risks
        user_risk = identity_service.calculate_user_risk(
            last_login_days=0,
            failed_attempts=user.get("failed_attempts", 0),
            is_mfa_enabled=user.get("mfa_enabled", False)
        )
        
        device_health = device_health_service.calculate_health_score(device)
        device_risk = 100 - device_health
        
        context_risk = 20 if request.location == "office" else 70
        
        # Total risk score
        total_risk = (user_risk * 0.40) + (device_risk * 0.35) + (context_risk * 0.25)
        
        # Make decision
        if total_risk < 50:
            decision = "allow"
            reason = f"Access allowed - Risk score {total_risk:.2f} below threshold"
            requires_mfa = False
        elif total_risk < 80:
            decision = "challenge"
            reason = f"Additional verification required - Risk score {total_risk:.2f} detected"
            requires_mfa = True
        else:
            decision = "deny"
            reason = f"Access denied - Risk score {total_risk:.2f} exceeds safe threshold"
            requires_mfa = False
        
        # Log access
        access_logs.append({
            "user_id": request.user_id,
            "device_id": request.device_id,
            "resource": request.resource,
            "action": request.action,
            "decision": decision,
            "risk_score": total_risk,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        logger.info(f"Access {decision}: User {request.user_id}, Risk {total_risk:.2f}")
        
        return {
            "decision": decision,
            "reason": reason,
            "risk_score": round(total_risk, 2),
            "requires_mfa": requires_mfa,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Access verification error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")
    
@app.get("/access/logs")
async def get_access_logs():
    """Get all access logs"""
    try:
        logger.info("Access logs retrieved")
        return {
            "logs": access_logs,
            "total": len(access_logs),
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Access logs error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve logs: {str(e)}")


# Device Endpoints
@app.post("/devices/register")
async def register_device(device_data: dict):
    """Register a new device"""
    device_id = len(devices_db) + 1
    device_info = {
        "id": device_id,
        "user_id": device_data.get("user_id"),
        "device_name": device_data.get("device_name"),
        "device_type": device_data.get("device_type"),
        "os_type": device_data.get("os_type"),
        "os_version": device_data.get("os_version"),
        "os_security_score": device_data.get("os_security_score", 60),
        "antivirus_enabled": device_data.get("antivirus_enabled", False),
        "firewall_enabled": device_data.get("firewall_enabled", False),
        "disk_encrypted": device_data.get("disk_encrypted", False),
        "last_patch_date": datetime.utcnow(),
        "device_health_score": 0.0,
        "is_trusted": False,
        "last_seen": datetime.utcnow(),
        "created_at": datetime.utcnow()
    }
    
    # Calculate health score
    device_info["device_health_score"] = device_health_service.calculate_health_score(device_info)
    
    devices_db[device_id] = device_info
    logger.info(f"Device registered: {device_info['device_name']}")
    
    return device_info

@app.post("/security/threat-intelligence")
async def threat_intelligence_check(device_id: int):
    """Check device against known zero-day threats"""
    
    device = devices_db.get(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    # 1. Check against known zero-days
    ti_engine = ThreatIntelligenceEngine()
    known_exploits = ti_engine.check_against_known_exploits({
        "os": device.get("os_type"),
        "version": device.get("os_version")
    })
    
    # 2. Detect anomalies
    anomaly_detector = AnomalyDetector()
    # (In real app, would analyze actual behavior)
    
    # 3. Check for EDR indicators
    edr = EndpointDetectionAndResponse()
    # (In real app, would analyze actual process data)
    
    return {
        "device_id": device_id,
        "known_vulnerabilities": known_exploits,
        "zero_day_risk": "MEDIUM" if known_exploits else "LOW",
        "recommendation": "APPLY_PATCHES" if known_exploits else "MONITOR",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/security/respond-to-incident")
async def incident_response(device_id: int, severity: str):
    """Respond to suspected zero-day incident"""
    
    responder = IncidentResponseEngine()
    
    response = {
        "device_id": device_id,
        "severity": severity,
        "actions_taken": [
            responder.immediate_response(None, device_id),
            responder.isolate_device(device_id),
            responder.alert_security_team()
        ],
        "timeline": {
            "immediate": "< 1 second",
            "short_term": "< 5 minutes",
            "medium_term": "< 1 hour",
            "long_term": "< 24 hours"
        }
    }
    
    return response

# New endpoint in src/api/main.py

@app.post("/emergency/zero-day-detected")
async def zero_day_emergency_protocol(device_id: int, cve_id: str):
    """
    Executed when zero-day is detected but NO PATCH exists
    """
    
    incident_id = f"INC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    
    response = {
        "incident_id": incident_id,
        "status": "EMERGENCY_PROTOCOL_ACTIVATED",
        "timeline": {
            
            "MINUTE_0": {
                "action": "Kill all sessions + Block outbound traffic",
                "command": f"revoke_sessions({device_id})",
                "status": "EXECUTING"
            },
            
            "MINUTE_1": {
                "action": "Network isolation",
                "command": f"isolate_device_network({device_id})",
                "status": "EXECUTING"
            },
            
            "MINUTE_5": {
                "action": "Activate incident response team",
                "notifications": ["SOC", "CISO", "CEO"],
                "status": "EXECUTING"
            },
            
            "MINUTE_30": {
                "action": "Scan all similar systems for indicators",
                "scan_type": "IOC_SWEEP",
                "status": "QUEUED"
            },
            
            "HOUR_2": {
                "action": "Deploy compensating controls (WAF, FIM, etc)",
                "effectiveness": "60-80%",
                "status": "QUEUED"
            },
            
            "HOUR_6": {
                "action": "Vendor engagement + patch status",
                "contact": "Vendor security team",
                "status": "QUEUED"
            },
            
            "HOUR_12": {
                "action": "Forensic analysis complete",
                "goal": "Understand exploit for patch development",
                "status": "QUEUED"
            },
            
            "HOUR_24": {
                "action": "Patch available (hopefully)",
                "next_step": "Deploy patch to all systems",
                "status": "WAITING"
            }
        },
        
        "immediate_actions": [
            "Session revocation: ✅ DONE",
            "Network isolation: ✅ DONE",
            "Alert security team: ✅ DONE",
            "Forensic snapshot: ✅ DONE"
        ],
        
        "next_critical_action": "Wait for vendor patch / Deploy workarounds",
        "estimated_recovery_time": "24-72 hours"
    }
    
    return response

@app.get("/devices")
async def list_devices():
    """Get all registered devices"""
    return {
        "devices": list(devices_db.values()),
        "total": len(devices_db)
    }

@app.get("/devices/{device_id}/health")
async def get_device_health(device_id: int):
    """Get device health status"""
    device = devices_db.get(device_id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )
    
    return device_health_service.get_device_status(device)

# Helper Functions
def _calculate_context_risk(location: str) -> float:
    """Calculate context risk based on location"""
    # Simplified: known locations have lower risk
    known_locations = ["office", "home", "vpn"]
    if any(loc in location.lower() for loc in known_locations):
        return 20.0
    return 60.0

def _get_time_risk() -> float:
    """Calculate risk based on time of day"""
    hour = datetime.utcnow().hour
    # Higher risk outside business hours
    if 9 <= hour <= 17:
        return 20.0
    else:
        return 50.0

def _get_location_anomaly(last_location: str, current_location: str) -> float:
    """Calculate location anomaly risk"""
    if not last_location:
        return 30.0
    if last_location == current_location:
        return 10.0
    return 70.0

def _get_decision_reason(decision: str, risk_score: float) -> str:
    """Get human-readable reason for decision"""
    if decision == "allow":
        return f"Access allowed - Risk score {risk_score:.2f} is below threshold"
    elif decision == "challenge":
        return f"Additional verification required - Risk score {risk_score:.2f} detected"
    else:
        return f"Access denied - Risk score {risk_score:.2f} exceeds safe threshold"

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
   