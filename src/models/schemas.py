
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum

class AccessDecisionEnum(str, Enum):
    ALLOW = "allow"
    CHALLENGE = "challenge"
    DENY = "deny"

# User Schemas
class UserBase(BaseModel):
    username: str
    email: EmailStr

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    id: int
    is_active: bool
    mfa_enabled: bool
    risk_score: float
    created_at: datetime
    
    class Config:
        from_attributes = True

# Device Schemas
class DeviceCreate(BaseModel):
    device_name: str
    device_type: str
    os_type: str
    os_version: str

class DeviceUpdate(BaseModel):
    os_security_score: Optional[float] = None
    antivirus_enabled: Optional[bool] = None
    firewall_enabled: Optional[bool] = None
    disk_encrypted: Optional[bool] = None
    last_patch_date: Optional[datetime] = None

class DeviceResponse(BaseModel):
    id: int
    device_name: str
    device_type: str
    os_type: str
    device_health_score: float
    is_trusted: bool
    last_seen: datetime
    
    class Config:
        from_attributes = True

# Access Request Schema
class AccessRequest(BaseModel):
    user_id: int
    device_id: int
    resource: str
    action: str
    ip_address: str
    location: str

class AccessResponse(BaseModel):
    decision: AccessDecisionEnum
    reason: str
    risk_score: float
    requires_mfa: bool
    timestamp: datetime

# Access Log Schema
class AccessLogResponse(BaseModel):
    id: int
    user_id: int
    device_id: int
    resource: str
    action: str
    decision: AccessDecisionEnum
    total_risk_score: float
    timestamp: datetime
    
    class Config:
        from_attributes = True

# Policy Schema
class PolicyCreate(BaseModel):
    name: str
    resource: str
    condition: str
    action: str
    priority: int = 100

class PolicyResponse(BaseModel):
    id: int
    name: str
    resource: str
    action: str
    priority: int
    is_active: bool
    created_at: datetime
    
    class Config:
        from_attributes = True

# Token Schema
class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int

class TokenData(BaseModel):
    user_id: Optional[int] = None

class LoginRequest(BaseModel):
    """Login request with device fingerprinting"""
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    device_fingerprint: str = Field(..., min_length=10, max_length=100)

# Device fingerprinting fields
    device_fingerprint: str = Field(..., description="Browser/device unique ID")
    ip_address: str = Field(..., description="User's IP address")
    user_agent: str = Field(..., description="Browser user agent string")
    
    # Optional additional security
    location: Optional[str] = Field(None, description="Geographic location")
    timestamp: Optional[str] = Field(None, description="Request timestamp")

class DeviceInfo(BaseModel):
    """Stored device information"""
    device_id: str
    device_fingerprint: str
    ip_address: str
    user_agent: str
    location: Optional[str] = None
    last_seen: str
    trust_score: int = 100  # 0-100, decreases with suspicious activity

class LoginResponse(BaseModel):
    """Login response with security warnings"""
    success: bool
    message: str
    access_token: Optional[str] = None
    user_id: Optional[int] = None
    
    # Security alerts
    is_new_device: bool = False
    is_new_ip: bool = False
    requires_2fa: bool = False
    risk_level: str = "low"  # low, medium, high, critical
    security_warnings: list[str] = []

