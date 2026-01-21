
from pydantic import BaseModel, EmailStr
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

