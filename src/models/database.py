from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Enum as SQLEnum
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
import enum

Base = declarative_base()

class AccessDecision(str, enum.Enum):
    """Access decision outcomes"""
    ALLOW = "allow"
    CHALLENGE = "challenge"
    DENY = "deny"

class User(Base):
    """User model"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    mfa_enabled = Column(Boolean, default=False)
    risk_score = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

class Device(Base):
    """Device model"""
    __tablename__ = "devices"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    device_name = Column(String, index=True)
    device_type = Column(String)  # laptop, mobile, tablet
    os_type = Column(String)  # windows, macos, linux
    os_version = Column(String)
    os_security_score = Column(Float, default=0.0)
    antivirus_enabled = Column(Boolean, default=False)
    firewall_enabled = Column(Boolean, default=False)
    disk_encrypted = Column(Boolean, default=False)
    last_patch_date = Column(DateTime, nullable=True)
    device_health_score = Column(Float, default=0.0)
    is_trusted = Column(Boolean, default=False)
    last_seen = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

class AccessLog(Base):
    """Access request log model"""
    __tablename__ = "access_logs"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, index=True)
    device_id = Column(Integer)
    resource = Column(String, index=True)
    action = Column(String)
    user_risk_score = Column(Float)
    device_risk_score = Column(Float)
    context_risk_score = Column(Float)
    total_risk_score = Column(Float)
    decision = Column(SQLEnum(AccessDecision))
    ip_address = Column(String)
    location = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    details = Column(String)

class Policy(Base):
    """Dynamic policy model"""
    __tablename__ = "policies"
    
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, index=True)
    resource = Column(String, index=True)
    condition = Column(String)  # JSON format
    action = Column(String)  # allow, challenge, deny
    priority = Column(Integer, default=100)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class BehaviorProfile(Base):
    """User behavior profile model"""
    __tablename__ = "behavior_profiles"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, unique=True, index=True)
    normal_location = Column(String)
    normal_time_zone = Column(String)
    typical_access_time = Column(String)
    typical_devices = Column(String)  # JSON array
    normal_resources = Column(String)  # JSON array
    anomaly_count = Column(Integer, default=0)
    last_updated = Column(DateTime, default=datetime.utcnow)



# src/models/schemas.py

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