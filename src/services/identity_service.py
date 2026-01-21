from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt
from typing import Optional
import logging

logger = logging.getLogger(__name__)

class IdentityService:
    """Service for user identity verification"""
    
    def __init__(self, secret_key: str, algorithm: str = "HS256"):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    
    def hash_password(self, password: str) -> str:
        """Hash a password"""
        return self.pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        return self.pwd_context.verify(plain_password, hashed_password)
    
    def create_access_token(
        self,
        user_id: int,
        expires_delta: Optional[timedelta] = None
    ) -> tuple:
        """Create JWT access token"""
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=30)
        
        to_encode = {
            "user_id": user_id,
            "exp": expire,
            "iat": datetime.utcnow()
        }
        
        encoded_jwt = jwt.encode(
            to_encode,
            self.secret_key,
            algorithm=self.algorithm
        )
        
        return encoded_jwt, expire
    
    def verify_token(self, token: str) -> Optional[int]:
        """Verify JWT token and extract user_id"""
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm]
            )
            user_id: int = payload.get("user_id")
            if user_id is None:
                return None
            return user_id
        except JWTError as e:
            logger.warning(f"Token verification failed: {e}")
            return None
    
    def calculate_user_risk(
        self,
        last_login_days: int,
        failed_attempts: int,
        is_mfa_enabled: bool
    ) -> float:
        """Calculate user risk score based on behavior"""
        risk = 0.0
        
        if last_login_days == 0:
            risk += 5
        elif last_login_days <= 7:
            risk += 10
        elif last_login_days <= 30:
            risk += 15
        else:
            risk += 30
        
        risk += min(failed_attempts * 8, 40)
        
        if is_mfa_enabled:
            risk -= 15
        
        return max(0, min(risk, 100))