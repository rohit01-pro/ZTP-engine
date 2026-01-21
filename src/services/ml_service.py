import numpy as np
import joblib
from typing import Dict, Tuple
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import logging

logger = logging.getLogger(__name__)

class MLPolicyEngine:
    """Machine Learning based policy decision engine"""
    
    def __init__(self, model_path: str):
        """Initialize ML engine with trained model"""
        try:
            self.model = joblib.load(model_path)
            self.scaler = StandardScaler()
            logger.info("ML model loaded successfully")
        except:
            logger.warning("Model not found, using default heuristics")
            self.model = None
        
        # Anomaly detection model
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.is_trained = False
    
    def extract_features(self, access_data: Dict) -> np.ndarray:
        """
        Extract features from access request for ML model
        
        Features:
        1. User risk score (0-100)
        2. Device health score (0-100)
        3. Time of day risk (0-100)
        4. Location anomaly (0-100)
        5. Behavior deviation (0-100)
        """
        features = [
            access_data.get("user_risk_score", 50),
            access_data.get("device_health_score", 50),
            access_data.get("time_of_day_risk", 30),
            access_data.get("location_anomaly", 40),
            access_data.get("behavior_deviation", 35),
        ]
        return np.array(features).reshape(1, -1)
    
    def predict_access_decision(self, access_data: Dict) -> Tuple[str, float]:
        """
        Predict access decision using ML model
        
        Returns:
            Tuple of (decision, confidence)
            decision: "allow", "challenge", or "deny"
            confidence: 0.0 to 1.0
        """
        features = self.extract_features(access_data)
        
        if self.model is None:
            # Fallback to heuristic decision
            total_risk = (
                access_data.get("user_risk_score", 50) * 0.4 +
                access_data.get("device_health_score", 50) * 0.35 +
                access_data.get("context_risk_score", 50) * 0.25
            )
        else:
            try:
                # Use ML model for prediction
                prediction = self.model.predict(features)[0]
                total_risk = prediction * 100  # Scale to 0-100
            except Exception as e:
                logger.error(f"ML prediction error: {e}")
                total_risk = 50
        
        # Decision logic based on risk score
        if total_risk < 50:
            decision = "allow"
            confidence = 1 - (total_risk / 100)
        elif total_risk < 80:
            decision = "challenge"
            confidence = 0.7
        else:
            decision = "deny"
            confidence = 1 - ((total_risk - 80) / 20)
        
        return decision, confidence
    
    def detect_anomaly(self, behavior_vector: np.ndarray) -> bool:
        """
        Detect if behavior is anomalous using Isolation Forest
        
        Args:
            behavior_vector: User behavior features
        
        Returns:
            True if anomaly detected, False otherwise
        """
        if not self.is_trained:
            return False
        
        try:
            prediction = self.anomaly_detector.predict(behavior_vector)
            return prediction[0] == -1  # -1 indicates anomaly
        except Exception as e:
            logger.error(f"Anomaly detection error: {e}")
            return False
    
    def calculate_risk_score(
        self,
        user_risk: float,
        device_risk: float,
        context_risk: float
    ) -> float:
        """
        Calculate total risk score using weighted formula
        
        Formula: Total Risk = (User Risk × 0.4) + (Device Risk × 0.35) + (Context Risk × 0.25)
        """
        total_risk = (
            (user_risk * 0.4) +
            (device_risk * 0.35) +
            (context_risk * 0.25)
        )
        return min(max(total_risk, 0), 100)  # Clamp to 0-100
    
    def train_on_data(self, X_train: np.ndarray, y_train: np.ndarray):
        """Train anomaly detector on historical behavior data"""
        try:
            self.anomaly_detector.fit(X_train)
            self.is_trained = True
            logger.info("Anomaly detector trained successfully")
        except Exception as e:
            logger.error(f"Training error: {e}")



# src/services/device_health_service.py

from typing import Dict
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class DeviceHealthService:
    """Service for calculating device health scores"""
    
    def __init__(self):
        """Initialize device health assessment criteria"""
        self.criteria = {
            "os_security": 0.25,
            "antivirus": 0.25,
            "firewall": 0.20,
            "encryption": 0.15,
            "patches": 0.15,
        }
    
    def calculate_health_score(self, device_data: Dict) -> float:
        """
        Calculate overall device health score (0-100)
        
        Factors:
        - OS security patches
        - Antivirus status
        - Firewall status
        - Disk encryption
        - Last patch date
        """
        scores = {}
        
        # OS Security Score (0-100)
        scores["os_security"] = device_data.get("os_security_score", 60)
        
        # Antivirus Score
        scores["antivirus"] = 100 if device_data.get("antivirus_enabled") else 30
        
        # Firewall Score
        scores["firewall"] = 100 if device_data.get("firewall_enabled") else 40
        
        # Encryption Score
        scores["encryption"] = 100 if device_data.get("disk_encrypted") else 50
        
        # Patch Score based on days since last patch
        last_patch = device_data.get("last_patch_date")
        if last_patch:
            days_since_patch = (datetime.utcnow() - last_patch).days
            if days_since_patch <= 7:
                scores["patches"] = 100
            elif days_since_patch <= 30:
                scores["patches"] = 80
            elif days_since_patch <= 60:
                scores["patches"] = 50
            else:
                scores["patches"] = 20
        else:
            scores["patches"] = 30
        
        # Weighted calculation
        health_score = sum(
            scores[key] * self.criteria[key]
            for key in self.criteria
        )
        
        logger.info(f"Device health score calculated: {health_score:.2f}")
        return round(health_score, 2)
    
    def calculate_device_risk(self, health_score: float) -> float:
        """
        Convert health score to risk score
        Higher health = Lower risk
        
        Risk = 100 - HealthScore
        """
        return max(0, min(100 - health_score, 100))
    
    def get_device_status(self, device_data: Dict) -> Dict:
        """Get comprehensive device status"""
        health_score = self.calculate_health_score(device_data)
        risk_score = self.calculate_device_risk(health_score)
        
        status = {
            "health_score": health_score,
            "risk_score": risk_score,
            "is_healthy": health_score >= 70,
            "issues": self._identify_issues(device_data),
            "recommendations": self._get_recommendations(device_data)
        }
        
        return status
    
    def _identify_issues(self, device_data: Dict) -> list:
        """Identify device security issues"""
        issues = []
        
        if not device_data.get("antivirus_enabled"):
            issues.append("Antivirus not enabled")
        
        if not device_data.get("firewall_enabled"):
            issues.append("Firewall not enabled")
        
        if not device_data.get("disk_encrypted"):
            issues.append("Disk not encrypted")
        
        last_patch = device_data.get("last_patch_date")
        if last_patch and (datetime.utcnow() - last_patch).days > 30:
            issues.append("OS patches outdated")
        
        return issues
    
    def _get_recommendations(self, device_data: Dict) -> list:
        """Get security recommendations"""
        recommendations = []
        
        if not device_data.get("antivirus_enabled"):
            recommendations.append("Enable antivirus software")
        
        if not device_data.get("firewall_enabled"):
            recommendations.append("Enable firewall protection")
        
        if not device_data.get("disk_encrypted"):
            recommendations.append("Enable full disk encryption")
        
        last_patch = device_data.get("last_patch_date")
        if not last_patch or (datetime.utcnow() - last_patch).days > 7:
            recommendations.append("Apply latest OS patches")
        
        return recommendations



# src/services/identity_service.py

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
        """
        Create JWT access token
        
        Returns:
            Tuple of (token, expires_at)
        """
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
        """
        Verify JWT token and extract user_id
        
        Returns:
            user_id if token is valid, None otherwise
        """
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
        """
        Calculate user risk score based on behavior
        
        Factors:
        - Last login (recent logins = lower risk)
        - Failed login attempts (more failures = higher risk)
        - MFA status (enabled = lower risk)
        """
        risk = 0.0
        
        # Last login risk (0-30 points)
        if last_login_days == 0:
            risk += 5
        elif last_login_days <= 7:
            risk += 10
        elif last_login_days <= 30:
            risk += 15
        else:
            risk += 30
        
        # Failed attempts risk (0-40 points)
        risk += min(failed_attempts * 8, 40)
        
        # MFA bonus (-15 points)
        if is_mfa_enabled:
            risk -= 15
        
        return max(0, min(risk, 100))