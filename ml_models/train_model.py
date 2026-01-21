import numpy as np
import pandas as pd
from xgboost import XGBClassifier
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import joblib
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PolicyModelTrainer:
    """Trainer for Zero Trust Policy ML model"""
    
    def __init__(self):
        self.model = XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            random_state=42,
            objective='multi:softmax',
            num_class=3  # allow, challenge, deny
        )
        self.scaler = StandardScaler()
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
    
    def generate_synthetic_data(self, num_samples: int = 1000) -> tuple:
        """
        Generate synthetic training data for Zero Trust model
        
        Features:
        1. User Risk Score (0-100)
        2. Device Health Score (0-100)
        3. Time of Day Risk (0-100)
        4. Location Anomaly (0-100)
        5. Behavior Deviation (0-100)
        
        Labels:
        0 = allow
        1 = challenge
        2 = deny
        """
        logger.info(f"Generating {num_samples} synthetic samples...")
        
        X = []
        y = []
        
        for _ in range(num_samples):
            # Random features
            user_risk = np.random.uniform(0, 100)
            device_health = np.random.uniform(0, 100)
            time_risk = np.random.uniform(0, 100)
            location_anomaly = np.random.uniform(0, 100)
            behavior_dev = np.random.uniform(0, 100)
            
            # Calculate weighted risk
            total_risk = (
                (user_risk * 0.4) +
                (device_health * 0.35) +
                (location_anomaly * 0.25)
            )
            
            # Assign label based on risk
            if total_risk < 50:
                label = 0  # allow
            elif total_risk < 80:
                label = 1  # challenge
            else:
                label = 2  # deny
            
            X.append([user_risk, device_health, time_risk, location_anomaly, behavior_dev])
            y.append(label)
        
        return np.array(X), np.array(y)
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray) -> dict:
        """Train the policy model"""
        logger.info("Training policy model...")
        
        # Normalize features
        X_train_scaled = self.scaler.fit_transform(X_train)
        
        # Train model
        self.model.fit(X_train_scaled, y_train)
        
        logger.info("Policy model training completed!")
        
        return {
            "model": self.model,
            "scaler": self.scaler,
            "feature_names": [
                "user_risk_score",
                "device_health_score",
                "time_of_day_risk",
                "location_anomaly",
                "behavior_deviation"
            ]
        }
    
    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> dict:
        """Evaluate model performance"""
        X_test_scaled = self.scaler.transform(X_test)
        predictions = self.model.predict(X_test_scaled)
        
        metrics = {
            "accuracy": accuracy_score(y_test, predictions),
            "precision": precision_score(y_test, predictions, average='weighted'),
            "recall": recall_score(y_test, predictions, average='weighted'),
            "f1_score": f1_score(y_test, predictions, average='weighted')
        }
        
        logger.info(f"Model Metrics: {metrics}")
        return metrics
    
    def save_models(self, model_path: str, scaler_path: str):
        """Save trained models to disk"""
        joblib.dump(self.model, model_path)
        joblib.dump(self.scaler, scaler_path)
        logger.info(f"Models saved: {model_path}, {scaler_path}")
    
    def train_and_evaluate(self, num_samples: int = 1000):
        """End-to-end training and evaluation"""
        # Generate synthetic data
        X, y = self.generate_synthetic_data(num_samples)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train model
        self.train(X_train, y_train)
        
        # Evaluate model
        metrics = self.evaluate(X_test, y_test)
        
        # Save models
        self.save_models(
            "./ml_models/ztp_policy_model.pkl",
            "./ml_models/scaler.pkl"
        )
        
        return metrics

# Run training
if __name__ == "__main__":
    trainer = PolicyModelTrainer()
    metrics = trainer.train_and_evaluate(num_samples=1000)
    print(f"\nFinal Metrics:\n{metrics}")



# src/utils/logger.py

import logging
import json
from logging.handlers import RotatingFileHandler
from datetime import datetime

class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging"""
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        return json.dumps(log_data)

def setup_logging(log_level: str = "INFO", log_file: str = None):
    """Setup application logging"""
    
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level))
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, log_level))
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # File handler (if log file specified)
    if log_file:
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10485760,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(getattr(logging, log_level))
        file_formatter = JSONFormatter()
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)



# src/utils/exceptions.py

from fastapi import HTTPException, status

class AccessDeniedError(HTTPException):
    """Access denied exception"""
    def __init__(self, detail: str = "Access denied"):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail
        )

class DeviceNotTrustedError(HTTPException):
    """Device not trusted exception"""
    def __init__(self, detail: str = "Device is not trusted"):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail
        )

class HighRiskAccessError(HTTPException):
    """High risk access exception"""
    def __init__(self, risk_score: float):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied - Risk score {risk_score:.2f} exceeds threshold"
        )

class MFARequiredError(HTTPException):
    """MFA required exception"""
    def __init__(self, detail: str = "Multi-factor authentication required"):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail
        )



# src/utils/helpers.py

from datetime import datetime
from typing import Optional

def calculate_days_since(date: Optional[datetime]) -> int:
    """Calculate days since a given date"""
    if not date:
        return 999
    return (datetime.utcnow() - date).days

def is_business_hours(hour: int) -> bool:
    """Check if hour is during business hours"""
    return 9 <= hour <= 17

def get_risk_level(risk_score: float) -> str:
    """Get risk level from score"""
    if risk_score < 50:
        return "LOW"
    elif risk_score < 80:
        return "MEDIUM"
    else:
        return "HIGH"

def sanitize_input(value: str, max_length: int = 255) -> str:
    """Sanitize user input"""
    if not value:
        return ""
    # Remove special characters and limit length
    return value[:max_length].strip()