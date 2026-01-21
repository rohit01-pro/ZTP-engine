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
        """Calculate overall device health score (0-100)"""
        scores = {}
        
        scores["os_security"] = device_data.get("os_security_score", 60)
        scores["antivirus"] = 100 if device_data.get("antivirus_enabled") else 30
        scores["firewall"] = 100 if device_data.get("firewall_enabled") else 40
        scores["encryption"] = 100 if device_data.get("disk_encrypted") else 50
        
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
        
        health_score = sum(
            scores[key] * self.criteria[key]
            for key in self.criteria
        )
        
        logger.info(f"Device health score calculated: {health_score:.2f}")
        return round(health_score, 2)
    
    def calculate_device_risk(self, health_score: float) -> float:
        """Convert health score to risk score"""
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