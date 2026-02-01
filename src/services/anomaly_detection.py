# Add behavioral analysis to your ZTP-Engine
# Detect UNUSUAL activity that might indicate zero-day exploitation

import json
from datetime import datetime, timedelta

class AnomalyDetector:
    """Detect suspicious behavior that might indicate zero-day exploitation"""
    
    def __init__(self):
        self.baseline = {}
        self.alerts = []
    
    def detect_unusual_access(self, user_id, access_request):
        """Detect abnormal access patterns"""
        
        anomalies = []
        
        # 1. RAPID REPEATED FAILURES
        # Example: Check if more than 5 failed attempts occurred within the last 10 minutes
        failed_attempts = access_request.get("failed_attempts", 0)
        last_failed_time = access_request.get("last_failed_time")  # should be a datetime object
        if failed_attempts > 5 and last_failed_time:
            if datetime.now() - last_failed_time <= timedelta(minutes=10):
                anomalies.append({
                    "type": "RAPID_FAILURES",
                    "severity": "HIGH",
                    "reason": "Multiple failed login attempts detected"
                })
        
        # 2. BULK DATA EXPORT (Common zero-day exploitation)
        if access_request.get("data_volume_mb", 0) > 100:
            anomalies.append({
                "type": "BULK_EXPORT",
                "severity": "CRITICAL",
                "reason": "Unusual large data transfer detected"
            })
        
        # 3. PROCESS EXECUTION (Malware indicator)
        if access_request.get("process_execution"):
            anomalies.append({
                "type": "SUSPICIOUS_PROCESS",
                "severity": "CRITICAL",
                "reason": "Unusual process execution detected"
            })
        
        # 4. MEMORY INJECTION (Zero-day exploitation technique)
        if access_request.get("memory_injection_detected"):
            anomalies.append({
                "type": "MEMORY_INJECTION",
                "severity": "CRITICAL",
                "reason": "Potential code injection attack detected"
            })
        
        # 5. PRIVILEGE ESCALATION (Post-exploitation indicator)
        if access_request.get("privilege_elevation_requested"):
            anomalies.append({
                "type": "PRIV_ESCALATION",
                "severity": "CRITICAL",
                "reason": "Unusual privilege escalation attempt"
            })
        
        return anomalies
    
    def detect_network_anomalies(self, access_request):
        """Detect network-level indicators of compromise (IoC)"""
        
        anomalies = []
        
        # 1. UNUSUAL PORTS
        if access_request.get("port") not in [80, 443, 8000, 3306]:
            anomalies.append({
                "type": "UNUSUAL_PORT",
                "severity": "MEDIUM",
                "port": access_request.get("port")
            })
        
        # 2. KNOWN MALICIOUS IPs
        malicious_ips = self.load_threat_intel()
        if access_request.get("ip_address") in malicious_ips:
            anomalies.append({
                "type": "MALICIOUS_IP",
                "severity": "CRITICAL",
                "ip": access_request.get("ip_address")
            })
        
        # 3. DATA EXFILTRATION PATTERNS
        if access_request.get("unusual_outbound_traffic"):
            anomalies.append({
                "type": "DATA_EXFILTRATION",
                "severity": "CRITICAL",
                "reason": "Suspicious outbound traffic detected"
            })
        
        return anomalies
    
    def load_threat_intel(self):
        """Load threat intelligence (IPs, domains, file hashes)"""
        # In production: Load from OSINT feeds
        # ✅ AlienVault OTX
        # ✅ MISP
        # ✅ Threat Stream
        return set()
