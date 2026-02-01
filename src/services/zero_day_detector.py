import json
from datetime import datetime, timedelta
from collections import defaultdict

class ZeroDayDetector:
    """Detect zero-day exploitation in real-time"""
    
    def __init__(self):
        self.suspicious_activity_log = defaultdict(list)
        self.threshold_alerts = []
    
    def detect_exploitation_patterns(self, access_log):
        """Detect common exploitation signatures"""
        
        red_flags = []
        
        # RED FLAG 1: ABNORMAL RESOURCE ACCESS
        if self.detect_abnormal_resource_access(access_log):
            red_flags.append({
                "type": "ABNORMAL_RESOURCE_ACCESS",
                "severity": "CRITICAL",
                "description": "Accessing resources normally not accessed by this user",
                "examples": [
                    "Regular user accessing /admin",
                    "Employee accessing /finance",
                    "Regular user reading /etc/passwd"
                ]
            })
        
        # RED FLAG 2: PRIVILEGE ESCALATION
        if self.detect_privilege_escalation(access_log):
            red_flags.append({
                "type": "PRIVILEGE_ESCALATION",
                "severity": "CRITICAL",
                "description": "User attempting to elevate privileges",
                "indicator": "User: regular → Admin privileges"
            })
        
        # RED FLAG 3: RAPID FILE/DATA ACCESS
        if self.detect_rapid_data_access(access_log):
            red_flags.append({
                "type": "BULK_DATA_ACCESS",
                "severity": "CRITICAL",
                "description": "Abnormally high data access in short time",
                "normal_rate": "100 files/hour",
                "detected_rate": "1000 files/minute"
            })
        
        # RED FLAG 4: PROCESS EXECUTION
        if self.detect_process_execution(access_log):
            red_flags.append({
                "type": "PROCESS_EXECUTION",
                "severity": "CRITICAL",
                "description": "Suspicious process launched",
                "examples": [
                    "cmd.exe spawned by web service",
                    "powershell from Excel",
                    "Unknown .exe execution"
                ]
            })
        
        # RED FLAG 5: NETWORK ACTIVITY
        if self.detect_suspicious_network(access_log):
            red_flags.append({
                "type": "SUSPICIOUS_NETWORK",
                "severity": "HIGH",
                "description": "Unusual outbound connections",
                "examples": [
                    "Connection to known C2 server",
                    "Unusual port usage",
                    "Data exfiltration"
                ]
            })
        
        # RED FLAG 6: MEMORY CORRUPTION
        if self.detect_memory_anomaly(access_log):
            red_flags.append({
                "type": "MEMORY_ANOMALY",
                "severity": "CRITICAL",
                "description": "Memory access patterns indicating exploitation",
                "technique": "Buffer overflow / Code injection"
            })
        
        # RED FLAG 7: TIMING ANOMALIES
        if self.detect_timing_anomaly(access_log):
            red_flags.append({
                "type": "TIMING_ANOMALY",
                "severity": "HIGH",
                "description": "Activity at unusual times",
                "examples": [
                    "Critical file access at 3 AM",
                    "Database export on weekend"
                ]
            })
        
        return red_flags
    
    def detect_abnormal_resource_access(self, log):
        """Check if user accessing resources they shouldn't"""
        user_id = log.get("user_id")
        resource = log.get("resource")
        
        # Known baseline: what resources does this user normally access?
        normal_resources = {
            "developer": ["code_repo", "test_db", "logs"],
            "accountant": ["financial_reports", "invoices"],
            "customer_support": ["customer_db", "tickets"],
            "admin": ["all_resources"]
        }
        
        user_role = log.get("user_role")
        if resource not in normal_resources.get(user_role, []):
            return True
        return False
    
    def detect_privilege_escalation(self, log):
        """Detect sudden privilege elevation"""
        # Compare: was user admin 5 minutes ago?
        was_admin_before = log.get("was_admin_5min_ago", False)
        is_admin_now = log.get("is_admin_now", False)
        
        if not was_admin_before and is_admin_now:
            return True
        return False
    
    def detect_rapid_data_access(self, log):
        """Detect bulk data exfiltration"""
        access_rate = log.get("files_accessed_per_minute", 0)
        normal_rate = 10  # Normal: ~10 files/min
        
        if access_rate > (normal_rate * 5):  # >5x normal
            return True
        return False
    
    def detect_process_execution(self, log):
        """Detect suspicious process spawning"""
        process = log.get("process_name")
        parent_process = log.get("parent_process")
        
        # Known suspicious combinations
        suspicious_combos = [
            ("cmd.exe", "w3wp.exe"),  # Web server spawning cmd
            ("powershell.exe", "excel.exe"),  # Excel spawning PS
            ("cmd.exe", "outlook.exe"),  # Email spawning cmd
        ]
        
        if (process, parent_process) in suspicious_combos:
            return True
        return False
    
    def detect_suspicious_network(self, log):
        """Detect C2 communication or data exfil"""
        ip = log.get("destination_ip")
        port = log.get("destination_port")
        data_volume = log.get("data_volume_mb", 0)
        
        # Known C2 IPs (would be updated from threat intel)
        known_c2_ips = set()  # Load from threat intelligence
        
        if ip in known_c2_ips:
            return True
        
        # Unusual ports
        if port > 50000 and data_volume > 100:  # High port + large transfer
            return True
        
        return False
    
    def detect_memory_anomaly(self, log):
        """Detect buffer overflow or injection attempts"""
        memory_access_pattern = log.get("memory_access_pattern")
        
        # Known exploitation patterns
        patterns = [
            "stack_overflow",
            "heap_corruption",
            "code_injection",
            "return_oriented_programming"
        ]
        
        if memory_access_pattern in patterns:
            return True
        return False
    
    def detect_timing_anomaly(self, log):
        """Detect access at unusual times"""
        import pytz
        from datetime import datetime
        
        timestamp = log.get("timestamp")
        user_timezone = log.get("user_timezone", "UTC")
        
        dt = datetime.fromisoformat(timestamp)
        hour = dt.hour
        
        # For developers: normal 9-17, abnormal 23-07
        normal_hours = list(range(9, 18))  # 9 AM - 5 PM
        
        if hour not in normal_hours:
            return True
        return False
