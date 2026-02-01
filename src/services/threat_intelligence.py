# New file: src/services/threat_intelligence.py

import requests
from datetime import datetime

class ThreatIntelligenceEngine:
    """Integrate with threat feeds to detect known exploits"""
    
    def __init__(self):
        self.threat_feeds = [
            "https://otx.alienvault.com/api/v1/pulses/subscribed",  # AlienVault
            "https://cve.mitre.org/data/downloads/",  # CVE Database
            "https://www.exploit-db.com/",  # Known exploits
        ]
        self.known_zero_days = self.load_known_zero_days()
    
    def load_known_zero_days(self):
        """Load recently disclosed zero-days"""
        return {
            "CVE-2025-0001": {
                "product": "Windows",
                "severity": "CRITICAL",
                "affected_versions": ["Windows 10", "Windows 11"],
                "exploit_available": False,  # Not exploited in the wild yet
                "mitigation": "Apply KB12345"
            },
            "CVE-2025-0002": {
                "product": "Apache",
                "severity": "HIGH",
                "affected_versions": ["2.4.49", "2.4.50"],
                "exploit_available": True,  # Being exploited
                "mitigation": "Upgrade to 2.4.51"
            }
        }
    
    def check_against_known_exploits(self, device_info):
        """Check if device matches known zero-day exploitation patterns"""
        
        matches = []
        
        for cve, details in self.known_zero_days.items():
            if device_info.get("os") == details["product"]:
                if device_info.get("version") in details["affected_versions"]:
                    matches.append({
                        "cve": cve,
                        "severity": details["severity"],
                        "exploit_in_wild": details["exploit_available"],
                        "mitigation": details["mitigation"]
                    })
        
        return matches
    
    def apply_virtual_patching(self, affected_cve):
        """Apply virtual patch (WAF rule) for known zero-day"""
        return {
            "type": "VIRTUAL_PATCH",
            "cve": affected_cve,
            "mechanism": "WAF_RULE",
            "example_rule": "ModSecurity rule that blocks exploitation pattern",
            "effectiveness": "70-80% (not 100%)"
        }
