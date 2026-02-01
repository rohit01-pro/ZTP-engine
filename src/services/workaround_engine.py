class WorkaroundEngine:
    """Deploy temporary fixes until patch available"""
    
    def deploy_workarounds(self, zero_day_cve):
        """Deploy compensating controls specific to zero-day"""
        
        workarounds = {
            "TEMPORARY_DISABLE": {
                "vulnerability": "RCE in Feature X",
                "workaround": "Disable Feature X temporarily",
                "impact": "Some functionality lost, but system secure",
                "duration": "Until patch available"
            },
            
            "WAF_RULES": {
                "vulnerability": "Buffer overflow in API",
                "workaround": "Block requests >1000 bytes to API endpoint",
                "impact": "May block legitimate requests",
                "false_positive_rate": "2-5%"
            },
            
            "VIRTUAL_PATCHING": {
                "vulnerability": "SQL injection in login",
                "workaround": "Add WAF rule to block SQL keywords",
                "effectiveness": "70-80%",
                "risk": "Attackers may bypass"
            },
            
            "PROCESS_ISOLATION": {
                "vulnerability": "Privilege escalation",
                "workaround": "Run service in container with restricted privileges",
                "impact": "Even if exploited, damage limited",
                "deployment_time": "2-4 hours"
            },
            
            "NETWORK_SEGMENTATION": {
                "vulnerability": "Lateral movement after RCE",
                "workaround": "Isolate vulnerable systems from critical systems",
                "impact": "Limits blast radius",
                "deployment_time": "4-8 hours"
            }
        }
        
        return workarounds
