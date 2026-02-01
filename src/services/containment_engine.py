class ContainmentEngine:
    """Prevent zero-day from spreading to other systems"""
    
    def __init__(self):
        self.blocked_ips = set()
        self.blocked_processes = set()
        self.blocked_behaviors = set()
    
    def implement_compensating_controls(self, zero_day_info):
        """Deploy workarounds until patch available"""
        
        controls = {
            "NETWORK_LEVEL": [
                {
                    "type": "WAF_RULE",
                    "description": "Block known exploit requests at firewall",
                    "example": "Block requests containing buffer overflow pattern",
                    "effectiveness": "60-70%"
                },
                {
                    "type": "EGRESS_FILTERING",
                    "description": "Block C2 communication channels",
                    "action": "Block outbound to known C2 IPs/domains",
                    "effectiveness": "80-90%"
                }
            ],
            
            "HOST_LEVEL": [
                {
                    "type": "PROCESS_MONITORING",
                    "description": "Kill suspicious processes immediately",
                    "example": "cmd.exe spawned by web server = AUTO KILL",
                    "effectiveness": "70-80%"
                },
                {
                    "type": "FILE_INTEGRITY_MONITORING",
                    "description": "Detect unauthorized file changes",
                    "effect": "Detect if exploit modifies system files",
                    "effectiveness": "80-90%"
                },
                {
                    "type": "DISABLE_FEATURE",
                    "description": "Disable vulnerable feature temporarily",
                    "example": "If RCE in feature X, disable feature X",
                    "effectiveness": "90-95%"
                }
            ],
            
            "APPLICATION_LEVEL": [
                {
                    "type": "INPUT_VALIDATION",
                    "description": "Strict input validation in vulnerable code path",
                    "effectiveness": "60-70%"
                },
                {
                    "type": "MEMORY_PROTECTION",
                    "description": "Enable DEP, ASLR, stack canaries",
                    "effectiveness": "40-60%"
                }
            ],
            
            "ACCESS_CONTROL": [
                {
                    "type": "PRIVILEGE_RESTRICTION",
                    "description": "Run service as unprivileged user",
                    "effect": "Even if exploited, attacker has limited access",
                    "effectiveness": "70-80%"
                },
                {
                    "type": "RESOURCE_ISOLATION",
                    "description": "Use containers/VMs to isolate vulnerable service",
                    "effectiveness": "80-90%"
                }
            ]
        }
        
        return controls
    
    def implement_threat_hunting(self):
        """Proactively search for exploitation signs"""
        
        hunt_queries = {
            "PROCESS_EXECUTION": """
                SELECT * FROM process_logs 
                WHERE parent_process IN ('w3wp.exe', 'apache', 'nginx')
                AND child_process IN ('cmd.exe', 'powershell.exe', 'bash')
                AND timestamp > NOW() - INTERVAL 1 DAY
            """,
            
            "FILE_ACCESS": """
                SELECT * FROM file_access_logs
                WHERE username NOT IN (select_normal_users)
                AND file_accessed IN ('/etc/passwd', 'C:\\Windows\\System32\\...')
                AND timestamp > NOW() - INTERVAL 1 DAY
            """,
            
            "NETWORK_CONNECTIONS": """
                SELECT * FROM network_logs
                WHERE destination_ip IN (select_known_c2_ips)
                OR destination_port > 50000
                AND data_volume > 100 MB
                AND timestamp > NOW() - INTERVAL 1 DAY
            """,
            
            "PRIVILEGE_CHANGES": """
                SELECT * FROM auth_logs
                WHERE privilege_before='user' AND privilege_after='admin'
                AND timestamp > NOW() - INTERVAL 1 DAY
            """
        }
        
        return hunt_queries
