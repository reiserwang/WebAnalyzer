import logging
import asyncio
import os
from typing import Dict, Any, List

class MSFDeepScanner:
    """
    Orchestrates targeted Metasploit Auxiliary scans based on detected technologies.
    """
    def __init__(self, target):
        self.target = target
        self.logger = logging.getLogger("MSFDeepScan")
        
        # Technology -> Module mapping
        self.rules = {
            "WordPress": [
                {"module": "auxiliary/scanner/http/wordpress_login_enum", "options": {"UserFile": "", "PassFile": "", "STOP_ON_SUCCESS": True}},
                {"module": "auxiliary/scanner/http/wordpress_scanner", "options": {}}
            ],
            "Jenkins": [
                {"module": "auxiliary/scanner/http/jenkins_enum", "options": {}}
            ],
            "Tomcat": [
                {"module": "auxiliary/scanner/http/tomcat_mgr_login", "options": {"STOP_ON_SUCCESS": True}}
            ],
            "SMB": [
                {"module": "auxiliary/scanner/smb/smb_version", "options": {}},
                {"module": "auxiliary/scanner/smb/smb_enumshares", "options": {}}
            ],
            "SSH": [
                {"module": "auxiliary/scanner/ssh/ssh_version", "options": {}}
            ]
        }
        
        # High Profile CVEs
        self.cve_sweeps = {
            "Log4Shell": {"module": "auxiliary/scanner/http/log4shell_scanner", "options": {"HTTP_METHOD": "HEAD"}},
            "BlueKeep": {"module": "auxiliary/scanner/rdp/cve_2019_0708_bluekeep", "options": {}},
            "EternalBlue": {"module": "auxiliary/scanner/smb/smb_ms17_010", "options": {}}
        }

        # SSL/TLS Analysis
        self.ssl_scans = {
            "Heartbleed": {"module": "auxiliary/scanner/ssl/openssl_heartbleed", "options": {}},
            "CCS Injection": {"module": "auxiliary/scanner/ssl/openssl_ccs", "options": {}}
        }

    def scan(self, technologies: List[str] = [], run_cve_sweeps: bool = True, run_ssl_analysis: bool = True) -> Dict[str, Any]:
        """
        Run relevant auxiliary modules.
        """
        results = {
            "tech_scans": {},
            "cve_sweeps": {},
            "ssl_analysis": {},
            "errors": []
        }
        
        try:
             # Check if pymetasploit3 is available and configure credentials
            from pymetasploit3.msfrpc import MsfRpcClient
            
            MSF_PASSWORD = os.getenv("MSF_PASSWORD", "toor")
            MSF_HOST = os.getenv("MSF_HOST", "127.0.0.1")
            MSF_PORT = int(os.getenv("MSF_PORT", 55553))
            
            try:
                client = MsfRpcClient(MSF_PASSWORD, host=MSF_HOST, port=MSF_PORT, ssl=True)
            except Exception as e:
                return {"error": "Metasploit RPC not connected. Start msfrpcd first."}

            # 1. Tech Specific Scans
            for tech in technologies:
                # Basic fuzzy match
                matched_rules = []
                for key in self.rules:
                    if key.lower() in tech.lower():
                        matched_rules.extend(self.rules[key])
                
                if matched_rules:
                    results["tech_scans"][tech] = self._run_batch(client, matched_rules)

            # 2. CVE Sweeps
            if run_cve_sweeps:
                for cve_name, config in self.cve_sweeps.items():
                    # We only run these if relevant ports/services might be open, but for "Deep Scan" we might try anyway
                    # assuming the user knows what they are doing.
                    # RHOSTS needs to be set
                    config['options']['RHOSTS'] = self.target
                    
                    cid = client.consoles.console().cid
                    # Running scan synchronously-ish via console or module execution
                    # Using module execution is better
                    res = self._execute_single(client, config['module'], config['options'])
                    results["cve_sweeps"][cve_name] = res

            # 3. SSL/TLS Analysis
            if run_ssl_analysis:
                for scan_name, config in self.ssl_scans.items():
                    config['options']['RHOSTS'] = self.target
                    # Ensure port is set to 443 by default if needed, or module default
                    # Most defaults are 443
                    res = self._execute_single(client, config['module'], config['options'])
                    results["ssl_analysis"][scan_name] = res

        except ImportError:
             return {"error": "pymetasploit3 not installed"}
        except Exception as e:
            self.logger.error(f"Deep Scan error: {e}")
            results["errors"].append(str(e))
            
        return results

    def _run_batch(self, client, rules):
        batch_res = []
        for rule in rules:
            rule['options']['RHOSTS'] = self.target
            res = self._execute_single(client, rule['module'], rule['options'])
            batch_res.append(res)
        return batch_res

    def _execute_single(self, client, module_path, options):
        try:
            mod_type = module_path.split('/')[0]
            mod_name = '/'.join(module_path.split('/')[1:])
            module = client.modules.use(mod_type, mod_name)
            
            # For auxiliary scanners, 'run' typically returns specific data or prints to console
            # capturing output via RPC is tricky without reading console
            # But module.execute returns a job ID.
            
            job_id = module.execute(payload=options)
            
            # In a real async system we'd poll the job
            # For this prototype, we return the Job ID initiated
            return {"module": module_path, "status": "started", "job_id": job_id}
        except Exception as e:
            return {"module": module_path, "status": "error", "error": str(e)}

    def check_job_status(self, job_id: str) -> Dict[str, Any]:
        """
        Queries Metasploit RPC for the status of a specific job.
        """
        try:
             # Check if pymetasploit3 is available and configure credentials
            from pymetasploit3.msfrpc import MsfRpcClient
            
            MSF_PASSWORD = os.getenv("MSF_PASSWORD", "toor")
            MSF_HOST = os.getenv("MSF_HOST", "127.0.0.1")
            MSF_PORT = int(os.getenv("MSF_PORT", 55553))
            
            client = MsfRpcClient(MSF_PASSWORD, host=MSF_HOST, port=MSF_PORT, ssl=True)
            
            # List jobs to see if it's running
            jobs = client.jobs.list
            if str(job_id) in jobs:
                return {"status": "running", "job_id": job_id, "details": jobs[str(job_id)]}
            else:
                # If not in list, it finished (or never existed/error)
                # We can't easily get the exit status/result from basic RPC for auxiliary modules
                # without digging into sessions or console logs. 
                # For now, "completed" is a safe assumption if we knew it started.
                return {"status": "completed", "job_id": job_id}

        except Exception as e:
            return {"status": "error", "error": str(e)}
