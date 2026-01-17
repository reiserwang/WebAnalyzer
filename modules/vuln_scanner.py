import nmap
import logging
from typing import Dict, Any, List
import re

class VulnScanner:
    """
    A Nessus-like vulnerability scanner using Nmap NSE scripts.
    Also specializes in SNMP enumeration.
    """
    def __init__(self, target: str, safe_mode: bool = True, dont_scan: List[str] = None):
        self.target = target
        self.safe_mode = safe_mode
        self.dont_scan = dont_scan or []
        self.logger = logging.getLogger("VulnScanner")
        self.nm = nmap.PortScanner()

    def scan(self) -> Dict[str, Any]:
        """
        Run the scanner.
        """
        if self.target in self.dont_scan:
            return {"error": "Target is in exclusion list."}

        results = {
            "vulnerabilities": [],
            "snmp_info": {},
            "summary": {}
        }

        try:
            self.logger.info(f"Starting Vulnerability Scan for {self.target}")
            
            # 1. SNMP Enumeration (UDP 161)
            # We run this separately because it's UDP and specific
            snmp_args = "-sU -p 161 --script snmp-info,snmp-sysdescr,snmp-processes,snmp-win32-software"
            # Fast timeout for UDP to avoid hanging
            snmp_args += " --host-timeout 30s" 
            
            self.logger.info("Running SNMP Scan...")
            try:
                self.nm.scan(self.target, arguments=snmp_args)
                if self.target in self.nm.all_hosts() and 'udp' in self.nm[self.target]:
                    udp_data = self.nm[self.target]['udp']
                    if 161 in udp_data:
                        snmp_script_output = udp_data[161].get('script', {})
                        results["snmp_info"] = self._parse_snmp(snmp_script_output)
            except Exception as e:
                self.logger.error(f"SNMP Scan Error: {e}")

            # 2. General Vulnerability Scan (TCP)
            # --script vuln is heavy. In safe mode, we might limit it? 
            # Actually, user requested "Nessus like", so we need depth.
            # But we must respect safe_mode avoiding DoS scripts.
            # 'vuln' category includes some intrusive ones. 'safe and vuln' is safer.
            
            script_arg = "vuln"
            if self.safe_mode:
                script_arg = "(vuln) and not (DoS or intrusive)"
            
            # Using -sV is crucial for version detection which feeds 'vulners' script
            # We scan top 100 ports + detected ones? Or just top ports to save time.
            # A full port scan is too slow for a "quick" web view.
            # Let's target common ports + any arguments we might want to pass.
            # For now, top 100 ports.
            tcp_args = f"-sV --version-intensity 5 --script \"{script_arg}\" --top-ports 100"
            
            self.logger.info("Running Vuln Scan (TCP)...")
            self.nm.scan(self.target, arguments=tcp_args)
            
            if self.target in self.nm.all_hosts():
                host = self.nm[self.target]
                if 'tcp' in host:
                    for port, info in host['tcp'].items():
                        script_out = info.get('script', {})
                        # Parse known vuln scripts
                        self._parse_vulns(port, info, script_out, results["vulnerabilities"])

            # Sort vulnerabilities by severity
            severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
            results["vulnerabilities"].sort(key=lambda x: severity_order.get(x['severity'], 5))
            
            # Summary
            counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
            for v in results["vulnerabilities"]:
                s = v.get("severity", "Info")
                counts[s] = counts.get(s, 0) + 1
            results["summary"] = counts

        except Exception as e:
            self.logger.error(f"Vuln Scan Failed: {e}")
            return {"error": str(e)}

        return results

    def _parse_snmp(self, output: Dict[str, str]) -> Dict[str, str]:
        parsed = {}
        # snmp-sysdescr, snmp-info usually return raw text
        if 'snmp-sysdescr' in output:
            parsed['sysDescr'] = output['snmp-sysdescr'].strip()
        if 'snmp-info' in output:
            # Often contains Uptime, etc.
            parsed['details'] = output['snmp-info']
        if 'snmp-processes' in output:
            parsed['processes'] = output['snmp-processes']
        return parsed

    def _parse_vulns(self, port: int, service_info: dict, script_output: dict, vuln_list: list):
        """
        Parses output from scripts like 'vulners', 'vuln', etc.
        """
        service_name = service_info.get('name', 'unknown')
        
        for script_id, output in script_output.items():
            # Handle 'vulners' script (structured-ish text)
            if script_id == 'vulners':
                # Parse CVEs from vulners text
                # Format: match_name\tscore\tlink
                lines = output.split('\n')
                for line in lines:
                    if 'CVE-' in line:
                         parts = line.split()
                         if len(parts) >= 2:
                             cve_id = next((p for p in parts if 'CVE-' in p), 'Unknown')
                             score = 0.0
                             try:
                                 score = float(next((p for p in parts if p.replace('.','').isdigit()), 0))
                             except: pass
                             
                             severity = "Info"
                             if score >= 9.0: severity = "Critical"
                             elif score >= 7.0: severity = "High"
                             elif score >= 4.0: severity = "Medium"
                             elif score > 0: severity = "Low"
                             
                             vuln_list.append({
                                 "severity": severity,
                                 "title": f"{cve_id} on {service_name}",
                                 "description": f"Found via Vulners on port {port}. Score: {score}",
                                 "cve": cve_id,
                                 "port": port,
                                 "service": service_name
                             })
            
            # Handle other generic vuln scripts
            elif 'vuln' in script_id or 'cve' in script_id:
                # Naive Severity based on output keywords
                severity = "Medium" # Default
                if "RCE" in output or "Remote Code Execution" in output: severity = "Critical"
                elif "SQL Injection" in output: severity = "High"
                
                vuln_list.append({
                    "severity": severity,
                    "title": f"Potential {script_id} on {service_name}",
                    "description": output[:200] + "..." if len(output) > 200 else output,
                    "port": port,
                    "service": service_name
                })
