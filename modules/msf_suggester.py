import json
import logging
import os

class MetasploitSuggester:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        # Basic mapping database: Technology/Service -> [MSF Modules]
        # In a real scenario, this would be a larger DB or queried from an external source.
        self.tech_mapping = {
            "Apache Tomcat": ["exploit/multi/http/tomcat_mgr_upload", "exploit/multi/http/tomcat_jsp_upload_bypass"],
            "Apache Struts": ["exploit/multi/http/struts2_content_type_ognl", "exploit/multi/http/struts2_rest_xstream"],
            "WordPress": ["exploit/unix/webapp/wp_admin_shell_upload", "auxiliary/scanner/http/wordpress_login_enum"],
            "Joomla": ["exploit/unix/webapp/joomla_comfields_sqli_rce"],
            "Drupal": ["exploit/unix/webapp/drupal_drupalgeddon2"],
            "WebLogic": ["exploit/multi/http/oracle_weblogic_wls_security_component_cpu_jan_2018"],
            "Jenkins": ["exploit/linux/http/jenkins_script_console"],
            "PHP": ["exploit/multi/http/php_cgi_arg_injection"],
            "SMB": ["exploit/windows/smb/ms17_010_eternalblue"],
            "FTP": ["exploit/unix/ftp/vsftpd_234_backdoor"],
            "SSH": ["auxiliary/scanner/ssh/ssh_login"]
        }
        
        # CVE -> MSF Module mapping
        self.cve_mapping = {
            "CVE-2017-5638": "exploit/multi/http/struts2_content_type_ognl",
            "CVE-2017-0144": "exploit/windows/smb/ms17_010_eternalblue",
            "CVE-2018-7600": "exploit/unix/webapp/drupal_drupalgeddon2",
            "CVE-2021-44228": "exploit/multi/http/log4shell_header_injection"
        }

    def suggest(self, scan_results):
        """
        Analyze scan results and suggest Metasploit modules.
        
        Args:
            scan_results (dict): The complete results dictionary from the scanner.
        """
        suggestions = []
        
        # 1. Analyze Detected Technologies
        if "Web Technologies" in scan_results:
            techs = scan_results["Web Technologies"]
            # Techs can be a dict (from Wappalyzer/custom)
            if isinstance(techs, dict):
                for category, name in techs.items():
                    # Check if name is in our mapping
                     if isinstance(name, str):
                         self._check_tech_match(name, suggestions)
                     elif isinstance(name, list):
                         for n in name:
                             self._check_tech_match(n, suggestions)

        # 2. Analyze Detected CVEs (from Nmap Zero Day)
        if "Nmap Zero Day Scan" in scan_results:
            nmap_res = scan_results["Nmap Zero Day Scan"]
            if "zero_day_vulnerabilities" in nmap_res:
                for vuln in nmap_res["zero_day_vulnerabilities"]:
                    vuln_id = vuln.get('id')
                    if vuln_id in self.cve_mapping:
                        suggestions.append({
                            "type": "CVE Match (High Confidence)",
                            "indicator": vuln_id,
                            "module": self.cve_mapping[vuln_id],
                            "description": f"Direct mapping for {vuln_id}"
                        })

        # 3. Analyze Services (from Nmap)
        if "Nmap Zero Day Scan" in scan_results:
             nmap_res = scan_results["Nmap Zero Day Scan"]
             if "port_scan" in nmap_res and "services" in nmap_res["port_scan"]:
                 services = nmap_res["port_scan"]["services"]
                 for port, info in services.items():
                     service_name = info.get('service')
                     if service_name:
                         # Basic service mapping (e.g., 'ssh' -> ssh scanner)
                         for key in self.tech_mapping:
                             if key.lower() in service_name.lower():
                                 for mod in self.tech_mapping[key]:
                                     # Avoid duplicates
                                     if not any(s['module'] == mod for s in suggestions):
                                         suggestions.append({
                                             "type": "Service Match",
                                             "indicator": f"Port {port} ({service_name})",
                                             "module": mod,
                                             "description": f"Standard module for {service_name}"
                                         })

        return suggestions

    async def execute_module(self, module_path, options, action='execute', safe_mode=True, dont_scan=None):
        """
        Attempts to execute a Metasploit module via RPC.
        Supports 'execute' (default) and 'check'.
        """
        try:
            # Check if pymetasploit3 is available and configure credentials
            from pymetasploit3.msfrpc import MsfRpcClient
            
            # Ensure environment variables are set
            MSF_PASSWORD = os.getenv("MSF_PASSWORD")
            MSF_HOST = os.getenv("MSF_HOST")
            MSF_PORT = os.getenv("MSF_PORT")

            if not all([MSF_PASSWORD, MSF_HOST, MSF_PORT]):
                return {"status": "error", "message": "Metasploit RPC credentials (MSF_PASSWORD, MSF_HOST, MSF_PORT) are not set."}

            # Check if target is in the 'do not scan' list
            rhosts = options.get("RHOSTS")
            if dont_scan and rhosts and rhosts in dont_scan:
                return {"status": "skipped", "message": f"Target {rhosts} is in the 'do not scan' list."}

            # In safe mode, only allow auxiliary modules
            if safe_mode and 'exploit/' in module_path:
                return {"status": "skipped", "message": f"Module {module_path} is an exploit and cannot be run in safe mode."}

            try:
                client = MsfRpcClient(MSF_PASSWORD, host=MSF_HOST, port=int(MSF_PORT), ssl=True)
                
                # Determine module type (exploit, auxiliary, etc.)
                mod_type = module_path.split('/')[0]
                mod_name = '/'.join(module_path.split('/')[1:])
                
                module = client.modules.use(mod_type, mod_name)
                
                if action == 'check':
                    # Only exploits usually have a 'check' method exposed directly in some RPC versions
                    # or via 'check' command in console. pymetasploit3 might expose it via module.check()
                    # if the module supports it.
                    if hasattr(module, 'check'):
                        result = module.check()
                        return {"status": "checked", "result": result, "module": module_path}
                    else:
                        # Fallback: try to execute with 'CheckModule' option if available or custom logic
                        # But for now, let's treat it as not supported if method missing
                        return {"status": "error", "message": f"Module {module_path} does not support check mode via RPC."}
                
                # Default Execute (Exploit/Run)
                job_id = module.execute(payload=options)
                return {"status": "started", "job_id": job_id, "module": module_path}
                
            except Exception as e:
                self.logger.error(f"MSF RPC Connection Failed: {e}")
                return {"status": "error", "message": "Could not connect to Metasploit RPC service. Ensure msfrpcd is running."}
                
        except ImportError:
            return {"status": "error", "message": "pymetasploit3 library not installed"}
            
    def _check_tech_match(self, tech_name, suggestions):
        for key, modules in self.tech_mapping.items():
            if key.lower() in tech_name.lower():
                for mod in modules:
                     # Avoid duplicates if already added
                     if not any(s['module'] == mod for s in suggestions):
                        suggestions.append({
                            "type": "Technology Match",
                            "indicator": tech_name,
                            "module": mod,
                            "description": f"Module associated with {tech_name}"
                        })
