import nmap
import asyncio
import logging
from typing import Dict, Any, List

class IoTScanner:
    def __init__(self, target: str, timeout: int = 30, safe_mode=True, dont_scan=None):
        self.target = target
        self.timeout = timeout
        self.safe_mode = safe_mode
        self.dont_scan = dont_scan or []
        self.nm = nmap.PortScanner()
        self.logger = logging.getLogger("IoTScanner")
        
        # Common IoT Ports (Expanded)
        self.iot_ports = [
            21,    # FTP
            22,    # SSH
            23,    # Telnet
            69,    # TFTP
            80,    # Web
            81,    # Web Alt
            102,   # Siemens S7
            139,   # SMB / NetBIOS
            443,   # Web SSL
            502,   # Modbus (ICS)
            515,   # LPR (Printers)
            554,   # RTSP (Cameras)
            631,   # IPP (Printers)
            1883,  # MQTT
            1900,  # UPnP
            1911,  # Fox (Tridium Niagara)
            2404,  # IEC 60870-5-104 (ICS)
            3000,  # Node.js / React
            37777, # Dahua DVR
            4840,  # OPC UA
            5000,  # UPnP / Synology
            5222,  # XMPP
            5353,  # mDNS
            5555,  # ADB / Freebox
            5672,  # AMQP
            5900,  # VNC (HMI)
            8000,  # Hikvision / Web Alt
            8080,  # Web Alt
            8081,  # Web Alt
            8083,  # Zigbee Gateway Web
            8883,  # MQTT SSL
            9100,  # Printer JetDirect
            20000, # DNP3 (ICS)
            44818, # EtherNet/IP (ICS)
            47808, # BACnet
            49152  # Supermicro IPMI / UPnP
        ]

        # CVE Database for common IoT devices
        self.cve_db = {
            "Hikvision": ["CVE-2021-36260", "CVE-2017-7921"],
            "Dahua": ["CVE-2021-33044", "CVE-2021-33045"],
            "Axis": ["CVE-2018-10660", "CVE-2018-10661", "CVE-2018-10662"],
            "TPLink": ["CVE-2022-30075"],
            "Synology": ["CVE-2022-22648"],
            "MikroTik": ["CVE-2018-14847"],
        }

        # Common Default Credentials
        self.default_creds = {
            "admin": ["admin", "1234", "123456", "password", "system"],
            "root": ["root", "toor", "admin", "123456", "vizxv"],
            "user": ["user", "1234"],
            "support": ["support", "admin"]
        }
        
    def scan(self) -> Dict[str, Any]:
        """
        Performs a scan specifically targeting IoT devices.
        Returns a dictionary of findings.
        """
        if self.target in self.dont_scan:
            self.logger.warning(f"Skipping scan for {self.target} as it is in the 'do not scan' list.")
            return {"summary": f"Scan for {self.target} skipped."}
            
        try:
            self.logger.info(f"Starting IoT scan for {self.target}")
            
            # Convert ports to str
            ports_str = ",".join(map(str, self.iot_ports))
            
            # -sV: Service Detection
            # -Pn: Treat as online
            # -T4: Aggressive timing (faster), -T2: Polite timing
            # --open: Only show open ports
            timing = "-T2" if self.safe_mode else "-T4"
            args = f"-sV -Pn {timing} --open -p {ports_str}"
            
            self.nm.scan(self.target, arguments=args)
            
            result = {
                "devices_found": [],
                "summary": "No IoT devices/services detected on target IP."
            }
            
            # Nmap structure: scan[ip]['tcp'][port]
            # Since target might resolve to one IP, we usually just have one host key
            # But duplicate logic handling just in case
            
            hosts = self.nm.all_hosts()
            if not hosts:
                return result

            host_findings = []
            
            for host in hosts:
                host_data = {
                    "ip": host,
                    "services": []
                }
                
                # TCP Scans
                if 'tcp' in self.nm[host]:
                    for port, info in self.nm[host]['tcp'].items():
                        service_name = info.get('name', 'unknown')
                        product = info.get('product', '')
                        version = info.get('version', '')
                        
                        # Heuristic Device Identification
                        device_type = "Unknown"
                        port = int(port)
                        
                        if port in [554, 37777, 8000]: 
                            device_type = "Camera/DVR (RTSP/Proprietary)"
                        elif port in [1883, 8883, 5672]: 
                            device_type = "IoT Broker (MQTT/AMQP)"
                        elif port in [502, 102, 47808, 20000, 44818, 2404, 1911]: 
                            device_type = "Industrial Controller (ICS/SCADA)"
                        elif port in [631, 9100, 515]:
                            device_type = "Printer/Scanner"
                        elif port in [5555]:
                            device_type = "Android/Multimedia Device"
                        elif port in [4840]:
                            device_type = "OPC UA Server"
                        elif port in [23]:
                            device_type = "Legacy Device (Telnet)"
                        elif port in [5900]:
                            device_type = "HMI Display (VNC)"
                        elif port in [139]:
                            device_type = "Windows/Samba Share"
                        elif port in [3000]:
                            device_type = "Node.js/Web App"
                        
                        # Check for CVEs
                        cves = self._map_cves(product)
                        
                        # Check for default credentials (simplified simulation for now to avoid blocking)
                        # In a real scenario, we would attempt login via SSH/Telnet/HTTP
                        weak_creds = []
                        if not self.safe_mode and port in [21, 22, 23, 80, 443, 8080]:
                             weak_creds = self._check_default_creds(host, port, service_name)

                        host_data["services"].append({
                            "port": port,
                            "service": service_name,
                            "banner": f"{product} {version}".strip(),
                            "device_type_hint": device_type,
                            "state": info.get('state'),
                            "potential_cves": cves,
                            "weak_credentials": weak_creds
                        })
                
                if host_data["services"]:
                    host_findings.append(host_data)

            if host_findings:
                result["devices_found"] = host_findings
                result["summary"] = f"Found potential IoT services on {len(host_findings)} host(s)."
                
            return result

        except Exception as e:
            self.logger.error(f"IoT Scan failed: {e}")
            return {"error": str(e)}

    def _map_cves(self, product_banner: str) -> List[str]:
        """Map product name to potential CVEs."""
        found_cves = []
        if not product_banner:
            return []
            
        for vendor, cve_list in self.cve_db.items():
            if vendor.lower() in product_banner.lower():
                found_cves.extend(cve_list)
        return list(set(found_cves))

    def _check_default_creds(self, ip: str, port: int, service: str) -> List[str]:
        """
        Check for default credentials. 
        Note: This is a placeholder. Implementing actual brute-force requires 
        paramiko (SSH), telnetlib (Telnet), or requests (HTTP) with proper timeouts.
        For now, we return a hint if the service matches known risky ones.
        """
        # Actual implementation would go here. 
        # Returning potential checks for the user to verify manually.
        findings = []
        if service in ["ssh", "telnet", "ftp"]:
             findings.append("Manual Verify: admin/admin, root/root")
        elif service in ["http", "https", "http-alt"]:
             findings.append("Manual Verify: admin/admin, admin/1234")
        
        return findings
