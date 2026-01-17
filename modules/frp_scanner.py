import socket
import requests
import logging
from urllib.parse import urlparse

class FRPScanner:
    def __init__(self, target, timeout=5):
        self.target = target
        self.timeout = timeout
        self.common_ports = [7000, 7500, 80, 443, 8080, 4443]
        self.logger = logging.getLogger(__name__)

    def check_port(self, port):
        """Check if a port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def check_http_signature(self, port):
        """Check for FRP signatures in HTTP responses."""
        protocols = ['http', 'https']
        for proto in protocols:
            try:
                url = f"{proto}://{self.target}:{port}"
                response = requests.get(url, timeout=self.timeout, verify=False)
                
                # Check 1: Dashboard Title
                if "frp dashboard" in response.text.lower():
                    return True, f"FRP Dashboard detected at {url} (Title Match)"
                
                # Check 2: Header Signature (FRP sometimes sets custom headers or specific server headers)
                # Note: FRP doesn't always strictly identify itself in headers, but we look for anomalies
                if 'www-authenticate' in response.headers:
                    if 'frp' in response.headers['www-authenticate'].lower():
                         return True, f"FRP Auth detected at {url}"

                # Check 3: Static assets often found in FRP dashboard
                if "/static/js/app" in response.text or "frp" in response.text.lower():
                     return True, f"Potential FRP content detected at {url}"
                     
            except requests.RequestException:
                continue
        return False, None

    def scan(self):
        self.logger.info(f"Starting FRP Scan for {self.target}")
        results = {
            "is_frp_detected": False,
            "details": [],
            "open_ports": []
        }

        # 1. Resolve domain to IP (basic validation)
        try:
            ip = socket.gethostbyname(self.target)
        except socket.gaierror:
            results["error"] = "Could not resolve domain"
            return results

        # 2. Check Ports
        for port in self.common_ports:
            if self.check_port(port):
                results["open_ports"].append(port)
                
                # 3. Check Signatures on Open Ports
                is_frp, details = self.check_http_signature(port)
                if is_frp:
                    results["is_frp_detected"] = True
                    results["details"].append(details)

        return results
