import asyncio
import aiohttp
import nmap
import socket
import ssl
import json
import time
import dns.resolver
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor
import re
import os

class UltraAdvancedNetworkScanner:
    def __init__(self, timeout=20, domain=None, safe_mode=True, dont_scan=None, output_file="nmap_report.json"):
        self.nm = nmap.PortScanner()
        self.timeout = timeout
        self.safe_mode = safe_mode
        self.dont_scan = dont_scan or []
        
        # Sanitize domain to prevent path traversal
        if domain:
            # Remove any characters that could be used for path traversal
            safe_domain = re.sub(r'[\\/]', '', domain)
            self.domain = safe_domain
        else:
            self.domain = "default"

        self.security_sources = [
            'https://services.nvd.nist.gov/rest/json/cves/2.0',
            'https://www.exploit-db.com/search',
            'https://api.github.com/search/repositories',
            'https://cve.mitre.org/data/downloads/index.html',
            'https://www.rapid7.com/db/',
            'https://packetstormsecurity.com/search/',
            'https://www.securityfocus.com/bid',
            'https://vulners.com/api/v3/search',
            'https://cxsecurity.com/search/',
            'https://sploitus.com/',
            'https://www.securetia.com/',
            'https://openbugbounty.org/search/',
            'https://bugcrowd.com/list-of-bug-bounty-programs',
            'https.hackerone.com/vulnerability-management'
        ]
        self.output_dir = os.path.join("logs", self.domain)
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        self.output_file = os.path.join(self.output_dir, output_file)

    @lru_cache(maxsize=1000)
    def dns_resolve(self, domain):
        # Check if domain is already an IP or CIDR
        # Simple regex for IPv4/IPv6 or CIDR match
        import ipaddress
        try:
            # Check if it's a network (CIDR) or address
            ipaddress.ip_network(domain, strict=False)
            return {
                'ipv4': domain,
                'ipv6': None,
                'dns_records': {'A': [], 'MX': [], 'NS': []} 
            }
        except ValueError:
            pass # Not an IP/CIDR, proceed with DNS resolution

        try:
            ipv4 = socket.gethostbyname(domain)
            resolver = dns.resolver.Resolver()
            
            ipv6 = None
            try:
                ipv6 = socket.getaddrinfo(domain, None, socket.AF_INET6)[0][4][0]
            except: pass

            dns_records = {
                'A': [str(ip) for ip in resolver.resolve(domain, 'A')],
                'MX': [str(mx.exchange) for mx in resolver.resolve(domain, 'MX')],
                'NS': [str(ns.target) for ns in resolver.resolve(domain, 'NS')]
            }

            return {
                'ipv4': ipv4,
                'ipv6': ipv6,
                'dns_records': dns_records
            }
        except Exception as e:
            return {'error': str(e)}

    async def advanced_port_scan(self, target):
        # Nmap tarama argümanları
        timing = "-T2" if self.safe_mode else "-T4"
        scan_args = f'-sV -Pn {timing} -p-' if not self.safe_mode else f'-sV -Pn {timing} -F'
        
        # Taramayı thread içinde çalıştır
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as executor:
            scan_result = await loop.run_in_executor(
                executor, 
                lambda: self.nm.scan(target, arguments=scan_args)
            )
        
        services = {}
        open_ports = []
        
        # Tarama sonuçlarını işleme
        try:
            for proto in self.nm[target].all_protocols():
                ports = self.nm[target][proto].keys()
                for port in ports:
                    service = self.nm[target][proto][port]
                    
                    if service.get('state') == 'open':
                        port_info = {
                            'port': port,
                            'state': service.get('state', ''),
                            'service': service.get('name', 'unknown'),
                            'version': service.get('product', '') + ' ' + service.get('version', ''),
                            'product': service.get('product', ''),
                            'cpe': service.get('cpe', [])
                        }
                        
                        open_ports.append(port)
                        services[port] = port_info
        except Exception as e:
            print(f"Port tarama hatası: {e}")
        
        return {
            'open_ports': open_ports,
            'services': services
        }

    def _calculate_severity(self, cve):
        """
        CVE risk seviyesini hesaplar
        
        Args:
            cve (dict): CVE bilgileri
        
        Returns:
            dict: Risk seviyesi ve skoru
        """
        try:
            # CVSS metrik kontrolleri
            metrics = cve.get('metrics', {}).get('cvssMetricV31', [{}])[0]
            base_score = metrics.get('cvssData', {}).get('baseScore', 0)
            
            # Risk seviye haritası
            severity_map = [
                (9, 'Critical'),
                (7, 'High'),
                (4, 'Medium'),
                (0, 'Low')
            ]
            
            # Seviye belirleme
            for threshold, level in severity_map:
                if base_score >= threshold:
                    return {'level': level, 'score': base_score}
            
            return {'level': 'Unknown', 'score': 0}
        except Exception as e:
            # Herhangi bir hata durumunda varsayılan değer
            return {'level': 'Unknown', 'score': 0}
    
    async def fetch_vulnerabilities(self, services):
        vulnerabilities = []
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            tasks = []
            for service in services.values():
                tasks.append(self._advanced_vulnerability_search(session, service))
            
            results = await asyncio.gather(*tasks)
            
            for result in results:
                vulnerabilities.extend(result)
        
        return vulnerabilities

    async def _advanced_vulnerability_search(self, session, service):
        vulns = []
        keywords = [
            service.get('service', ''), 
            service.get('version', ''), 
            service.get('product', '')
        ]
        
        # NVD CVE Sorgusu
        try:
            async with session.get(
                'https://services.nvd.nist.gov/rest/json/cves/2.0',
                params={
                    'keywordSearch': ' '.join(filter(bool, keywords)),
                    'resultsPerPage': 10
                }
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    for item in data.get('vulnerabilities', []):
                        cve = item.get('cve', {})
                        vuln_details = {
                            'source': 'NVD',
                            'type': 'CVE',
                            'id': cve.get('id', 'N/A'),
                            'description': cve.get('descriptions', [{}])[0].get('value', 'No description available'),
                            'severity': self._calculate_severity(cve)
                        }
                        vulns.append(vuln_details)
        except Exception as e:
            print(f"CVE arama hatası: {e}")
        
        # Exploit DB Sorgusu
        try:
            async with session.get(
                'https://www.exploit-db.com/search',
                params={'q': ' '.join(filter(bool, keywords))}
            ) as response:
                if response.status == 200:
                    exploit_details = {
                        'source': 'Exploit-DB',
                        'type': 'Exploit',
                        'id': 'N/A',
                        'description': f"Potential exploit for {' '.join(filter(bool, keywords))}",
                        'severity': {'level': 'Unknown', 'score': 0}
                    }
                    vulns.append(exploit_details)
        except Exception as e:
            print(f"Exploit arama hatası: {e}")
        
        return vulns

    async def run_comprehensive_scan(self, domain):
        if domain in self.dont_scan:
            return {"error": f"Domain {domain} is in the 'do not scan' list."}

        start_time = time.time()
        
        # DNS çözümlemesi
        dns_info = self.dns_resolve(domain)
        ip = dns_info.get('ipv4')
        
        if not ip or 'error' in dns_info:
            return {"error": "Domain çözümlenemedi"}

        if ip in self.dont_scan:
            return {"error": f"IP {ip} is in the 'do not scan' list."}

        # Port taraması
        port_scan_results = await self.advanced_port_scan(ip)
        
        # Zero-Day açık taraması
        zero_day_results = await self.fetch_vulnerabilities(
            port_scan_results.get('services', {})
        )
        
        # Sonuçları birleştirme
        results = {
            'domain': domain,
            'scan_time': time.time() - start_time,
            'dns_info': dns_info,
            'port_scan': port_scan_results,
            'zero_day_vulnerabilities': zero_day_results
        }
        
        # Raporu kaydetme
        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        return results

def run_scan(domain):
        scanner = UltraAdvancedNetworkScanner(domain=domain)
        return asyncio.run(scanner.run_comprehensive_scan(domain))
