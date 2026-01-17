import requests
import logging
from urllib.parse import urlparse

class PolicyAnalyzer:
    def __init__(self, domain, timeout=10):
        self.domain = domain
        self.timeout = timeout
        self.results = {
            "score": 100,
            "csp": {},
            "coop": {},
            "corp": {},
            "coep": {},
            "summary": []
        }

    def analyze(self):
        protocols = ['https', 'http']
        headers = None
        
        for proto in protocols:
            try:
                url = f"{proto}://{self.domain}"
                response = requests.get(url, timeout=self.timeout, verify=False)
                headers = response.headers
                break # Prefer HTTPS, fall back to HTTP
            except requests.RequestException:
                continue
        
        if not headers:
            self.results["error"] = "Could not fetch headers"
            self.results["score"] = 0
            return self.results

        self._analyze_csp(headers)
        self._analyze_coop(headers)
        self._analyze_corp(headers)
        self._analyze_coep(headers)
        
        return self.results

    def _analyze_csp(self, headers):
        csp_raw = headers.get('Content-Security-Policy', '')
        if not csp_raw:
            self.results["csp"] = {"present": False, "issues": ["Missing Content-Security-Policy header"]}
            self.results["score"] -= 40
            self.results["summary"].append("CRITICAL: Missing CSP Header")
            return

        issues = []
        directives = {}
        for part in csp_raw.split(';'):
            part = part.strip()
            if not part: continue
            tokens = part.split()
            directives[tokens[0]] = tokens[1:]

        # Check weaknesses
        if 'unsafe-inline' in csp_raw:
            issues.append("'unsafe-inline' detected (XSS Risk)")
            self.results["score"] -= 20
        
        if 'unsafe-eval' in csp_raw:
            issues.append("'unsafe-eval' detected")
            self.results["score"] -= 10

        if 'default-src' not in directives:
            issues.append("Missing 'default-src' directive")
            self.results["score"] -= 10
            
        if '*' in csp_raw and 'default-src' in directives and '*' in directives['default-src']:
             issues.append("Wildcard '*' in default-src (Ineffective CSP)")
             self.results["score"] -= 20

        self.results["csp"] = {
            "present": True,
            "raw": csp_raw,
            "parsed": directives,
            "issues": issues
        }
        if issues:
             self.results["summary"].append(f"CSP Weaknesses: {', '.join(issues)}")

    def _analyze_coop(self, headers):
        # Cross-Origin-Opener-Policy
        coop = headers.get('Cross-Origin-Opener-Policy', '')
        status = "Missing"
        if coop:
            if coop == "same-origin":
                status = "Strong (same-origin)"
            elif coop == "same-origin-allow-popups":
                status = "Moderate (same-origin-allow-popups)"
            else:
                status = f"Weak ({coop})"
                self.results["score"] -= 5
        else:
            self.results["score"] -= 5
            
        self.results["coop"] = {"value": coop, "status": status}

    def _analyze_corp(self, headers):
        # Cross-Origin-Resource-Policy
        corp = headers.get('Cross-Origin-Resource-Policy', '')
        status = "Missing"
        if corp:
            if corp == "same-origin":
                 status = "Strong (same-origin)"
            elif corp == "same-site":
                 status = "Moderate (same-site)"
            else:
                 status = f"Weak ({corp})"
                 self.results["score"] -= 5
        else:
             self.results["score"] -= 5
             
        self.results["corp"] = {"value": corp, "status": status}

    def _analyze_coep(self, headers):
        # Cross-Origin-Embedder-Policy
        coep = headers.get('Cross-Origin-Embedder-Policy', '')
        status = "Missing"
        if coep == "require-corp":
            status = "Strong (require-corp)"
        elif coep:
             status = f"Weak ({coep})"
             self.results["score"] -= 5
        else:
             self.results["score"] -= 5

        self.results["coep"] = {"value": coep, "status": status}
