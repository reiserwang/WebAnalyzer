import requests
import yaml
import json
from urllib.parse import urljoin
from modules.base import BaseModule
from typing import Dict, Any, List

class APIFuzzer(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "API Fuzzer"
        self.description = "Fuzzes REST API endpoints based on OpenAPI/Swagger schema."
        self.dependencies = ["requests", "PyYAML"]
        
    def _parse_open_api(self, url: str) -> List[Dict]:
        endpoints = []
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code != 200:
                return []
                
            try:
                data = resp.json()
            except:
                try:
                    data = yaml.safe_load(resp.text)
                except:
                    return []
            
            # Support Swagger 2.0 and OpenAPI 3.0 structure
            paths = data.get("paths", {})
            base_path = data.get("basePath", "") # Swagger 2.0
            # OpenAPI 3.0 uses 'servers', ignoring for simplicity, relying on user providing target base URL
                
            for path, methods in paths.items():
                full_path = f"{base_path}{path}" if base_path else path
                
                for method, details in methods.items():
                    if method.lower() not in ["get", "post", "put", "delete"]:
                        continue
                        
                    params = []
                    # Check path params
                    if "parameters" in details:
                         for p in details["parameters"]:
                             if p.get("in") == "path":
                                 params.append(p.get("name"))
                    
                    endpoints.append({
                        "path": full_path,
                        "method": method.upper(),
                        "params": params,
                        "summary": details.get("summary", "No summary")
                    })
        except Exception as e:
            pass # Suppress parsing errors
            
        return endpoints

    def _test_endpoint(self, base_url: str, endpoint: Dict) -> Dict:
        path = endpoint["path"]
        method = endpoint["method"]
        params = endpoint["params"]
        
        findings = []
        
        # SKIP unsafe methods
        if method == "DELETE":
            return {
                "endpoint": f"{method} {path}",
                "status": "Skipped (Safety)",
                "details": "DELETE method skipped in safe mode."
            }

        # BOLA / IDOR Check
        # If the path contains {id}, try to substitute and access
        url_template = path
        
        # Only test if we have path parameters to substitute
        if not params:
             # Basic access check? 
             # For MVP, only fuzzing params.
             return {
                "endpoint": f"{method} {path}",
                "status": "Passive",
                "details": "No path parameters to fuzz."
            }
             
        # Mock Logic for Fuzzing
        # We replace {param} with '1' and check response
        fuzzed_path = path
        for p in params:
            # Naive replacement for {id} or {userId} etc
            fuzzed_path = fuzzed_path.replace(f"{{{p}}}", "1")
            
        target_url = urljoin(base_url, fuzzed_path) if base_url.startswith("http") else f"http://{base_url}{fuzzed_path}"
        
        try:
            # Just do a GE T request even if method is POST/PUT for simple discovery?
            # Or assume GET for retrieval testing.
            if method == "GET":
                resp = requests.get(target_url, timeout=5)
                status_code = resp.status_code
                
                detail = f"Status {status_code}"
                if status_code == 200:
                    detail += " - Resource Accessible (Potential IDOR if unauth)"
                elif status_code in [401, 403]:
                    detail += " - Protected"
                elif status_code == 404:
                    detail += " - Not Found"
                    
                findings.append(detail)
            else:
                 findings.append("Skipped non-GET for simple BOLA fuzzing")
                 
        except Exception as e:
            findings.append(f"Request Error: {str(e)}")

        return {
            "endpoint": f"{method} {path}",
            "status": "Tested",
            "details": "; ".join(findings)
        }

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        schema_url = kwargs.get("schema_url")
        if not schema_url:
            return {
                "error": "Missing Schema",
                "details": "Please provide a Swagger/OpenAPI URL (cli arg: --schema-url)"
            }
            
        endpoints = self._parse_open_api(schema_url)
        if not endpoints:
             return {
                 "error": "Parse Failed",
                 "details": f"Could not find valid endpoints in {schema_url}"
             }

        results = []
        # Test first 10 endpoints to avoid flooding in MVP
        for ep in endpoints[:10]:
             res = self._test_endpoint(target, ep)
             results.append(res)
             
        return {
            "schema_source": schema_url,
            "endpoints_found": len(endpoints),
            "findings": results
        }
