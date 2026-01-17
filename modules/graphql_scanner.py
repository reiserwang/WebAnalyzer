import requests
import json
from modules.base import BaseModule
from typing import Dict, Any

class GraphQLScanner(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "GraphQL Scanner"
        self.description = "Checks GraphQL endpoints for introspection and depth limits."
        self.dependencies = ["requests"]

    def _check_introspection(self, target: str) -> Dict[str, Any]:
        query = """
        query {
          __schema {
            types {
              name
            }
          }
        }
        """
        try:
            # Try POST first
            response = requests.post(target, json={'query': query}, timeout=10)
            
            # Simple check for successful introspection
            if response.status_code == 200:
                try:
                    data = response.json()
                    if "data" in data and data["data"] and "__schema" in data["data"]:
                         return {
                             "status": "Vulnerable",
                             "details": "Introspection is ENABLED. The full API schema is exposed."
                         }
                except ValueError:
                    pass
            
            return {
                "status": "Safe", 
                "details": "Introspection appears disabled or not accessible."
            }

        except Exception as e:
            return {"status": "Error", "details": str(e)}

    def _check_tracing(self, target: str) -> Dict[str, Any]:
        """Check if GraphQL tracing is enabled."""
        query = "query { __typename }"
        try:
            response = requests.post(target, json={'query': query}, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if "extensions" in data and "tracing" in data["extensions"]:
                     return {
                         "status": "Vulnerable",
                         "details": "GraphQL Tracing is ENABLED (extensions.tracing present)."
                     }
            return {"status": "Safe", "details": "Tracing not detected."}
        except Exception as e:
            return {"status": "Error", "details": str(e)}

    def _check_field_suggestions(self, target: str) -> Dict[str, Any]:
        """Check if API suggests fields (Information Leakage)."""
        # Query a field that likely doesn't exist but is close to a common one
        query = "query { __schema { typess { name } } }" # 'typess' instead of 'types'
        try:
            response = requests.post(target, json={'query': query}, timeout=10)
            if response.status_code == 200:
                 data = response.json()
                 if "errors" in data:
                     for error in data["errors"]:
                         if "did you mean" in error.get("message", "").lower():
                             return {
                                 "status": "Vulnerable",
                                 "details": "Field suggestions are ENABLED (Information Leakage)."
                             }
            return {"status": "Safe", "details": "Field suggestions not detected."}
        except Exception:
            return {"status": "Safe", "details": "Could not verify."}

    def _check_batching(self, target: str) -> Dict[str, Any]:
        """Check for JSON Array Batching and Alias Overloading."""
        results = {}
        
        # 1. Array Batching
        try:
            batch_query = [{"query": "query { __typename }"}, {"query": "query { __typename }"}]
            response = requests.post(target, json=batch_query, timeout=10)
            if response.status_code == 200 and isinstance(response.json(), list) and len(response.json()) == 2:
                results["array_batching"] = {
                    "status": "Vulnerable",
                    "details": "Array Batching is ENABLED (DoS Risk)."
                }
            else:
                results["array_batching"] = {"status": "Safe", "details": "Array batching not supported."}
        except Exception as e:
            results["array_batching"] = {"status": "Error", "details": str(e)}

        # 2. Alias Overloading (Simple check with 5 aliases)
        # Should ideally define a threshold, but if 5 works, it supports it.
        aliases = ",".join([f"a{i}:__typename" for i in range(5)])
        alias_query = f"query {{ {aliases} }}"
        try:
             response = requests.post(target, json={'query': alias_query}, timeout=10)
             if response.status_code == 200 and "data" in response.json():
                 results["alias_overloading"] = {
                     "status": "Vulnerable", # It supports aliasing, potentially vulnerable if no limit
                     "details": "Multiple aliases accepted. Verify max limits (DoS Risk)."
                 }
             else:
                 results["alias_overloading"] = {"status": "Safe", "details": "Alias query failed."}
        except Exception as e:
             results["alias_overloading"] = {"status": "Error", "details": str(e)}
             
        return results

    def _check_csrf(self, target: str) -> Dict[str, Any]:
        """Check for GET and POST-urlencoded support (CSRF Risk)."""
        results = {}
        query = "query { __typename }"
        
        # 1. GET Request
        try:
            response = requests.get(target, params={'query': query}, timeout=10)
            if response.status_code == 200 and "data" in response.json():
                results["get_method"] = {
                    "status": "Vulnerable",
                    "details": "GraphQL accepts GET requests (CSRF Risk)."
                }
            else:
                results["get_method"] = {"status": "Safe", "details": "GET requests ignored or blocked."}
        except Exception:
             results["get_method"] = {"status": "Error", "details": "Connection failed."}

        # 2. POST Url-Encoded
        try:
            response = requests.post(target, data={'query': query}, headers={'Content-Type': 'application/x-www-form-urlencoded'}, timeout=10)
            if response.status_code == 200 and "data" in response.json():
                 results["post_urlencoded"] = {
                     "status": "Vulnerable",
                     "details": "GraphQL accepts x-www-form-urlencoded (CSRF Risk)."
                 }
            else:
                 results["post_urlencoded"] = {"status": "Safe", "details": "Url-encoded blocked."}
        except Exception:
             results["post_urlencoded"] = {"status": "Error", "details": "Connection failed."}
             
        return results

    def _check_query_depth(self, target: str) -> Dict[str, Any]:
        # Build a deep recursive query using __schema
        # __schema { types { fields { type { fields { ... } } } } }
        # Each level adds 3 layers of depth in AST ideally, but let's just make it deep textually.
        
        depth_level = 15
        nested_part = "types { fields { type { " * depth_level
        closing_part = "} } } " * depth_level
        
        query = f"query DeepCheck {{ __schema {{ {nested_part} name {closing_part} }} }}"
        
        try:
            response = requests.post(target, json={'query': query}, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if "errors" in data:
                    errors = json.dumps(data["errors"]).lower()
                    if "depth" in errors or "complexity" in errors:
                        return {
                            "status": "Secure",
                            "details": "API blocked the deep query (Depth/Complexity limit active)."
                        }
                    else:
                        # Error but not depth related (maybe introspection disabled)
                        return {
                            "status": "Unknown",
                            "details": "Query failed but not explicitly due to depth."
                        }
                
                # No errors -> query executed?
                if "data" in data and data["data"]:
                     return {
                        "status": "Vulnerable", 
                        "details": f"API accepted a query with ~{depth_level*3} levels of nesting."
                    }

            return {"status": "Unknown", "details": f"Response code {response.status_code}"}
            
        except Exception as e:
             return {"status": "Error", "details": str(e)}

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        # 'target' is expected to be the full graphql endpoint e.g., http://example.com/graphql
        # If it's just a domain, try to append /graphql
        if not target.startswith("http"):
             target = f"http://{target}"
             
        # Simple heuristic to append /graphql if not present
        if "/graphql" not in target and not target.endswith("/graphql"):
             # Use a few common paths? For now just try the base or append /graphql
             # Let's assume the user might provide the full URL, but if they provide the root, we default to /graphql
             target = f"{target.rstrip('/')}/graphql"

        return {
            "target": target,
            "introspection": self._check_introspection(target),
            "depth_limit": self._check_query_depth(target),
            "tracing": self._check_tracing(target),
            "field_suggestions": self._check_field_suggestions(target),
            "batching_dos": self._check_batching(target),
            "csrf_methods": self._check_csrf(target)
        }
