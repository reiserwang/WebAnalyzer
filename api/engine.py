from modules.base import BaseModule
from modules.manager import ModuleManager
from modules.adapters import FunctionAdapter, ClassAdapter

# Module Imports
from modules.domain_info import get_domain_info
from modules.domain_dns import DNSAnalyzer
from modules.subfinder_tool import run_subfinder
from modules.seo_analysis import analyze_advanced_seo
from modules.web_technologies import detect_web_technologies
from modules.security_analysis import analyze_security
from modules.contact_spy import GlobalDomainScraper
from modules.subdomain_takeover import SubdomainTakeover
from modules.advanced_content_scanner import AdvancedContentScanner
from modules.cloudflare_bypass import CloudflareBypass
from modules.nmap_zero_day import UltraAdvancedNetworkScanner

# New Security Modules
from modules.frp_scanner import FRPScanner
from modules.policy_analyzer import PolicyAnalyzer
from modules.msf_suggester import MetasploitSuggester
from modules.active_pentest import ActivePentest
from modules.iot_scanner import IoTScanner
from modules.msf_deep_scan import MSFDeepScanner
from modules.vuln_scanner import VulnScanner
from modules.topology_scanner import TopologyScanner

# Hardcoded key from legacy main.py (Should be moved to env in future)
LEGACY_API_KEY = "at_14sqNbh0sbZ61CY1Bl0meKYgVKrL8"

class AnalyzerEngine:
    def __init__(self):
        self.manager = ModuleManager()
        self._register_default_modules()

    def _register_default_modules(self):
        """
        Register all known modules using adapters.
        """
        # 1. Domain Information
        self.manager.register_module(FunctionAdapter(
            "Domain Information", 
            lambda d: get_domain_info(d, LEGACY_API_KEY),
            "Basic domain registration info"
        ))

        # 2. DNS Records
        # DNSAnalyzer needs instantiation and has get_dns_records method
        self.manager.register_module(ClassAdapter(
            "DNS Records",
            DNSAnalyzer(),
            "get_dns_records",
            "DNS Record Analysis"
        ))

        # 3. SEO Analysis
        self.manager.register_module(FunctionAdapter(
            "SEO Analysis",
            analyze_advanced_seo
        ))

        # 4. Web Technologies
        self.manager.register_module(FunctionAdapter(
            "Web Technologies",
            detect_web_technologies
        ))

        # 5. Security Analysis
        # This one had custom logic (merging PolicyAnalyzer). 
        # We can implement a custom Adapter or a Lambda to handle composition.
        def security_analysis_wrapper(domain):
            base_security = analyze_security(domain)
            try:
                policy_analyzer = PolicyAnalyzer(domain)
                base_security["Policy Analysis"] = policy_analyzer.analyze()
            except Exception:
                pass # Fail silently for policy part if error
            return base_security

        self.manager.register_module(FunctionAdapter(
            "Security Analysis",
            security_analysis_wrapper
        ))

        # 6. Advanced Content Scan
        # Wrapper to handle specific args like output_dir
        def content_scan_wrapper(domain):
            scanner = AdvancedContentScanner(
                domain,
                output_dir=f"logs/{domain}",
                max_depth=2, max_pages=20, timeout=5, max_workers=5, verify_ssl=False
            )
            return scanner.run()

        self.manager.register_module(FunctionAdapter(
            "Advanced Content Scan",
            content_scan_wrapper
        ))

        # 7. Contact Spy
        def contact_spy_wrapper(domain):
            scraper = GlobalDomainScraper(domain, max_pages=20, log_dir="logs")
            return scraper.crawl()
            
        self.manager.register_module(FunctionAdapter(
            "Contact Spy",
            contact_spy_wrapper
        ))

        # 8/9 Subdomains & Takeover
        # These depend on each other. We might separate them or orchestrate them.
        self.manager.register_module(FunctionAdapter(
            "Subdomain Discovery",
            run_subfinder
        ))

        def takeover_wrapper(domain, subdomains=None):
            # If subdomains not passed, we might need a way to get them from previous results?
            # ModuleManager.run_all doesn't share state between modules automatically yet.
            # But run_scan does this: "subdomains = run_subfinder..."
            # For now, let's keep it simple: takeover wrapper needs subdomains.
            # We'll handle state/dependency in run_scan loop or keep custom logic for this dependency.
            if not subdomains: 
                return {"error": "No subdomains provided"}
            scanner = SubdomainTakeover(domain, output_dir=f"logs/{domain}", timeout=5, max_workers=10)
            return scanner.scan(subdomains)

        self.manager.register_module(FunctionAdapter(
             "Subdomain Takeover",
             takeover_wrapper
        ))

        # 10. Nmap Zero Day
        async def nmap_wrapper(domain):
             scanner = UltraAdvancedNetworkScanner(domain=domain, timeout=5, aggressive_mode=False)
             return await scanner.run_comprehensive_scan(domain)
        
        self.manager.register_module(FunctionAdapter(
            "Nmap Zero Day Scan",
            nmap_wrapper
        ))

        # 11. Cloudflare Bypass
        def cf_wrapper(domain):
            bypass = CloudflareBypass(target=domain, verbose=False)
            return bypass.run()
        
        self.manager.register_module(FunctionAdapter("CloudFlare Bypass", cf_wrapper))

        # 12. FRP Scanner
        def frp_wrapper(domain):
            scanner = FRPScanner(domain, timeout=3)
            return scanner.scan()
        self.manager.register_module(FunctionAdapter("FRP Scanner", frp_wrapper))

        # 13. Metasploit Suggester
        # Needs full results. We will handle this dependency in run_scan logic for now
        # OR register it such that it expects 'results' in kwargs
        def msf_suggest_wrapper(domain, existing_results=None):
             suggester = MetasploitSuggester()
             return suggester.suggest(existing_results or {})
        self.manager.register_module(FunctionAdapter("Metasploit Suggester", msf_suggest_wrapper))

        # 14. Active Pentest
        def active_pentest_wrapper(domain, existing_results=None):
            content_results = existing_results.get("Advanced Content Scan", {}) if existing_results else {}
            pentest = ActivePentest(domain, content_scan_results=content_results)
            return pentest.run()
        self.manager.register_module(FunctionAdapter("Active Pentest", active_pentest_wrapper))

        # 15. IoT Scanner
        def iot_wrapper(domain):
            scanner = IoTScanner(target=domain)
            return scanner.scan()
        self.manager.register_module(FunctionAdapter("IoT Scanner", iot_wrapper))

        # 16. MSF Deep Scan
        def msf_deep_wrapper(domain, existing_results=None):
             technologies = []
             if existing_results:
                 web_tech = existing_results.get("Web Technologies", {})
                 if isinstance(web_tech, dict):
                    for cat, names in web_tech.items():
                        if isinstance(names, list): technologies.extend(names)
                        elif isinstance(names, str): technologies.append(names)
             scanner = MSFDeepScanner(target=domain)
             return scanner.scan(technologies)
        self.manager.register_module(FunctionAdapter("MSF Deep Scan", msf_deep_wrapper))

        # 17. Vuln Scanner
        def vuln_wrapper(domain):
            scanner = VulnScanner(target=domain)
            return scanner.scan()
        self.manager.register_module(FunctionAdapter("Vulnerability Scanner", vuln_wrapper))

        # 18. Network Topology
        def topology_wrapper(domain):
            scanner = TopologyScanner(target=domain)
            return scanner.scan()
        self.manager.register_module(FunctionAdapter("Network Topology", topology_wrapper))

    async def run_scan(self, domain: str, modules: List[str] = None) -> Dict[str, Any]:
        """
        Runs the specified modules against the domain using ModuleManager.
        """
        self.results = {}
        
        # Determine which modules to run. If None, run all.
        target_modules = modules if modules and len(modules) > 0 else self.manager.get_available_modules()
        
        # Run independent modules first (that don't depend on others)
        # For simplicity in this refactor, we can iterate or use run_all
        # But we have dependencies: Subdomain Takeover needs Subdomains.
        # MSF Suggester needs everything.
        
        # Let's run modules in batches or simply iterate and pass self.results
        
        for name in target_modules:
            # Skip dependency-heavy ones for a second pass if needed, 
            # Or just run them and let them pick from self.results
            
            # Special handling for submodule params
            kwargs = {}
            if name == "Subdomain Takeover":
               # Check if we have subdomains from a previous run or if we need to run discovery
               subdomains = self.results.get("Subdomains", [])
               if not subdomains and "Subdomain Discovery" in target_modules and "Subdomain Discovery" not in self.results:
                    # Force run discovery if it was requested but not run yet?
                    # Since we iterate list, order matters if we do it sequentially.
                    # Ideally we topology sort, but effectively we can just pass self.results 
                    # and let the wrapper handle "if not found".
                    pass 
               kwargs["subdomains"] = subdomains
            
            if name in ["Metasploit Suggester", "Active Pentest", "MSF Deep Scan"]:
                kwargs["existing_results"] = self.results

            # Execute
            # Note: ModuleManager.run_module catches exceptions and returns {"error": ...}
            self.results[name] = await self.manager.run_module(name, domain, **kwargs)
            
            # If Subdomain Discovery just ran, update local var for Takeover to use?
            # effectively self.results has it.

        return self.results
