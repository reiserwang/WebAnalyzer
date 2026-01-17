import os
import sys
import asyncio
import time
from typing import List, Dict, Any

from utils.utils import clear_terminal, save_results_to_json, display_banner
from api.engine import AnalyzerEngine

# Initialize Engine globally or in main
engine = AnalyzerEngine()

def print_result_header(title):
    print("\n\033[93m" + "="*40 + "\033[0m")
    print(f"\033[93m--- {title} ---\033[0m")
    print("\033[93m" + "="*40 + "\033[0m")

def print_domain_info(domain_info):
    print_result_header("DOMAIN INFORMATION")
    if "error" in domain_info:
         print(f"\033[91mError: {domain_info['error']}\033[0m")
         return

    keys_to_display_first = [
        "Domain", "Registrar", "Creation Date", "Expiration Date", 
        "Last Updated Date", "Server Provider", "Physical Location"
    ]
    for key in keys_to_display_first:
        if key in domain_info and domain_info[key] not in ["Unknown", "Not available"]:
            print(f"\033[94m{key}:\033[0m {domain_info[key]}")

    for key, value in domain_info.items():
        if key in keys_to_display_first: continue
        if isinstance(value, dict):
            print(f"\033[94m{key}:\033[0m")
            for subkey, subvalue in value.items():
                print(f"  - {subkey}: {subvalue}")
        elif isinstance(value, list):
            print(f"\033[94m{key}:\033[0m")
            for item in value:
                print(f"  - {item}")
        elif value not in ["Unknown", "Not available"]:
            print(f"\033[94m{key}:\033[0m {value}")

def print_dns_records(dns_records):
    print_result_header("DNS INFORMATION")
    if "error" in dns_records:
         print(f"\033[91mError: {dns_records['error']}\033[0m")
         return
    
    print("DNS Records:")
    for record_type, records in dns_records.get("records", {}).items():
        print(f"{record_type}:")
        for record in records:
            print(f"  - {record}")
    
    # Simple report summary if exists (Note: generate_report was part of original logic but separate from data)
    # The adapter returns the raw data + report? Adapter calls get_dns_records.
    # The original main.py called analyzer.generate_report separately. 
    # We might miss that unless the adapter includes it.
    # For now, print what we have.
    if "response_time_ms" in dns_records:
        print(f"\033[94mResponse Time:\033[0m {dns_records['response_time_ms']} ms")

def print_subdomain_takeover(results, output_dir):
    if "error" in results:
         print(f"\033[91mError: {results['error']}\033[0m")
         return

    if results.get("vulnerable_subdomains"):
        high = results["statistics"]["high_confidence"]
        med = results["statistics"]["medium_confidence"]
        low = results["statistics"]["low_confidence"]

        print_result_header("SUBDOMAIN TAKEOVER VULNERABILITIES")
        print(f"\033[94mTotal Vulnerable Subdomains:\033[0m {len(results['vulnerable_subdomains'])}")
        print(f"\033[91mHigh Confidence:\033[0m {high}")
        print(f"\033[93mMedium Confidence:\033[0m {med}")
        print(f"\033[94mLow Confidence:\033[0m {low}")

        if high > 0:
            print("\n\033[91mCritical Vulnerabilities:\033[0m")
            for sub in results["vulnerable_subdomains"]:
                if sub["confidence"] == "High":
                    print(f"  \033[91m{sub['subdomain']}\033[0m - {sub['vulnerability_type']} ({sub['service']})")
                    print(f"    → \033[93mExploitation Difficulty:\033[0m {sub['exploitation_difficulty']}")
                    print(f"    → \033[92mMitigation:\033[0m {sub['mitigation']}")
        print(f"\n\033[94mDetailed results saved to:\033[0m {output_dir}/takeover_summary.json")
    else:
        print("\n\033[92mNo subdomain takeover vulnerabilities found.\033[0m")

def print_content_scan(results):
    print_result_header("ADVANCED CONTENT SCAN")
    if "error" in results:
         print(f"\033[91mError: {results['error']}\033[0m")
         return
    # Use logic from original run_advanced_content_scanner printing
    # ... (simplified for brevity, main logic preserved)
    summary = results.get("summary", {})
    high_secrets = [s for s in results.get("secrets", []) if s["severity"] == "High"]
    
    print(f"\033[94mTotal URLs Crawled:\033[0m {summary.get('total_urls_crawled', 0)}")
    print(f"\033[91mHigh Severity Secrets Found:\033[0m {len(high_secrets)}")




def select_modules():
    """
    Allows user to select which modules to run or choose to run all modules.
    Returns a list of selected module names and a boolean indicating if all modules should run.
    """
    modules = engine.manager.get_available_modules()


    print("\033[93m" + "=" * 50 + "\033[0m")
    print("\033[93m>>>        MODULE SELECTION MENU        <<<\033[0m")
    print("\033[93m" + "=" * 50 + "\033[0m")

    # Display module options
    for i, module in enumerate(modules, 1):
        print(f"\033[94m[{i}] {module}\033[0m")

    print("\033[94m[A] Run ALL Modules\033[0m")
    print("\033[94m[Q] Quit\033[0m")

    while True:
        # Get user input
        choice = input(
            "\033[92mEnter module numbers (comma-separated) or 'A' for all, 'Q' to quit: \033[0m").upper().strip()

        # Quit option
        if choice == 'Q':
            print("\033[91mExiting module selection.\033[0m")
            return [], False

        # All modules option
        if choice == 'A':
            print("\033[92m[✔] All modules selected!\033[0m")
            return modules, True

        # Individual module selection
        try:
            # Split input and remove any whitespace
            selected_numbers = [num.strip() for num in choice.split(',')]

            # Validate and collect selected modules
            selected_modules = []
            for num in selected_numbers:
                try:
                    index = int(num) - 1
                    if 0 <= index < len(modules):
                        selected_modules.append(modules[index])
                    else:
                        print(f"\033[91m[✘] Invalid selection: {num}\033[0m")
                        break
                except ValueError:
                    print(f"\033[91m[✘] Invalid selection: {num}\033[0m")
                    break
            else:
                # If no invalid selections were found
                if selected_modules:
                    print("\033[92m[✔] Modules selected successfully:\033[0m")
                    for module in selected_modules:
                        print(f"\033[94m- {module}\033[0m")
                    return selected_modules, False

        except Exception:
            print("\033[91m[✘] Invalid input. Please enter valid module numbers.\033[0m")


def print_cloudflare_bypass(results):
    print_result_header("CLOUDFLARE BYPASS")
    if "error" in results:
         print(f"\033[91mError: {results['error']}\033[0m")
         return

    print(f"\033[94mScan time: {results['scan_time']:.1f} seconds\033[0m")
    print(f"\033[94mCloudFlare protected: {'Yes' if results['cloudflare_protected'] else 'No'}\033[0m")
    
    if results['real_ips']:
        print("\033[92m[+] REAL IP ADDRESSES:\033[0m")
        for i, ip_info in enumerate(results['real_ips'], 1):
             status = "✓" if ip_info.get('status') == "active" else "✗" if ip_info.get('status') == "inactive" else "?"
             print(f"\033[94m{i}. \033[97m{ip_info['ip']} [{status}]\033[0m")
    else:
        print("\033[91m[-] No real IPs found.\033[0m")


def print_api_fuzzer(results):
    print_result_header("API FUZZER SCAN")
    if "error" in results:
         print(f"\033[91mError: {results['error']}\033[0m")
         if "details" in results:
             print(f"\033[93mDetails: {results['details']}\033[0m")
         return

    print(f"\033[94mSchema Source:\033[0m {results.get('schema_source', 'N/A')}")
    print(f"\033[94mEndpoints Found:\033[0m {results.get('endpoints_found', 0)}")
    
    findings = results.get("findings", [])
    if findings:
        print("\n\033[93m[!] Findings:\033[0m")
        for f in findings:
            status_color = "\033[92m" if "Tested" in f.get("status", "") else "\033[90m"
            print(f"  {status_color}[{f.get('status')}]\033[0m {f.get('endpoint')}")
            print(f"    → {f.get('details')}")
    else:
        print("\033[92mNo findings or check failed.\033[0m")

def print_graphql_scanner(results):
    print_result_header("GRAPHQL SCANNER")
    if "error" in results:
         print(f"\033[91mError: {results['error']}\033[0m")
         return
         
    target = results.get("target", "Unknown")
    print(f"\033[94mTarget:\033[0m {target}")
    
    intro = results.get("introspection", {})
    depth = results.get("depth_limit", {})
    
    print("\n\033[94m[1] Introspection Check:\033[0m")
    status = intro.get("status", "Unknown")
    color = "\033[91m" if status == "Vulnerable" else "\033[92m"
    print(f"  Status: {color}{status}\033[0m")
    print(f"  Details: {intro.get('details', '')}")
    
    print("\n\033[94m[2] Query Depth Limit:\033[0m")
    status = depth.get("status", "Unknown")
    color = "\033[91m" if status == "Vulnerable" else "\033[92m"
    print(f"  Status: {color}{status}\033[0m")
    print(f"  Details: {depth.get('details', '')}")

async def main():
    # Clear terminal and display banner
    clear_terminal()
    display_banner()

    print("\033[92m[✔] All required modules are successfully loaded!\033[0m\n")
    print("\033[94mWhat's Next:\033[0m Prepare to analyze the domain for detailed insights.\n")

    # Prompt user for domain input
    domain = input("\033[92mPlease enter a domain name (e.g., example.com): \033[0m")

    # Select modules to run
    selected_modules, run_all = select_modules()

    # Collect additional inputs if needed
    extra_inputs = {}
    if "API Fuzzer" in selected_modules or run_all:
         schema_in = input("\033[92m[Optional] Enter OpenAPI/Swagger Schema URL (Enter to skip): \033[0m").strip()
         if schema_in:
             extra_inputs["schema_url"] = schema_in
             print(f"\033[94m[i] Using Schema: {schema_in}\033[0m")
         else:
             print("\033[93m[!] No Schema URL provided. API Fuzzer may fail.\033[0m")

    # Collect results in a dictionary
    all_results = {}
    print(f"\n\033[94m[➤] Starting analysis for: {domain}\033[0m")

    # Mapping of module names to print functions
    # Using specific print functions maintains the detailed CLI output
    printers = {
        "Domain Information": print_domain_info,
        "DNS Records": print_dns_records,
        "Advanced Content Scan": print_content_scan,
        "CloudFlare Bypass": print_cloudflare_bypass,
        "CloudFlare Bypass": print_cloudflare_bypass,
        "API Fuzzer": print_api_fuzzer,
        "GraphQL Scanner": print_graphql_scanner,
        # Default fallback for others
    }

    # Execute modules
    for module_name in selected_modules:
        print(f"\n> Running {module_name}...")
        try:
             # Handle dependencies manually for now in the loop if needed
             kwargs = {}
             if module_name == "Subdomain Takeover":
                 # Use subdomains found so far
                 kwargs["subdomains"] = all_results.get("Subdomains", [])
                 if not kwargs["subdomains"] and "Subdomain Discovery" in selected_modules and "Subdomain Discovery" not in all_results:
                     # This implies order dependency. 
                     # For now rely on user selecting Discovery or engine handling it.
                     pass 

             if module_name in ["Metasploit Suggester", "Active Pentest", "MSF Deep Scan"]:
                 kwargs["existing_results"] = all_results
             
             if module_name == "API Fuzzer":
                 kwargs.update(extra_inputs)

             result = await engine.manager.run_module(module_name, domain, **kwargs)
             all_results[module_name] = result

             # Use custom printer if available
             if module_name in printers:
                 printers[module_name](result)
             elif module_name == "Subdomain Takeover":
                 print_subdomain_takeover(result, f"logs/{domain}")
             else:
                 # Generic Printer
                 if isinstance(result, dict) and "error" in result:
                     print(f"\033[91m[Error] {result['error']}\033[0m")
                 else:
                     # Very basic dump for others for now to prove concept
                     # Modify this to match original extensive printing if needed
                     import pprint
                     pprint.pprint(result, indent=2)

        except Exception as e:
            print(f"\033[91m[!] Error running {module_name}: {e}\033[0m")

    # Save results
    save_results_to_json(domain, all_results)


if __name__ == "__main__":
    asyncio.run(main())
