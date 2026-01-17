# UI Module Categorization Design

## Goal
Organize the flat list of 20+ scanning modules in the frontend into logical, visual categories to improve usability and finding modules.

## Categories

### 1. Reconnaissance (Passive/Safe)
*Modules that gather information without aggressive scanning.*
- Domain Information
- DNS Records
- Contact Spy
- SEO Analysis
- Web Technologies
- Topology Graph

### 2. Discovery (Active/Scanning)
*Modules that actively scan for assets, ports, and services.*
- Subdomain Discovery
- Port Scan
- CloudFlare Bypass
- FRP Scanner
- IoT Scanner

### 3. Vulnerability Assessment
*Modules that analyze specific surfaces for vulnerabilities.*
- Security Analysis
- Advanced Content Scan
- Subdomain Takeover
- Vuln Scanner
- API Fuzzer
- GraphQL Scanner
- Nmap Zero Day Scan

### 4. Exploitation & Deep Scan (High Risk)
*Aggressive modules that might simulate attacks or use Metasploit.*
- Active Pentest
- Metasploit Suggester
- MSF Deep Scan

## Implementation Strategy

1.  **Update `web/src/modules/index.js`**:
    - Export a `MODULE_CATEGORIES` constant mapping category names to module IDs/Names.
    - Maintain the flat `REGISTERED_MODULES` for backward compatibility with the result renderer.

2.  **Update `ScannerForm.jsx`**:
    - Replace the flat list `.map()` with a nested iteration over categories.
    - Use visual separators (headers/borders) for each category.
    - Implement a "Select All in Category" feature (optional but nice).
    - Maintain the logical "Select All" behavior (empty selection = all).

## Visual Style
- **Category Headers**: Bold, slightly larger, offset color (e.g., `#00ff41` for Recon, `#ff3333` for Exploitation).
- **Grid Layout**: Modules within a category displayed in a flex wrap grid.
