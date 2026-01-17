# Security Feature Expansion Plan

## 1. Objective
Add new security scanning capabilities focusing on **FRP (Fast Reverse Proxy)** detection and **Advanced Security Policy (CSP/COOP/CORP)** analysis (interpreted from "COSP").

## 2. New Modules

### A. FRP Detector (`modules/frp_scanner.py`)
**Goal:** Detect if the target domain or IP is hosting an FRP instance or is being proxied via FRP.
**Features:**
- **Port Scan:** Check common FRP ports (Default: `7000` for server, `7500` for dashboard, `80`, `443`).
- **Signature Detection:**
  - HTTP Headers: Check for custom headers that might leak FRP usage.
  - HTML Content: Look for "frp dashboard" title or specific static asset paths associated with the FRP dashboard.
  - Error Pages: Analyze 404/500 pages for FRP-specific error messages.
- **Behavior:**
  - Fast fail if ports are closed.
  - Low false-positive rate by using specific string matching.

### B. Advanced Policy Analyzer (`modules/policy_analyzer.py`)
**Goal:** Deep analysis of Content Security Policy (CSP) and Cross-Origin policies (COOP, CORP, COEP).
**Features:**
- **CSP Analysis:**
  - Parse `Content-Security-Policy` header.
  - **Weakness Detection:**
    - `unsafe-inline`, `unsafe-eval` usage.
    - Wildcard (`*`) sources in critical directives (`script-src`, `object-src`).
    - Missing `default-src` or `frame-ancestors`.
    - `data:` or `http:` schemes in sources.
  - **Score:** Calculate a security score based on CSP strength.
- **Cross-Origin Policies (The "COSP" Suite):**
  - **COOP (Cross-Origin-Opener-Policy):** Check for `same-origin` or `same-origin-allow-popups`.
  - **CORP (Cross-Origin-Resource-Policy):** Check for `same-site`, `same-origin`, or `cross-origin`.
  - **COEP (Cross-Origin-Embedder-Policy):** Check for `require-corp`.
- **Reporting:** Provide a detailed breakdown of policy gaps and recommendations.

## 3. Integration
- **`main.py` & `api/main.py`:**
  - Register new modules.
  - Add to the CLI selection menu.
  - Add to the API response.
- **`utils/utils.py`:** Ensure JSON serialization handles the new data structures.

## 4. Implementation Steps
1.  **Draft `modules/frp_scanner.py`**: Implement port check and HTTP signature matching.
2.  **Draft `modules/policy_analyzer.py`**: Implement header parsing and vulnerability logic.
3.  **Update `main.py`**: Add the new options "FRP Detection" and "Security Policy Audit".
4.  **Test**: Run against a local test server or known targets (if authorized).
5.  **Refine**: Handle edge cases (missing headers, multiple headers).

## 5. Timeline
- **Phase 1:** Policy Analyzer (Foundation for "COSP")
- **Phase 2:** FRP Detector
- **Phase 3:** Integration & Testing
