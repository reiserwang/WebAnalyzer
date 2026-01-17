# API Security Testing Implementation Plan

> **For Agent:** Use executing-plans skill to implement this plan task-by-task.

**Goal:** Add REST API fuzzing and GraphQL security scanning capabilities to WebAnalyzer.

**Architecture:** Two new `BaseModule` implementations (`APIFuzzer`, `GraphQLScanner`) that run standalone. `APIFuzzer` consumes OpenAPI schemas to generate safe test traffic. `GraphQLScanner` checks introspection and query depth.

**Tech Stack:** `requests`, `PyYAML` (needs addition to requirements.txt).

---

### Task 1: Dependencies & Skeleton

**Files:**
- Modify: `requirements.txt`
- Create: `modules/api_fuzzer.py` (Skeleton)
- Create: `modules/graphql_scanner.py` (Skeleton)

**Step 1: Update requirements**
Add `PyYAML` to `requirements.txt`.

**Step 2: Create APIFuzzer Skeleton**
Create the class inheriting `BaseModule` with a basic `run` method returning a placeholder dict.

**Step 3: Create GraphQLScanner Skeleton**
Create the class inheriting `BaseModule` with a basic `run` method returning a placeholder dict.

---

### Task 2: GraphQL Scanner Implementation

**Files:**
- Modify: `modules/graphql_scanner.py`

**Step 1: Introspection Logic**
Implement `_check_introspection(target_url)` which sends a standard introspection query.
Returns: `{"enabled": True, "schema_snapshot": "..."}` or `{"enabled": False}`.

**Step 2: Depth Limit Logic**
Implement `_check_query_depth(target_url)` which sends a nested query 5-10 levels deep.
Returns: `{"depth_check": "Safe" | "Vulnerable"}`.

**Step 3: Run Method**
Orchestrate the above methods in `run()`.

---

### Task 3: REST API Fuzzer Implementation

**Files:**
- Modify: `modules/api_fuzzer.py`

**Step 1: Schema Parsers**
Implement `_parse_open_api(url_or_file)` that fetches and parses JSON/YAML into a list of endpoints: `[{"path": "/users/{id}", "method": "GET", "params": ["id"]}]`.

**Step 2: Fuzzing Engine**
Implement `_test_endpoint(endpoint)`:
- If param is "id" or "user_id": Try BOLA payloads (1, 2, 99999).
- If string param: Try basic XSS probe `<script>`.
- **Constraint:** Respect "Safe Mode" (no DELETE methods).

**Step 3: Run Method**
Orchestrate parsing and fuzzing in `run()`.

---

### Task 4: CLI & Manager Integration

**Files:**
- Modify: `main.py`
- Modify: `api/engine.py`

**Step 1: Register Modules**
Ensure `ModuleManager` picks up the new modules (auto-discovery should handle this if in `modules/`, but verify explicit imports if needed in `api/engine.py`).

**Step 2: CLI Options**
Update `main.py` input loop to ask for "API Schema URL" if "API Fuzzer" module is selected.
Update `main.py` input loop to ask for "GraphQL Endpoint" if "GraphQL Scanner" module is selected.

---

### Task 5: Frontend Integration

**Files:**
- Create: `web/src/modules/definitions/APIFuzzer.jsx`
- Create: `web/src/modules/definitions/GraphQLScanner.jsx`
- Modify: `web/src/modules/index.js`
- Modify: `web/src/components/ScannerForm.jsx`

**Step 1: Create React Components**
Create result viewers for the new JSON outputs.
- `APIFuzzer.jsx`: Table of fuzzed endpoints and findings.
- `GraphQLScanner.jsx`: Status badge for Introspection and Depth Check.

**Step 2: Register in Frontend**
Import and add to `common/modules/index.js` `MODULE_DEFINITIONS`.

**Step 3: UI Inputs**
Update `ScannerForm.jsx` to conditionally show "API Schema URL" input field when those modules are toggled.

---

### Task 6: Verification

**Files:**
- Test: `tests/test_api_fuzzer.py`

**Step 1: Mock Test**
Verify `APIFuzzer` correctly parses a dummy JSON schema and produces expected fuzz requests (mock `requests.get`).

