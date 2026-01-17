# API Security Testing Requirements

## Feature: API Security Testing (REST/GraphQL)

### User Stories
- As a **security analyst**, I want to provide a **Swagger/OpenAPI URL** so that I can automatically discovery and fuzz API endpoints.
- As a **developer**, I want to scan my **GraphQL endpoint** for introspection vulnerabilities and complexity depth limits.
- As a **pentester**, I want to detect **IDOR (Insecure Direct Object References)** by fuzzing ID parameters in API requests.

### Functional Requirements

#### 1. REST API Scanner (`modules/api_fuzzer.py`)
1.  **Schema Discovery**:
    - Must verify if a URL is a Swagger/OpenAPI definition (JSON/YAML).
    - Must parse paths, methods (GET/POST/PUT/DELETE), and parameters from the schema.
2.  **Fuzzing Engine**:
    - Must fuzz path parameters (e.g., `/users/{id}`) with common payloads (SQLi, XSS, weird integers).
    - Must test for **BOLA/IDOR**: Iterate IDs (1, 2, 1000) to check for unauthorized access.
    - Must support "Safe Mode" (no DELETE/PUT requests) by default.
3.  **Authentication**:
    - Must support adding a custom `Authorization` header (Bearer token) or API Key.

#### 2. GraphQL Scanner (`modules/graphql_scanner.py`)
1.  **Introspection Check**:
    - Must check if Introspection Query is enabled.
    - If enabled, must dump the full schema (queries, mutations, types).
2.  **Suggestion Engine (Clairvoyance)**:
    - If introspection is disabled, must try multiple common field names (brute-force field guessing).
3.  **Complexity Analysis**:
    - Must detect if the API accepts deeply nested queries (prevent DoS).
    - Payload: `{ user { posts { author { posts { ... } } } } }`

#### 3. Integration
1.  **CLI/API**:
    - New inputs: `--api-schema <url>` and `--graphql-url <url>`.
    - New output section: "API Security Analysis".

### Acceptance Criteria
- [ ] **Schema Parsing**: Successfully extracts endpoints from a valid Swagger v2/v3 JSON.
- [ ] **GraphQL Introspection**: Accurately reports Enabled/Disabled status.
- [ ] **Fuzzing Safety**: Does not send DELETE requests unless `--unsafe` is specified via config.
- [ ] **Error Handling**: Gracefully handles invalid schemas or network timeouts.
