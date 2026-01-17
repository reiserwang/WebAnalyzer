# Architecture: API Security Testing

## Components

| Component | Responsibility | Interface |
|-----------|---------------|-----------|
| `APIFuzzer` | Parses OpenAPI schemas and fuzzes endpoints. | `run(target: str, schema_url: str = None)` |
| `GraphQLScanner` | Tests GraphQL endpoints for introspection and depth limits. | `run(target: str)` |
| `SchemaParser` | Helper to normalize OpenAPI v2/v3 into a standard list of endpoints. | `parse(json_data: dict) -> List[Endpoint]` |

## Data Flow

```mermaid
graph TD
    CLI[Main CLI / API] --> Manager[ModuleManager]
    
    Manager --> APIMod[APIFuzzer]
    Manager --> GQLMod[GraphQLScanner]
    
    subgraph REST Flow
        APIMod -->|Fetch JSON| Network[Network Request]
        Network -->|Schema| Parser[SchemaParser]
        Parser -->|Endpoints| FuzzerEngine[Fuzzer Engine]
        FuzzerEngine -->|Attack Payloads| TargetAPI[Target REST API]
    end
    
    subgraph GraphQL Flow
        GQLMod -->|Introspection Query| TargetGQL[Target GraphQL API]
        TargetGQL -->|Schema/Error| GQLMod
        GQLMod -->|Nested Query (DoS)| TargetGQL
    end
    
    APIMod -->|Result Dict| Manager
    GQLMod -->|Result Dict| Manager
```

## Tech Stack

| Choice | Justification |
|--------|---------------|
| **`requests`** | Standard HTTP client we already use; robust for REST/GraphQL. |
| **`PyYAML`** | Required to parse some OpenAPI specs that are in YAML format. |
| **`json`** | Native support for standard schemas. |

## Module Boundaries

-   **`modules/api_fuzzer.py`**:
    -   Class `APIFuzzer(BaseModule)`
    -   Internal helper `_parse_open_api(data)`
    -   Internal helper `_fuzz_endpoint(endpoint)`
-   **`modules/graphql_scanner.py`**:
    -   Class `GraphQLScanner(BaseModule)`
    -   Internal helper `_check_introspection()`
    -   Internal helper `_check_query_depth()`
