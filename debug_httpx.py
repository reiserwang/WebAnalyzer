try:
    from httpx import TestClient
    print("Successfully imported TestClient from httpx")
except ImportError as e:
    print(f"Failed to import TestClient from httpx: {e}")
