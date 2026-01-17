from httpx import TestClient
from api.main import app
from unittest.mock import patch

client = TestClient(app)

def test_health_check():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

@patch('api.engine.AnalyzerEngine.run_scan')
def test_scan(mock_run_scan):
    mock_run_scan.return_value = {"status": "completed"}
    response = client.post("/api/scan", json={"domain": "example.com", "modules": ["web_technologies"]})
    assert response.status_code == 200
    assert response.json() == {"domain": "example.com", "results": {"status": "completed"}}

@patch('modules.subdomain_takeover.SubdomainTakeover.check_takeover_vulnerability')
def test_subdomain_takeover_analysis_non_vulnerable(mock_check_takeover_vulnerability):
    """
    Test the /api/analyze/subdomain-takeover endpoint with a non-vulnerable URL.
    """
    mock_check_takeover_vulnerability.return_value = None
    test_url = "https://www.google.com"
    response = client.get(f"/api/analyze/subdomain-takeover?url={test_url}")
    
    assert response.status_code == 200
    response_data = response.json()
    
    assert "subdomain" in response_data
    assert response_data["subdomain"] == test_url
    assert "message" in response_data
    assert response_data["message"] == "No subdomain takeover vulnerability detected."
    assert response_data["result"] is None
