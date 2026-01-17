from httpx import TestClient
from api.main import app
from unittest.mock import patch

client = TestClient(app)

def test_placeholder():
    assert True  # Placeholder test

def test_health_check():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_subdomain_takeover_analysis_non_vulnerable():
    """
    Test the /api/analyze/subdomain-takeover endpoint with a non-vulnerable URL.
    """
    # Using a known non-vulnerable domain for testing
    test_url = "https://www.google.com"
    response = client.get(f"/api/analyze/subdomain-takeover?url={test_url}")
    
    assert response.status_code == 200
    response_data = response.json()
    
    assert "subdomain" in response_data
    assert response_data["subdomain"] == test_url
    assert "message" in response_data
    assert response_data["message"] == "No subdomain takeover vulnerability detected."
    assert response_data["result"] is None

@patch('modules.subdomain_takeover.SubdomainTakeover.check_takeover_vulnerability')
def test_subdomain_takeover_analysis_vulnerable(mock_check_takeover_vulnerability):
    """
    Test the /api/analyze/subdomain-takeover endpoint with a mock vulnerable URL.
    """
    # Mock a vulnerable response from the SubdomainTakeover module
    mock_check_takeover_vulnerability.return_value = {
        "subdomain": "https://vulnerable.example.com",
        "timestamp": "2024-01-01 12:00:00",
        "dns_info": {
            "a_records": [],
            "aaaa_records": [],
            "cname_records": ["example.github.io"],
            "mx_records": [],
            "txt_records": [],
            "ns_records": [],
            "has_valid_dns": True
        },
        "website_info": {
            "http_status": 200,
            "https_status": 200,
            "response_time": 0.1,
            "http_response": "There isn't a GitHub Pages site here",
            "https_response": "There isn't a GitHub Pages site here",
            "http_headers": {},
            "https_headers": {},
            "ssl_info": None,
            "is_accessible": True,
            "redirect_chain": []
        },
        "whois_info": None,
        "vulnerable": True,
        "service": "GitHub Pages",
        "vulnerability_type": "CNAME Error Pattern",
        "confidence": "High",
        "cname": "example.github.io",
        "description": "The subdomain has a CNAME record pointing to GitHub Pages (example.github.io) and returns an error message indicating the resource doesn't exist.",
        "exploitation_difficulty": "Easy",
        "mitigation": "Remove the CNAME record or reclaim the resource on GitHub Pages. Ensure you've properly set up the service before pointing DNS records to it."
    }

    test_url = "https://vulnerable.example.com"
    response = client.get(f"/api/analyze/subdomain-takeover?url={test_url}")
    
    assert response.status_code == 200
    response_data = response.json()
    
    assert "subdomain" in response_data
    assert response_data["subdomain"] == test_url
    assert "message" in response_data
    assert response_data["message"] == "Subdomain takeover vulnerability detected."
    assert "result" in response_data
    assert response_data["result"] is not None
    assert response_data["result"]["vulnerable"] is True
    assert response_data["result"]["service"] == "GitHub Pages"
    assert response_data["result"]["vulnerability_type"] == "CNAME Error Pattern"
