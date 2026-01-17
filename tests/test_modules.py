import pytest
from unittest.mock import patch, Mock
from modules.subdomain_takeover import SubdomainTakeover

@pytest.fixture
def subdomain_takeover():
    return SubdomainTakeover(domain="example.com")

@patch('dns.resolver.resolve')
def test_check_dns_configuration(mock_resolve, subdomain_takeover):
    # Mock DNS resolution
    mock_resolve.side_effect = [
        [Mock(to_text=lambda: '1.2.3.4')],  # A records
        [Mock(to_text=lambda: '2606:2800:220:1:248:1893:25c8:1946')],  # AAAA records
        [Mock(target='example.com.s3.amazonaws.com')],  # CNAME records
        [Mock(exchange='mail.example.com')],  # MX records
        [Mock(to_text=lambda: 'v=spf1 mx -all')],  # TXT records
        [Mock(to_text=lambda: 'ns1.example.com')],  # NS records
    ]
    
    dns_info = subdomain_takeover.check_dns_configuration("sub.example.com")
    
    assert dns_info["has_valid_dns"]
    assert dns_info["a_records"] == ['1.2.3.4']
    assert dns_info["aaaa_records"] == ['2606:2800:220:1:248:1893:25c8:1946']
    assert dns_info["cname_records"] == ['example.com.s3.amazonaws.com']
    assert dns_info["mx_records"] == ['mail.example.com']
    assert dns_info["txt_records"] == ['v=spf1 mx -all']
    assert dns_info["ns_records"] == ['ns1.example.com']

@patch('requests.get')
def test_check_website_availability(mock_get, subdomain_takeover):
    # Mock requests.get
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = "<html><body>Hello</body></html>"
    mock_response.headers = {"Content-Type": "text/html"}
    mock_response.history = []
    mock_get.return_value = mock_response

    website_info = subdomain_takeover.check_website_availability("sub.example.com")
    
    assert website_info["is_accessible"]
    assert website_info["http_status"] == 200
    assert website_info["https_status"] == 200
    assert "Hello" in website_info["http_response"]
    assert "Hello" in website_info["https_response"]
