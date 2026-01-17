import pytest
from unittest.mock import Mock, patch
from modules.iot_scanner import IoTScanner

@pytest.fixture
def mock_nmap():
    with patch('nmap.PortScanner') as mock:
        yield mock

def test_iot_scanner_cve_mapping(mock_nmap):
    scanner = IoTScanner(target="192.168.1.10")
    scanner.nm.all_hosts.return_value = ["192.168.1.10"]
    scanner.nm.__getitem__.return_value = {
        'tcp': {
            8000: {'name': 'http', 'product': 'Hikvision IP Camera', 'version': '1.0', 'state': 'open'}
        }
    }
    
    result = scanner.scan()
    
    devices = result.get("devices_found", [])
    assert len(devices) == 1
    service = devices[0]["services"][0]
    
    # Check CVE mapping
    assert "CVE-2021-36260" in service["potential_cves"]
    assert "Hikvision IP Camera" in service["banner"]

def test_iot_scanner_default_creds_unsafe(mock_nmap):
    # Unsafe mode should trigger cred check
    scanner = IoTScanner(target="192.168.1.10", safe_mode=False)
    scanner.nm.all_hosts.return_value = ["192.168.1.10"]
    scanner.nm.__getitem__.return_value = {
        'tcp': {
            22: {'name': 'ssh', 'product': 'OpenSSH', 'version': '7.2', 'state': 'open'}
        }
    }
    
    result = scanner.scan()
    service = result["devices_found"][0]["services"][0]
    
    # Needs to match manual verification text
    assert len(service["weak_credentials"]) > 0
    assert "Manual Verify" in service["weak_credentials"][0]

def test_iot_scanner_default_creds_safe(mock_nmap):
    # Safe mode should NOT trigger cred check
    scanner = IoTScanner(target="192.168.1.10", safe_mode=True)
    scanner.nm.all_hosts.return_value = ["192.168.1.10"]
    scanner.nm.__getitem__.return_value = {
        'tcp': {
            22: {'name': 'ssh', 'product': 'OpenSSH', 'version': '7.2', 'state': 'open'}
        }
    }
    
    result = scanner.scan()
    service = result["devices_found"][0]["services"][0]
    
    assert len(service["weak_credentials"]) == 0
