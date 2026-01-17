import pytest
import asyncio
from api.engine import AnalyzerEngine
from api.schemas import ScanRequest
from modules.nmap_zero_day import UltraAdvancedNetworkScanner

# Mocking manager to avoid loading all modules for unit test
from unittest.mock import MagicMock, AsyncMock

def test_scan_request_schema():
    req = ScanRequest(domain="192.168.1.0/24", scan_mode="local")
    assert req.scan_mode == "local"
    assert req.domain == "192.168.1.0/24"

def test_engine_local_mode_filtering():
    async def _test():
        engine = AnalyzerEngine()
        # Mock manager to return list of all modules
        engine.manager = MagicMock()
        engine.manager.get_available_modules.return_value = [
            "SEO Analysis", "Port Scan", "IoT Scanner", "Domain Information", "Network Topology"
        ]
        engine.manager.run_module = AsyncMock(return_value={"status": "mocked"})
        
        # Run scan with local mode
        await engine.run_scan("192.168.1.0/24", scan_mode="local")
        
        # Check calls to run_module
        # Should ONLY call: Port Scan, IoT Scanner, Network Topology
        # Should NOT call: SEO Analysis, Domain Information
        
        calls = [args[0] for args, _ in engine.manager.run_module.call_args_list]
        
        assert "Port Scan" in calls
        assert "IoT Scanner" in calls
        assert "Network Topology" in calls
        assert "SEO Analysis" not in calls
        assert "Domain Information" not in calls

    asyncio.run(_test())

def test_nmap_dns_resolve_ip_cidr():
    scanner = UltraAdvancedNetworkScanner(domain="default")
    
    # Test IP
    res_ip = scanner.dns_resolve("192.168.1.1")
    assert res_ip['ipv4'] == "192.168.1.1"
    assert 'error' not in res_ip
    
    # Test CIDR
    res_cidr = scanner.dns_resolve("192.168.1.0/24")
    assert res_cidr['ipv4'] == "192.168.1.0/24"
    assert 'error' not in res_cidr

def test_nmap_dns_resolve_domain():
    # If we can resolve localhost (or mock it), good.
    # But mainly testing the bypass logic didn't break things.
    # We won't test actual DNS resolution here as it depends on network.
    pass
