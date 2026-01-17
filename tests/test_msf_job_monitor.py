import unittest
import sys
from unittest.mock import MagicMock, patch

class TestMSFJobMonitor(unittest.TestCase):
    
    def test_run_success(self):
        # Create a mock for the module
        mock_msfrpc = MagicMock()
        mock_client_cls = MagicMock()
        mock_msfrpc.MsfRpcClient = mock_client_cls
        
        # Setup the client mock
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.jobs.list = {'0': 'Job Zero', '1': 'Job One'}
        
        def side_effect(jid):
            if jid == '0': return {'start_time': 1234567890, 'datastore': {'RHOSTS': '127.0.0.1'}}
            return {}
        mock_client.jobs.info.side_effect = side_effect

        # Patch sys.modules to return our mock
        with patch.dict(sys.modules, {'pymetasploit3.msfrpc': mock_msfrpc}):
            from modules.msf_job_monitor import MSFJobMonitor
            monitor = MSFJobMonitor()
            result = monitor.run()

        self.assertIn('active_jobs_count', result)
        self.assertEqual(result['active_jobs_count'], 2)
        
        # Check specific job details
        job0 = next(j for j in result['jobs'] if j['id'] == '0')
        self.assertEqual(job0['name'], 'Job Zero')
        self.assertEqual(job0['start_time'], 1234567890) 
        self.assertEqual(job0['status'], 'Running')

    def test_run_connection_error(self):
        # Create a mock that raises exception
        mock_msfrpc = MagicMock()
        mock_client_cls = MagicMock()
        mock_client_cls.side_effect = Exception("Connection refused")
        mock_msfrpc.MsfRpcClient = mock_client_cls
        
        with patch.dict(sys.modules, {'pymetasploit3.msfrpc': mock_msfrpc}):
            from modules.msf_job_monitor import MSFJobMonitor
            monitor = MSFJobMonitor()
            result = monitor.run()
        
        self.assertIn('error', result)
        self.assertIn('Metasploit RPC not connected', result['error'])

if __name__ == '__main__':
    unittest.main()
