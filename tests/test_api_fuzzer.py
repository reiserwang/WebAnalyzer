import unittest
from unittest.mock import MagicMock, patch
from modules.api_fuzzer import APIFuzzer

class TestAPIFuzzer(unittest.TestCase):
    def setUp(self):
        self.fuzzer = APIFuzzer()
        
    @patch('requests.get')
    def test_parse_open_api(self, mock_get):
        # Mock Response
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "paths": {
                "/users/{id}": {
                    "get": {
                        "parameters": [
                            {"name": "id", "in": "path"}
                        ]
                    }
                }
            }
        }
        mock_get.return_value = mock_resp
        
        endpoints = self.fuzzer._parse_open_api("http://mock-schema")
        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0]['path'], "/users/{id}")
        self.assertEqual(endpoints[0]['params'], ["id"])

    @patch('requests.get')
    def test_test_endpoint_bola(self, mock_get):
        # Mock Response for fuzzed request
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp
        
        endpoint = {
            "path": "/users/{id}",
            "method": "GET",
            "params": ["id"]
        }
        
        result = self.fuzzer._test_endpoint("http://api.com", endpoint)
        self.assertIn("Status 200", result['details'])
        self.assertEqual(result['status'], "Tested")

if __name__ == '__main__':
    unittest.main()
