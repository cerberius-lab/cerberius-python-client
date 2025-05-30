import unittest
from unittest.mock import patch, MagicMock
import time
import requests # Required for requests.exceptions.HTTPError and requests.exceptions.Timeout

from cerberius_python_client import CerberiusClient, CerberiusAPIError
from cerberius_python_client.models import (
    EmailLookupResponse, EmailData,
    IPLookupResponse, IPData,
    PromptGuardResponse, PromptGuardData
)

class TestCerberiusClient(unittest.TestCase):
    def setUp(self):
        self.api_key = "test_api_key"
        self.api_secret = "test_api_secret"
        self.client = CerberiusClient(api_key=self.api_key, api_secret=self.api_secret)

    def tearDown(self):
        self.client.close() # Ensure session is closed

    def test_client_initialization(self):
        self.assertEqual(self.client.api_key, self.api_key)
        self.assertEqual(self.client.api_secret, self.api_secret)

    def test_client_initialization_empty_key(self):
        with self.assertRaisesRegex(ValueError, "API key cannot be empty."):
            CerberiusClient(api_key="", api_secret="secret")

    def test_client_initialization_empty_secret(self):
        with self.assertRaisesRegex(ValueError, "API secret cannot be empty."):
            CerberiusClient(api_key="key", api_secret="")

    def test_generate_auth_headers(self):
        headers = self.client._generate_auth_headers()
        self.assertEqual(headers["X-API-Key"], self.api_key)
        self.assertTrue(headers["X-Timestamp"])
        self.assertTrue(headers["X-Signature"])
        self.assertEqual(headers["Content-Type"], "application/json")
        # Further signature validation could be done if we replicate HMAC logic here

    @patch('requests.Session.request')
    def test_lookup_emails_success(self, mock_request):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [{
                "email_address": "test@example.com", "smtp_valid": True, "validity_score": 90
            }],
            "excess_charges_apply": False
        }
        mock_request.return_value = mock_response

        response = self.client.lookup_emails(["test@example.com"])
        self.assertIsInstance(response, EmailLookupResponse)
        self.assertIsNotNone(response.data)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0].email_address, "test@example.com")
        self.assertTrue(response.data[0].smtp_valid)
        self.assertFalse(response.excess_charges_apply)
        mock_request.assert_called_once()

    @patch('requests.Session.request')
    def test_lookup_ips_success(self, mock_request):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [{
                "ip_address": "8.8.8.8", "country": "USA", "isp": "Google"
            }],
            "excess_charges_apply": True
        }
        mock_request.return_value = mock_response

        response = self.client.lookup_ips(["8.8.8.8"])
        self.assertIsInstance(response, IPLookupResponse)
        self.assertIsNotNone(response.data)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0].ip_address, "8.8.8.8")
        self.assertEqual(response.data[0].country, "USA")
        self.assertTrue(response.excess_charges_apply)
        mock_request.assert_called_once()

    @patch('requests.Session.request')
    def test_check_prompt_success(self, mock_request):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "malicious": True, "confidence_score": 99, "comment": "High risk"
            },
            "excess_charges_apply": False
        }
        mock_request.return_value = mock_response

        response = self.client.check_prompt("some malicious prompt")
        self.assertIsInstance(response, PromptGuardResponse)
        self.assertIsNotNone(response.data)
        self.assertTrue(response.data.malicious)
        self.assertEqual(response.data.confidence_score, 99)
        self.assertFalse(response.excess_charges_apply)
        mock_request.assert_called_once()

    @patch('requests.Session.request')
    def test_api_error_401_unauthorized(self, mock_request):
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.json.return_value = {"error": {"code": 100401, "message": "Unauthorized"}}
        # Configure the mock to raise HTTPError for bad status codes
        mock_response.raise_for_status = MagicMock(side_effect=requests.exceptions.HTTPError(response=mock_response))
        mock_request.return_value = mock_response

        with self.assertRaisesRegex(CerberiusAPIError, "Unauthorized") as cm:
            self.client.lookup_emails(["test@example.com"])
        
        self.assertEqual(cm.exception.status_code, 401)
        self.assertEqual(cm.exception.error_code, 100401)

    @patch('requests.Session.request')
    def test_api_error_422_validation(self, mock_request):
        mock_response = MagicMock()
        mock_response.status_code = 422
        mock_response.json.return_value = {"error": {"code": 100422, "message": "Request body validation error"}}
        mock_response.raise_for_status = MagicMock(side_effect=requests.exceptions.HTTPError(response=mock_response))
        mock_request.return_value = mock_response

        with self.assertRaisesRegex(CerberiusAPIError, "Request body validation error") as cm:
            self.client.lookup_ips(["invalid-ip"])
        
        self.assertEqual(cm.exception.status_code, 422)
        self.assertEqual(cm.exception.error_code, 100422)

    @patch('requests.Session.request', side_effect=requests.exceptions.Timeout("Request timed out"))
    def test_network_error_timeout(self, mock_request):
        with self.assertRaisesRegex(CerberiusAPIError, "Request failed: Request timed out"):
            self.client.check_prompt("a prompt")

    def test_lookup_emails_empty_list(self):
        with self.assertRaisesRegex(ValueError, "Email list cannot be empty."):
            self.client.lookup_emails([])

    def test_lookup_ips_empty_list(self):
        with self.assertRaisesRegex(ValueError, "IP list cannot be empty."):
            self.client.lookup_ips([])

    def test_check_prompt_empty_text(self):
        with self.assertRaisesRegex(ValueError, "Prompt text cannot be empty."):
            self.client.check_prompt("")

    @patch('requests.Session.request')
    def test_context_manager_usage(self, mock_request):
        # Similar to a success test, but initialize client within a 'with' block
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [{"email_address": "ctx@example.com", "smtp_valid": True}],
            "excess_charges_apply": False
        }
        mock_request.return_value = mock_response

        with CerberiusClient(api_key=self.api_key, api_secret=self.api_secret) as client:
            client.lookup_emails(["ctx@example.com"])
        # mock_request.assert_called_once() # This would be ideal
        # self.client._session.close() was called implicitly by __exit__; 
        # It's harder to assert the session.close() on the temporary client's session.
        # Instead, we can check if the mock_request was called.
        self.assertTrue(mock_request.called)

if __name__ == '__main__':
    unittest.main()
