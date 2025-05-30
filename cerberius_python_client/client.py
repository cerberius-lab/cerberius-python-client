import hashlib
import hmac
import time
import json
from typing import Optional, Dict, Any, List # Ensure List is imported
import requests # Add requests to pyproject.toml later
import dataclasses # For converting dataclasses to dict

from .models import (
    EmailLookupRequest, EmailLookupResponse, EmailData,
    IPLookupRequest, IPLookupResponse, IPData,
    PromptGuardRequest, PromptGuardResponse, PromptGuardData, Prompt,
    ErrorResponse
)

class CerberiusAPIError(Exception):
    def __init__(self, message: str, status_code: Optional[int] = None, error_code: Optional[int] = None, error_details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.error_details = error_details

    def __str__(self):
        return f"CerberiusAPIError: {self.args[0]} (Status: {self.status_code}, Code: {self.error_code})"

class CerberiusClient:
    BASE_URL = "https://service.cerberius.com/api"

    def __init__(self, api_key: str, api_secret: str, timeout: int = 30):
        if not api_key:
            raise ValueError("API key cannot be empty.")
        if not api_secret:
            raise ValueError("API secret cannot be empty.")
        
        self.api_key = api_key
        self.api_secret = api_secret
        self.timeout = timeout
        self._session = requests.Session()

    def _generate_auth_headers(self) -> Dict[str, str]:
        timestamp = str(int(time.time()))
        message = timestamp + self.api_key
        signature = hmac.new(self.api_secret.encode(), message.encode(), hashlib.sha256).hexdigest()
        
        return {
            "X-API-Key": self.api_key,
            "X-Timestamp": timestamp,
            "X-Signature": signature,
            "Content-Type": "application/json"
        }

    def _request(self, method: str, endpoint: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = f"{self.BASE_URL}{endpoint}"
        headers = self._generate_auth_headers()
        
        try:
            response = self._session.request(method, url, headers=headers, json=data, timeout=self.timeout)
            response.raise_for_status()  # Raises HTTPError for bad responses (4XX or 5XX)
            
            # Check for empty response before trying to parse JSON
            if not response.content:
                return {} # Or raise an error if an empty response is unexpected

            return response.json()

        except requests.exceptions.HTTPError as e:
            # Try to parse error response from Cerberius
            try:
                error_data = e.response.json()
                if "error" in error_data and isinstance(error_data["error"], dict):
                    err_content = error_data["error"]
                    raise CerberiusAPIError(
                        message=err_content.get("message", e.response.text),
                        status_code=e.response.status_code,
                        error_code=err_content.get("code"),
                        error_details=error_data
                    ) from e
                else: # Fallback if error format is unexpected
                     raise CerberiusAPIError(
                        message=e.response.text or "HTTP Error with no specific API error message",
                        status_code=e.response.status_code
                    ) from e
            except json.JSONDecodeError: # If error response is not JSON
                raise CerberiusAPIError(
                    message=e.response.text or "HTTP Error with non-JSON response",
                    status_code=e.response.status_code
                ) from e
        except requests.exceptions.RequestException as e: # Catch other requests errors (timeout, connection error)
            raise CerberiusAPIError(f"Request failed: {e}") from e

    def close(self):
        """Closes the underlying requests session."""
        self._session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def lookup_emails(self, emails: List[str]) -> EmailLookupResponse:
        """
        Validates a list of email addresses.
        Args:
            emails: A list of email strings to validate.
        Returns:
            An EmailLookupResponse object.
        Raises:
            CerberiusAPIError: If the API request fails.
        """
        if not emails:
            raise ValueError("Email list cannot be empty.")
            
        request_data = EmailLookupRequest(data=emails)
        payload = dataclasses.asdict(request_data)
        
        response_json = self._request("POST", "/email-lookup", data=payload)
        
        if 'data' not in response_json and 'excess_charges_apply' not in response_json:
            raise CerberiusAPIError("Malformed response from email-lookup", error_details=response_json)

        return EmailLookupResponse(
            data=[EmailData(**item) for item in response_json.get("data", [])] if response_json.get("data") is not None else None,
            excess_charges_apply=response_json.get("excess_charges_apply")
        )

    def lookup_ips(self, ips: List[str]) -> IPLookupResponse:
        """
        Looks up information on a list of IP addresses.
        Args:
            ips: A list of IP address strings.
        Returns:
            An IPLookupResponse object.
        Raises:
            CerberiusAPIError: If the API request fails.
        """
        if not ips:
            raise ValueError("IP list cannot be empty.")

        request_data = IPLookupRequest(data=ips)
        payload = dataclasses.asdict(request_data)
        
        response_json = self._request("POST", "/ip-lookup", data=payload)

        if 'data' not in response_json and 'excess_charges_apply' not in response_json:
             raise CerberiusAPIError("Malformed response from ip-lookup", error_details=response_json)

        return IPLookupResponse(
            data=[IPData(**item) for item in response_json.get("data", [])] if response_json.get("data") is not None else None,
            excess_charges_apply=response_json.get("excess_charges_apply")
        )

    def check_prompt(self, prompt_text: str) -> PromptGuardResponse:
        """
        Checks if a given prompt text is malicious.
        Args:
            prompt_text: The text of the prompt to check.
        Returns:
            A PromptGuardResponse object.
        Raises:
            CerberiusAPIError: If the API request fails.
        """
        if not prompt_text:
            raise ValueError("Prompt text cannot be empty.")

        request_data = PromptGuardRequest(data=Prompt(prompt=prompt_text))
        payload = dataclasses.asdict(request_data)
        
        response_json = self._request("POST", "/prompt-check", data=payload)

        if 'data' not in response_json and 'excess_charges_apply' not in response_json:
            raise CerberiusAPIError("Malformed response from prompt-check", error_details=response_json)
            
        response_data_item = response_json.get("data")
        parsed_data = PromptGuardData(**response_data_item) if response_data_item else None

        return PromptGuardResponse(
            data=parsed_data,
            excess_charges_apply=response_json.get("excess_charges_apply")
        )
