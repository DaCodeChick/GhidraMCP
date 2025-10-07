import requests
import logging
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

class GhidraHTTPClient:
    def __init__(self, server_url: str, timeout: int):
        self.server_url = server_url
        self.timeout = timeout
    
    def safe_get(self, endpoint: str, params: dict = None) -> list:
        """Perform a GET request with optional query parameters."""
        if params is None:
            params = {}

        url = urljoin(self.server_url, endpoint)

        try:
            response = requests.get(url, params=params, timeout=self.timeout)
            response.encoding = 'utf-8'
            if response.ok:
                return response.text.splitlines()
            else:
                return [f"Error {response.status_code}: {response.text.strip()}"]
        except Exception as e:
            return [f"Request failed: {str(e)}"]

    def safe_post(self, endpoint: str, data: dict | str) -> str:
        """Perform a POST request with data."""
        try:
            url = urljoin(self.server_url, endpoint)
            if isinstance(data, dict):
                response = requests.post(url, data=data, timeout=self.timeout)
            else:
                response = requests.post(url, data=data.encode("utf-8"), timeout=self.timeout)
            response.encoding = 'utf-8'
            if response.ok:
                return response.text.strip()
            else:
                return f"Error {response.status_code}: {response.text.strip()}"
        except Exception as e:
            return f"Request failed: {str(e)}"
