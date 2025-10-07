from .client import GhidraHTTPClient

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8089/"
DEFAULT_REQUEST_TIMEOUT = 30

class GhidraContext:
    def __init__(self, server_url: str = DEFAULT_GHIDRA_SERVER, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        self.server_url = server_url
        self.timeout = timeout
        self._http_client = None
    
    @property
    def http_client(self):
        if self._http_client is None:
            self._http_client = GhidraHTTPClient(self.server_url, self.timeout)
        return self._http_client
    
    def update_config(self, server_url: str = None, timeout: int = None):
        """Update configuration and reset HTTP client."""
        if server_url:
            self.server_url = server_url
        if timeout is not None:
            self.timeout = timeout
        self._http_client = None

# Global context instance
ghidra_context = GhidraContext()
