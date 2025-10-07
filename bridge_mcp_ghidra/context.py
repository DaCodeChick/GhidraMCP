import re
from urllib.parse import urlparse
from .client import GhidraHTTPClient, REQUEST_TIMEOUT

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8089/"
DEFAULT_PAGINATION_LIMIT = 100

# Input validation patterns
HEX_ADDRESS_PATTERN = re.compile(r'^0x[0-9a-fA-F]+$')
FUNCTION_NAME_PATTERN = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')

class GhidraAnalysisError(Exception):
    """Raised when Ghidra analysis operation fails"""
    pass

class GhidraValidationError(Exception):
    """Raised when input validation fails"""
    pass

class GhidraContext:
    def __init__(self, server_url: str = DEFAULT_GHIDRA_SERVER, timeout: int = REQUEST_TIMEOUT):
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
    
    def validate_function_name(name: str) -> bool:
        """Validate function name format"""
        return bool(FUNCTION_NAME_PATTERN.match(name)) if name else False
    
    def validate_hex_address(address: str) -> bool:
        """Validate hexadecimal address format"""
        if not address or not isinstance(address, str):
            return False
        return bool(HEX_ADDRESS_PATTERN.match(address))

    def validate_server_url(url: str) -> bool:
        """Validate that the server URL is safe to use"""
        try:
            parsed = urlparse(url)
            # Only allow HTTP/HTTPS protocols
            if parsed.scheme not in ['http', 'https']:
                return False
            # Only allow local addresses for security
            if parsed.hostname in ['localhost', '127.0.0.1', '::1']:
                return True
            # Allow private network ranges
            if parsed.hostname and (
                parsed.hostname.startswith('192.168.') or
                parsed.hostname.startswith('10.') or
                parsed.hostname.startswith('172.')
            ):
                return True
            return False
        except Exception:
            return False

# Global context instance
ghidra_context = GhidraContext()
