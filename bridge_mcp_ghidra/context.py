import json
import re
from .client import GhidraHTTPClient, REQUEST_TIMEOUT

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8089/"
DEFAULT_PAGINATION_LIMIT = 100

# Input validation patterns
FUNCTION_NAME_PATTERN = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')
HEX_ADDRESS_PATTERN = re.compile(r'^0x[0-9a-fA-F]+$')

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
	
	def parse_address_list(addresses: str, param_name: str = "addresses") -> list[str]:
		"""
		Parse comma-separated or JSON array of hex addresses with validation.

		Args:
			addresses: Comma-separated addresses or JSON array string
			param_name: Parameter name for error messages (default: "addresses")

		Returns:
			List of validated hex addresses

		Raises:
			GhidraValidationError: If addresses format is invalid or contains invalid hex addresses
		"""

		addr_list = []
		if addresses.startswith('['):
			try:
				addr_list = json.loads(addresses)
			except json.JSONDecodeError as e:
				raise GhidraValidationError(f"Invalid JSON array format for {param_name}: {e}")
		else:
			addr_list = [addr.strip() for addr in addresses.split(',') if addr.strip()]

		# Validate all addresses
		for addr in addr_list:
			if not validate_hex_address(addr):
				raise GhidraValidationError(f"Invalid hex address format: {addr}")

		return addr_list

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

# Global context instance
ghidra_context = GhidraContext()
