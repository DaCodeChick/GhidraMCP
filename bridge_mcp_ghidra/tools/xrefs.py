import json
from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context, GhidraValidationError, validate_hex_address

def register_xref_tools(mcp: FastMCP):
	"""Register cross-reference related tools."""

	@mcp.tool()
	def get_bulk_xrefs(addresses: str) -> str:
		"""
		Get cross-references for multiple addresses in a single batch request.

		This tool retrieves xrefs for multiple addresses simultaneously, dramatically
		reducing the number of network round-trips required for byte-by-byte analysis.

		Args:
			addresses: Comma-separated list of hex addresses (e.g., "0x6fb835b8,0x6fb835b9,0x6fb835ba")
					or JSON array string (e.g., '["0x6fb835b8", "0x6fb835b9"]')

		Returns:
			JSON string with xref mappings:
			{
			"0x6fb835b8": [{"from": "0x6fb6cae9", "type": "DATA"}],
			"0x6fb835b9": [],
			"0x6fb835ba": [],
			"0x6fb835bc": [{"from": "0x6fb6c9fe", "type": "READ"}]
			}
		"""

		# Parse input - support both comma-separated and JSON array
		addr_list = []
		if addresses.startswith('['):
			try:
				addr_list = json.loads(addresses)
			except:
				raise GhidraValidationError("Invalid JSON array format for addresses")
		else:
			addr_list = [addr.strip() for addr in addresses.split(',')]

		# Validate all addresses
		for addr in addr_list:
			if not validate_hex_address(addr):
				raise GhidraValidationError(f"Invalid hex address format: {addr}")

		data = {"addresses": addr_list}
		result = ghidra_context.http_client.safe_post_json("get_bulk_xrefs", data)

		# Format the JSON response for readability
		try:
			parsed = json.loads(result)
			return json.dumps(parsed, indent=2)
		except:
			return result

	@mcp.tool()
	def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
		"""
		Get all references to the specified function by name.
		
		Args:
			name: Function name to search for
			offset: Pagination offset (default: 0)
			limit: Maximum number of references to return (default: 100)
			
		Returns:
			List of references to the specified function
		"""

		return ghidra_context.http_client.safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

	@mcp.tool()
	def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
		"""
		Get all references from the specified address (xref from).
		
		Args:
			address: Source address in hex format (e.g. "0x1400010a0")
			offset: Pagination offset (default: 0)
			limit: Maximum number of references to return (default: 100)
			
		Returns:
			List of references from the specified address
		"""

		if not validate_hex_address(address):
			raise GhidraValidationError(f"Invalid hexadecimal address: {address}")
		
		return ghidra_context.http_client.safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

	@mcp.tool()
	def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
		"""
		Get all references to the specified address (xref to).
		
		Args:
			address: Target address in hex format (e.g. "0x1400010a0")
			offset: Pagination offset (default: 0)
			limit: Maximum number of references to return (default: 100)
			
		Returns:
			List of references to the specified address
		"""

		if not validate_hex_address(address):
			raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

		return ghidra_context.http_client.safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})
