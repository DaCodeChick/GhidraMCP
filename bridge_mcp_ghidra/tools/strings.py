import json
from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context, GhidraValidationError, validate_hex_address

def register_string_tools(mcp: FastMCP):
	"""Register string manipulation tools in the MCP server."""

	@mcp.tool()
	def inspect_memory_content(address: str, length: int = 64, detect_strings: bool = True) -> str:
		"""
		Read raw memory bytes and provide hex/ASCII representation with string detection hints.

		This tool helps prevent misidentification of strings as numeric data by:
		- Reading actual byte content in hex and ASCII format
		- Detecting printable ASCII characters and null terminators
		- Calculating string likelihood score
		- Suggesting appropriate data types (char[N] for strings, etc.)

		Args:
			address: Memory address in hex format (e.g., "0x6fb7ffbc")
			length: Number of bytes to read (default: 64)
			detect_strings: Enable string detection heuristics (default: True)

		Returns:
			JSON string with memory inspection results:
			{
			"address": "0x6fb7ffbc",
			"bytes_read": 64,
			"hex_dump": "4A 75 6C 79 00 ...",
			"ascii_repr": "July\\0...",
			"printable_count": 4,
			"printable_ratio": 0.80,
			"null_terminator_at": 4,
			"max_consecutive_printable": 4,
			"is_likely_string": true,
			"detected_string": "July",
			"suggested_type": "char[5]",
			"string_length": 5
			}
		"""

		if not validate_hex_address(address):
			raise GhidraValidationError(f"Invalid hex address format: {address}")

		if not isinstance(length, int) or length <= 0 or length > 4096:
			raise GhidraValidationError("length must be a positive integer <= 4096")

		params = {
			"address": address,
			"length": length,
			"detect_strings": str(detect_strings).lower()
		}

		result = "\n".join(ghidra_context.http_client.safe_get("inspect_memory_content", params))

		# Try to format as JSON for readability
		try:
			parsed = json.loads(result)
			return json.dumps(parsed, indent=2)
		except:
			return result

	@mcp.tool()
	def list_strings(offset: int = 0, limit: int = 100, filter: str = None) -> list:
		"""
		List all defined strings in the program with their addresses.
		
		Args:
			offset: Pagination offset (default: 0)
			limit: Maximum number of strings to return (default: 100)
			filter: Optional filter to match within string content
			
		Returns:
			List of strings with their addresses
		"""

		params = {"offset": offset, "limit": limit}
		if filter:
			params["filter"] = filter
		return ghidra_context.http_client.safe_get("strings", params)
