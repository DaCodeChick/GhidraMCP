from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context

def register_memory_tools(mcp: FastMCP):
	"""Register memory tools to MCP."""

	@mcp.tool()
	def list_segments(offset: int = 0, limit: int = 100) -> list:
		"""
		List all memory segments in the program with pagination.
		
		Args:
			offset: Pagination offset for starting position (default: 0)
			limit: Maximum number of segments to return (default: 100)
			
		Returns:
			List of memory segments with their addresses, names, and properties
		"""

		return ghidra_context.http_client.safe_get("segments", {"offset": offset, "limit": limit})

	@mcp.tool()
	def search_byte_patterns(pattern: str, mask: str = None) -> list:
		"""
		Search for byte patterns with optional masks (e.g., 'E8 ?? ?? ?? ??').
		Useful for finding shellcode, API calls, or specific instruction sequences.
		
		Args:
			pattern: Hexadecimal pattern to search for (e.g., "E8 ?? ?? ?? ??")
			mask: Optional mask for wildcards (use ? for wildcards)
			
		Returns:
			List of addresses where the pattern was found
		"""
		params = {"pattern": pattern}
		if mask:
			params["mask"] = mask
		return ghidra_context.http_client.safe_get("search_byte_patterns", params)

	@mcp.tool()
	def write_bytes(address: str, bytes_hex: str) -> str:
		"""
		Writes a sequence of bytes to the specified address in the program's memory.

		Args:
			address: Destination address (e.g., "0x140001000")
			bytes_hex: Sequence of space-separated bytes in hexadecimal format (e.g., "90 90 90 90")

		Returns:
			Result of the operation (e.g., "Bytes written successfully" or a detailed error)
		"""

		return ghidra_context.http_client.safe_post("write_bytes", {"address": address, "bytes": bytes_hex})
