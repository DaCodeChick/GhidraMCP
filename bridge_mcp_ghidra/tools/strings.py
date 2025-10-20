from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context

def register_string_tools(mcp: FastMCP):
	"""Register string manipulation tools in the MCP server."""

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
