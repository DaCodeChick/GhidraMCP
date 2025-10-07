from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context

def register_search_tools(mcp: FastMCP):
	"""Register search tools in the MCP instance."""

	@mcp.tool()
	def search_bytes(bytes_hex: str, offset: int = 0, limit: int = 100) -> list:
		"""
		Search the whole program for a specific byte sequence.

		Args:
			bytes_hex: Byte sequence encoded as a hex string
					(e.g. "DEADBEEF" or "DE AD BE EF").
			offset:    Pagination offset for results (default: 0).
			limit:     Maximum number of hit addresses to return (default: 100).

		Returns:
			A list of addresses (as hex strings) where the sequence was found,
			subject to pagination.  If no hits, an explanatory message list
			such as ["No matches found"] is returned.
		"""
		return ghidra_context.http_client.safe_get(
			"search_bytes",
			{"bytes": bytes_hex, "offset": offset, "limit": limit},
		)

	@mcp.tool()
	def search_data_types(pattern: str, offset: int = 0, limit: int = 100) -> list:
		"""
		Search for data types by name pattern.
		
		Args:
			pattern: Search pattern to match against data type names
			offset: Pagination offset (default: 0)
			limit: Maximum number of results to return (default: 100)
			
		Returns:
			List of matching data types with their details
		"""
		return ghidra_context.http_client.safe_get("search_data_types", {"pattern": pattern, "offset": offset, "limit": limit})

	@mcp.tool()
	def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
		"""
		Search for functions whose name contains the given substring.
		
		Args:
			query: Search string to match against function names
			offset: Pagination offset for starting position (default: 0)
			limit: Maximum number of results to return (default: 100)
			
		Returns:
			List of matching functions with their names and addresses
		"""
		if not query:
			return ["Error: query string is required"]
		return ghidra_context.http_client.safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})
