from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context

def register_namespace_tools(mcp: FastMCP):
	"""Register namespace-related tools in the MCP instance."""
	
	@mcp.tool()
	def list_namespaces(offset: int = 0, limit: int = 100) -> list:
		"""
		List all non-global namespaces in the program with pagination.
		
		Args:
			offset: Pagination offset for starting position (default: 0)
			limit: Maximum number of namespaces to return (default: 100)
			
		Returns:
			List of namespace names and their hierarchical paths
		"""

		return ghidra_context.http_client.safe_get("namespaces", {"offset": offset, "limit": limit})
