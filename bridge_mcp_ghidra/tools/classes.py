from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context

def register_class_tools(mcp: FastMCP):
	"""Register class-related tools to the FastMCP instance."""

	@mcp.tool()
	def list_classes(offset: int = 0, limit: int = 100) -> list:
		"""
		List all namespace/class names in the program with pagination.
		
		Args:
			offset: Pagination offset for starting position (default: 0)
			limit: Maximum number of classes to return (default: 100)
			
		Returns:
			List of namespace/class names with pagination information
		"""

		return ghidra_context.http_client.safe_get("classes", {"offset": offset, "limit": limit})
