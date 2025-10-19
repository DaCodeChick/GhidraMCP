from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context

def register_global_tools(mcp: FastMCP):
	"""Register global tools for Ghidra integration."""

	@mcp.tool()
	def get_data_by_label(label: str) -> str:
		"""
		Get information about a data label.

		Args:
			label: Exact symbol / label name to look up in the program.

		Returns:
			A newline-separated string.  
			Each line has:  "<label> -> <address> : <value-representation>"
			If the label is not found, an explanatory message is returned.
		"""

		return "\n".join(ghidra_context.http_client.safe_get("get_data_by_label", {"label": label}))

	@mcp.tool()
	def list_exports(offset: int = 0, limit: int = 100) -> list:
		"""
		List exported functions/symbols with pagination.
		
		Args:
			offset: Pagination offset for starting position (default: 0)
			limit: Maximum number of exports to return (default: 100)
			
		Returns:
			List of exported functions/symbols with their names and addresses
		"""

		return ghidra_context.http_client.safe_get("exports", {"offset": offset, "limit": limit})

	@mcp.tool()
	def list_globals(offset: int = 0, limit: int = 100, filter: str = None) -> list:
		"""
		List matching globals in the database (paginated, filtered).
		
		Lists global variables and symbols in the program with optional filtering.
		
		Args:
			offset: Pagination offset (default: 0)
			limit: Maximum number of globals to return (default: 100)
			filter: Optional filter to match global names (default: None)
			
		Returns:
			List of global variables/symbols with their details
		"""

		params = {"offset": offset, "limit": limit}
		if filter:
			params["filter"] = filter
		return ghidra_context.http_client.safe_get("list_globals", params)

	@mcp.tool()
	def list_imports(offset: int = 0, limit: int = 100) -> list:
		"""
		List imported symbols in the program with pagination.
		
		Args:
			offset: Pagination offset for starting position (default: 0)
			limit: Maximum number of imports to return (default: 100)
			
		Returns:
			List of imported symbols with their names and addresses
		"""

		return ghidra_context.http_client.safe_get("imports", {"offset": offset, "limit": limit})

	@mcp.tool()
	def rename_global_variable(old_name: str, new_name: str) -> str:
		"""
		Rename a global variable.
		
		Changes the name of a global variable or symbol in the program.
		
		Args:
			old_name: Current name of the global variable
			new_name: New name for the global variable
			
		Returns:
			Success/failure message
		"""

		return ghidra_context.http_client.safe_post("rename_global_variable", {
			"old_name": old_name,
			"new_name": new_name
		})
