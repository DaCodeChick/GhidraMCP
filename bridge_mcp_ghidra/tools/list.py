from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context, GhidraValidationError

def register_list_tools(mcp: FastMCP):
	"""Register list tools to MCP client."""

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

	@mcp.tool()
	def list_data_items(offset: int = 0, limit: int = 100) -> list:
		"""
		List defined data labels and their values with pagination.
		
		Args:
			offset: Pagination offset for starting position (default: 0)
			limit: Maximum number of data items to return (default: 100)
			
		Returns:
			List of data labels with their addresses, names, and values
		"""

		return ghidra_context.http_client.safe_get("data", {"offset": offset, "limit": limit})

	@mcp.tool()
	def list_data_types(category: str = None, offset: int = 0, limit: int = 100) -> list:
		"""
		List all data types available in the program with optional category filtering.
		
		This tool enumerates all data types defined in the program's data type manager,
		including built-in types, user-defined structs, enums, and imported types.
		
		Args:
			category: Optional category filter (e.g., "builtin", "struct", "enum", "pointer")
			offset: Pagination offset (default: 0)
			limit: Maximum number of data types to return (default: 100)
			
		Returns:
			List of data types with their names, categories, and sizes
		"""

		params = {"offset": offset, "limit": limit}
		if category:
			params["category"] = category
		return ghidra_context.http_client.safe_get("list_data_types", params)

	@mcp.tool()
	def list_data_type_categories(offset: int = 0, limit: int = 100) -> str:
		"""
		List all data type categories.
		
		This tool lists all available data type categories with pagination.
		
		Args:
			offset: Pagination offset (default: 0)
			limit: Maximum number of categories to return (default: 100)
			
		Returns:
			List of data type categories
		"""

		if not isinstance(offset, int) or offset < 0:
			raise GhidraValidationError("Offset must be a non-negative integer")
		if not isinstance(limit, int) or limit <= 0:
			raise GhidraValidationError("Limit must be a positive integer")

		return "\n".join(ghidra_context.http_client.safe_get("list_data_type_categories", {
			"offset": offset,
			"limit": limit
		}))
	
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
	def list_functions(offset: int = 0, limit: int = 100) -> list:
		"""
		List all function names in the program with pagination.
		
		Args:
			offset: Pagination offset for starting position (default: 0)
			limit: Maximum number of functions to return (default: 100)
			
		Returns:
			List of function names with pagination information
		"""

		return ghidra_context.http_client.safe_get("functions", {"offset": offset, "limit": limit})
	
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
