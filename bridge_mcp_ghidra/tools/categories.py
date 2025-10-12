from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context, GhidraValidationError

def register_category_tools(mcp: FastMCP):
	"""Register category tools for Ghidra context."""

	@mcp.tool()
	def create_data_type_category(category_path: str) -> str:
		"""
		Create a new data type category.
		
		This tool creates a new category for organizing data types.
		
		Args:
			category_path: Path for the new category (e.g., "MyTypes" or "MyTypes/SubCategory")
			
		Returns:
			Success or failure message with category creation details
		"""

		if not category_path or not isinstance(category_path, str):
			raise GhidraValidationError("Category path is required and must be a string")

		return ghidra_context.http_client.safe_post_json("create_data_type_category", {"category_path": category_path})

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
	def move_data_type_to_category(type_name: str, category_path: str) -> str:
		"""
		Move a data type to a different category.
		
		This tool moves an existing data type to a specified category.
		
		Args:
			type_name: Name of the data type to move
			category_path: Target category path
			
		Returns:
			Success or failure message with move operation details
		"""

		if not type_name or not isinstance(type_name, str):
			raise GhidraValidationError("Type name is required and must be a string")
		if not category_path or not isinstance(category_path, str):
			raise GhidraValidationError("Category path is required and must be a string")

		return ghidra_context.http_client.safe_post_json("move_data_type_to_category", {
			"type_name": type_name,
			"category_path": category_path
		})
