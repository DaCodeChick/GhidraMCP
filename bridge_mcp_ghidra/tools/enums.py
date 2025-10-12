from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context

def register_enum_tools(mcp: FastMCP):
	"""Register enum tools for Ghidra context."""

	@mcp.tool()
	def create_enum(name: str, values: dict, size: int = 4) -> str:
		"""
		Create a new enumeration data type with name-value pairs.
		
		This tool creates an enumeration type that can be applied to memory locations
		to provide meaningful names for numeric values.
		
		Args:
			name: Name for the new enumeration
			values: Dictionary of name-value pairs (e.g., {"OPTION_A": 0, "OPTION_B": 1})
			size: Size of the enum in bytes (1, 2, 4, or 8, default: 4)
			
		Returns:
			Success/failure message with created enumeration details
			
		Example:
			values = {"STATE_IDLE": 0, "STATE_RUNNING": 1, "STATE_STOPPED": 2}
		"""

		return ghidra_context.http_client.safe_post_json("create_enum", {"name": name, "values": values, "size": size})

	@mcp.tool()
	def get_enum_values(enum_name: str) -> str:
		"""
		Get all values and names in an enumeration.
		
		Args:
			enum_name: Name of the enumeration to query
			
		Returns:
			List of all enumeration values with their names and numeric values
		"""

		return ghidra_context.http_client.safe_get("get_enum_values", {"enum_name": enum_name})
