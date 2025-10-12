from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context

def register_variable_tools(mcp: FastMCP):
	"""Register variable-related tools in the MCP server."""

	@mcp.tool()
	def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
		"""
		Rename a local variable within a function.
		
		Args:
			function_name: Name of the function containing the variable
			old_name: Current name of the variable to rename
			new_name: New name for the variable
			
		Returns:
			Success or failure message indicating the result of the rename operation
		"""

		return ghidra_context.http_client.safe_post("renameVariable", {
			"functionName": function_name,
			"oldName": old_name,
			"newName": new_name
		})
	
	@mcp.tool()
	def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
		"""
		Set a local variable's type.
		
		Args:
			function_address: Memory address of the function in hex format (e.g., "0x1400010a0")
			variable_name: Name of the local variable to modify
			new_type: New data type for the variable (e.g., "int", "char*", "MyStruct")
			
		Returns:
			Success or failure message indicating the result of the type change
		"""

		return ghidra_context.http_client.safe_post("set_local_variable_type", {
			"function_address": function_address,
			"variable_name": variable_name,
			"new_type": new_type
		})
