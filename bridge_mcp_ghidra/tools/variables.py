from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context, validate_function_name, validate_hex_address

def register_variable_tools(mcp: FastMCP):
	"""Register variable-related tools in the MCP server."""

	@mcp.tool()
	def batch_rename_variables(
		function_address: str,
		variable_renames: dict
	) -> str:
		"""
		Rename multiple variables in a function atomically (v1.6.0).

		This tool renames multiple local variables or parameters in a single
		transaction with partial success reporting.

		Args:
			function_address: Function address in hex format (e.g., "0x401000")
			variable_renames: Dict of {"old_name": "new_name"} pairs

		Returns:
			JSON with detailed results:
			{
			"success": true,
			"variables_renamed": 5,
			"variables_failed": 1,
			"errors": [{"old_name": "var1", "error": "Variable not found"}]
			}

		Example:
			batch_rename_variables("0x6fb385a0", {
				"param_1": "eventRecord",
				"local_4": "playerNode",
				"iVar1": "skillIndex"
			})
		"""
		validate_hex_address(function_address)

		payload = {
			"function_address": function_address,
			"variable_renames": variable_renames or {}
		}

		return ghidra_context.http_client.safe_post_json("batch_rename_variables", payload)

	@mcp.tool()
	def batch_set_variable_types(
		function_address: str,
		variable_types: dict
	) -> str:
		"""
		Set types for multiple variables in a single operation (v1.5.0).

		Args:
			function_address: Function address in hex format
			variable_types: Dict of {"variable_name": "type_name"}

		Returns:
			JSON with success status and count of variables typed
		"""
		validate_hex_address(function_address)

		payload = {
			"function_address": function_address,
			"variable_types": variable_types or {}
		}

		return ghidra_context.http_client.safe_post_json("batch_set_variable_types", payload)

	@mcp.tool()
	def get_function_variables(
		function_name: str
	) -> str:
		"""
		List all variables in a function including parameters and locals (v1.5.0).

		Args:
			function_name: Name of the function

		Returns:
			JSON with function variables including names, types, and storage locations
		"""
		validate_function_name(function_name)

		params = {"function_name": function_name}
		return ghidra_context.http_client.safe_get("get_function_variables", params)

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
