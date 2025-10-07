from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context, GhidraValidationError

def register_rename_tools(mcp: FastMCP):
	"""Register rename tools."""

	@mcp.tool()
	def batch_rename_functions(renames: dict) -> dict:
		"""
		Rename multiple functions atomically.
		
		Args:
			renames: Dictionary mapping old names to new names
			
		Returns:
			Dictionary with rename results and any errors
		"""
		# Validate all function names
		for old_name, new_name in renames.items():
			if not ghidra_context.validate_function_name(old_name):
				raise GhidraValidationError(f"Invalid old function name: {old_name}")
			if not ghidra_context.validate_function_name(new_name):
				raise GhidraValidationError(f"Invalid new function name: {new_name}")

		return ghidra_context.http_client.safe_get("batch_rename_functions", {"renames": str(renames)})

	@mcp.tool()
	def rename_data(address: str, new_name: str) -> str:
		"""
		Rename a data label at the specified address.
		
		Args:
			address: Memory address in hex format (e.g., "0x1400010a0")
			new_name: New name for the data label
			
		Returns:
			Success or failure message indicating the result of the rename operation
		"""
		return ghidra_context.http_client.safe_post("renameData", {"address": address, "newName": new_name})

	@mcp.tool()
	def rename_function(old_name: str, new_name: str) -> str:
		"""
		Rename a function by its current name to a new user-defined name.
		
		Args:
			old_name: Current name of the function to rename
			new_name: New name for the function
			
		Returns:
			Success or failure message indicating the result of the rename operation
		"""
		return ghidra_context.http_client.safe_post("renameFunction", {"oldName": old_name, "newName": new_name})
	
	@mcp.tool()
	def rename_function_by_address(function_address: str, new_name: str) -> str:
		"""
		Rename a function by its address.
		
		Args:
			function_address: Memory address of the function in hex format (e.g., "0x1400010a0")
			new_name: New name for the function
			
		Returns:
			Success or failure message indicating the result of the rename operation
		"""
		return ghidra_context.http_client.safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

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

	@mcp.tool()
	def rename_label(address: str, old_name: str, new_name: str) -> str:
		"""
		Rename an existing label at the specified address.
		
		Args:
			address: Target address in hex format (e.g., "0x1400010a0")
			old_name: Current label name to rename
			new_name: New name for the label
			
		Returns:
			Success or failure message indicating the result of the rename operation
		"""
		return ghidra_context.http_client.safe_post("rename_label", {
			"address": address, 
			"old_name": old_name, 
			"new_name": new_name
		})
	
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
