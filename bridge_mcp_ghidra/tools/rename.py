import json
from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context, GhidraValidationError, validate_hex_address

def _check_if_data_defined(address: str) -> bool:
	"""
	Internal helper: Check if address has a defined data symbol.

	Args:
		address: Hex address to check

	Returns:
		True if data is defined, False if undefined
	"""

	try:
		result = ghidra_context.http_client.safe_post_json("analyze_data_region", {
			"address": address,
			"max_scan_bytes": 16,
			"include_xref_map": False,
			"include_assembly_patterns": False,
			"include_boundary_detection": False
		})

		if result and not result.startswith("Error"):
			data = json.loads(result)
			current_type = data.get("current_type", "undefined")
			# If current_type is "undefined", it's not a defined data item
			return current_type != "undefined"
	except Exception as e:
		ghidra_context.http_client.logger.warning(f"Failed to check if data defined at {address}: {e}")

	return False

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

		if not validate_hex_address(address):
			raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

		response = ghidra_context.http_client.safe_post("renameData", {"address": address, "newName": new_name})

		# Validate response and provide clear success message
		if "success" in response.lower() or "renamed" in response.lower():
			return f"Successfully renamed data at {address} to '{new_name}'"
		elif "error" in response.lower() or "failed" in response.lower():
			return response  # Return original error message
		else:
			return f"Rename operation completed: {response}"
	
	@mcp.tool()
	def rename_data_smart(address: str, new_name: str) -> str:
		"""
		Intelligently rename data at an address, automatically detecting if it's
		defined data or undefined bytes and using the appropriate method.

		This tool automatically chooses between rename_data (for defined symbols)
		and create_label (for undefined addresses) based on the current state.

		Args:
			address: Memory address in hex format (e.g., "0x1400010a0")
			new_name: New name for the data label

		Returns:
			Success or failure message with details about the operation performed
		"""

		if not validate_hex_address(address):
			raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

		# Check if data is defined
		is_defined = _check_if_data_defined(address)

		if is_defined:
			# Use rename_data endpoint for defined symbols
			ghidra_context.http_client.logger.info(f"Address {address} has defined data, using rename_data")
			response = ghidra_context.http_client.safe_post("renameData", {"address": address, "newName": new_name})

			if "success" in response.lower() or "renamed" in response.lower():
				return f"✓ Renamed defined data at {address} to '{new_name}'"
			else:
				return f"Rename data attempted: {response}"
		else:
			# Use create_label for undefined addresses
			ghidra_context.http_client.logger.info(f"Address {address} is undefined, using create_label")
			response = ghidra_context.http_client.safe_post("create_label", {"address": address, "name": new_name})

			if "success" in response.lower() or "created" in response.lower():
				return f"✓ Created label '{new_name}' at {address} (was undefined)"
			else:
				return f"Create label attempted: {response}"

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

		if not validate_hex_address(function_address):
			raise GhidraValidationError(f"Invalid hexadecimal address: {function_address}")

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

		if not validate_hex_address(address):
			raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

		return ghidra_context.http_client.safe_post("rename_label", {
			"address": address, 
			"old_name": old_name, 
			"new_name": new_name
		})
	
	@mcp.tool()
	def rename_or_label(address: str, name: str) -> str:
		"""
		Intelligently rename data or create label at an address (server-side detection).

		This tool automatically detects whether the address contains defined data or
		undefined bytes and chooses the appropriate operation server-side. This is
		more efficient than rename_data_smart as the detection happens in Ghidra
		without additional API calls.

		Use this tool when you're unsure whether data is defined or undefined, or when
		you want guaranteed reliability with minimal round-trips.

		Args:
			address: Memory address in hex format (e.g., "0x1400010a0")
			name: Name for the data/label

		Returns:
			Success or failure message with details about the operation performed
		"""
		
		if not validate_hex_address(address):
			raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

		return ghidra_context.http_client.safe_post("rename_or_label", {
			"address": address,
			"name": name
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
