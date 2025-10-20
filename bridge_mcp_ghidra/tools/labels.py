from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context, GhidraValidationError, validate_hex_address

def register_label_tools(mcp: FastMCP):
	"""Register label-related tools in the MCP instance."""

	@mcp.tool()
	def batch_create_labels(labels: list) -> str:
		"""
		Create multiple labels in a single atomic operation (v1.5.1).

		This tool creates multiple labels in one transaction, dramatically reducing API calls
		and preventing user interruption hooks from triggering repeatedly. This is the
		preferred method for creating multiple labels during function documentation.

		Performance impact:
		- Reduces N API calls to 1 call
		- Prevents interruption after each label creation
		- Atomic transaction ensures all-or-nothing semantics

		Args:
			labels: List of label objects, each with "address" and "name" fields
					Example: [{"address": "0x6faeb266", "name": "begin_slot_processing"},
							{"address": "0x6faeb280", "name": "loop_check_slot_active"}]

		Returns:
			JSON string with success status, counts, and any errors:
			{"success": true, "labels_created": 5, "labels_skipped": 1, "labels_failed": 0}
		"""
		if not labels or not isinstance(labels, list):
			raise GhidraValidationError("labels must be a non-empty list")

		# Validate each label entry
		for i, label in enumerate(labels):
			if not isinstance(label, dict):
				raise GhidraValidationError(f"Label at index {i} must be a dictionary")

			if "address" not in label or "name" not in label:
				raise GhidraValidationError(f"Label at index {i} must have 'address' and 'name' fields")

			if not validate_hex_address(label["address"]):
				raise GhidraValidationError(f"Invalid hexadecimal address at index {i}: {label['address']}")

		return safe_post_json("batch_create_labels", {
			"labels": labels
		})

	@mcp.tool()
	def create_label(address: str, name: str) -> str:
		"""
		Create a new label at the specified address.
		
		This tool creates a user-defined label at the given address. The label will be
		visible in Ghidra's Symbol Tree and can be used for navigation and reference.
		
		Args:
			address: Target address in hex format (e.g., "0x1400010a0")
			name: Name for the new label
			
		Returns:
			Success/failure message
		"""

		if not validate_hex_address(address):
			raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

		return ghidra_context.http_client.safe_post("create_label", {
			"address": address, 
			"name": name
		})

	@mcp.tool()
	def get_function_labels(name: str, offset: int = 0, limit: int = 20) -> list:
		"""
		Get all labels within the specified function by name.
		
		Args:
			name: Function name to search for labels within
			offset: Pagination offset (default: 0)
			limit: Maximum number of labels to return (default: 20)
			
		Returns:
			List of labels found within the specified function
		"""

		return ghidra_context.http_client.safe_get("function_labels", {"name": name, "offset": offset, "limit": limit})

	@mcp.tool()
	def rename_data(address: str, new_name: str) -> str:
		"""
		Rename a data label at the specified address.
		
		IMPORTANT: This tool only works for DEFINED data (data with an existing symbol/type).
		For undefined memory addresses, use create_label() or rename_or_label() instead.

		What is "defined data"?
		- Data that has been typed (e.g., dword, struct, array)
		- Data created via apply_data_type() or Ghidra's "D" key
		- Data with existing symbols in the Symbol Tree

		If you get an error like "No defined data at address", use:
		- create_label(address, name) for undefined addresses
		- rename_or_label(address, name) for automatic detection (recommended)

		Args:
			address: Memory address in hex format (e.g., "0x1400010a0")
			new_name: New name for the data label

		Returns:
			Success or failure message indicating the result of the rename operation

		See Also:
			- create_label(): Create label at undefined address
			- rename_or_label(): Automatically detect and use correct method
			- apply_data_type(): Define data type before renaming
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
