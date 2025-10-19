from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context, GhidraValidationError, validate_hex_address

def register_label_tools(mcp: FastMCP):
	"""Register label-related tools in the MCP instance."""

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
