from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context, GhidraValidationError, validate_hex_address

def register_struct_tools(mcp: FastMCP):
	"""Register struct-related tools to the FastMCP instance."""

	@mcp.tool()
	def add_struct_field(struct_name: str, field_name: str, field_type: str, offset: int = -1) -> str:
		"""
		Add a new field to an existing structure.
		
		This tool adds a new field to an existing structure at the specified offset
		or at the end if no offset is provided.
		
		Args:
			struct_name: Name of the structure to modify
			field_name: Name of the new field
			field_type: Data type of the new field
			offset: Offset to insert the field at (-1 for end, default: -1)
			
		Returns:
			Success or failure message with details
		"""

		if not struct_name or not isinstance(struct_name, str):
			raise GhidraValidationError("Structure name is required and must be a string")
		if not field_name or not isinstance(field_name, str):
			raise GhidraValidationError("Field name is required and must be a string")
		if not field_type or not isinstance(field_type, str):
			raise GhidraValidationError("Field type is required and must be a string")
		
		data = {
			"struct_name": struct_name,
			"field_name": field_name,
			"field_type": field_type,
			"offset": offset
		}
		
		return ghidra_context.http_client.safe_post_json("add_struct_field", data)

	@mcp.tool()
	def auto_create_struct_from_memory(address: str, size: int, name: str) -> str:
		"""
		Automatically create a structure by analyzing memory layout at an address.
		
		Args:
			address: Target address in hex format (e.g., "0x1400010a0")
			size: Size in bytes to analyze (0 for automatic detection)
			name: Name for the new structure
			
		Returns:
			Success/failure message with created structure details
		"""

		if not validate_hex_address(address):
			raise GhidraValidationError(f"Invalid hexadecimal address: {address}")
		return ghidra_context.http_client.safe_post("auto_create_struct", {"address": address, "size": size, "name": name})

	@mcp.tool()
	def create_struct(name: str, fields: list) -> str:
		"""
		Create a new structure data type with specified fields.
		
		This tool creates a custom structure definition that can be applied to memory
		locations. Fields should be specified as a list of dictionaries with 'name',
		'type', and optionally 'offset' keys.
		
		Args:
			name: Name for the new structure
			fields: List of field definitions, each with:
					- name: Field name
					- type: Field data type (e.g., "int", "char", "DWORD")
					- offset: Optional explicit offset (auto-calculated if omitted)
					
		Returns:
			Success/failure message with created structure details
			
		Example:
			fields = [
				{"name": "id", "type": "int"},
				{"name": "name", "type": "char[32]"},
				{"name": "flags", "type": "DWORD"}
			]
		"""

		return ghidra_context.http_client.safe_post_json("create_struct", {"name": name, "fields": fields})

	@mcp.tool()
	def get_struct_layout(struct_name: str) -> list:
		"""
		Get the detailed layout of a structure including field offsets.
		
		Args:
			struct_name: Name of the structure to analyze
			
		Returns:
			Detailed structure layout with field offsets, sizes, and types
		"""

		return ghidra_context.http_client.safe_get("get_struct_layout", {"struct_name": struct_name})

	@mcp.tool()
	def modify_struct_field(struct_name: str, field_name: str, new_type: str = None, new_name: str = None) -> str:
		"""
		Modify a field in an existing structure.
		
		This tool allows changing the type and/or name of a field in an existing structure.
		At least one of new_type or new_name must be provided.
		
		Args:
			struct_name: Name of the structure to modify
			field_name: Name of the field to modify
			new_type: New data type for the field (optional)
			new_name: New name for the field (optional)
			
		Returns:
			Success or failure message with details
		"""

		if not struct_name or not isinstance(struct_name, str):
			raise GhidraValidationError("Structure name is required and must be a string")
		if not field_name or not isinstance(field_name, str):
			raise GhidraValidationError("Field name is required and must be a string")
		if not new_type and not new_name:
			raise GhidraValidationError("At least one of new_type or new_name must be provided")
		
		data = {
			"struct_name": struct_name,
			"field_name": field_name
		}
		if new_type:
			data["new_type"] = new_type
		if new_name:
			data["new_name"] = new_name

		return ghidra_context.http_client.safe_post_json("modify_struct_field", data)

	@mcp.tool()
	def remove_struct_field(struct_name: str, field_name: str) -> str:
		"""
		Remove a field from an existing structure.
		
		This tool removes a field from an existing structure by name.
		
		Args:
			struct_name: Name of the structure to modify
			field_name: Name of the field to remove
			
		Returns:
			Success or failure message with details
		"""

		if not struct_name or not isinstance(struct_name, str):
			raise GhidraValidationError("Structure name is required and must be a string")
		if not field_name or not isinstance(field_name, str):
			raise GhidraValidationError("Field name is required and must be a string")

		return ghidra_context.http_client.safe_post_json("remove_struct_field", {
			"struct_name": struct_name,
			"field_name": field_name
		})
