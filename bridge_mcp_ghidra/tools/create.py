import json
from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context, GhidraValidationError, validate_hex_address

def register_create_tools(mcp: FastMCP):
	"""Register create tools for Ghidra context."""

	@mcp.tool()
	def auto_create_struct(address: str, size: int, name: str) -> str:
		"""
		Automatically create a structure by analyzing memory layout at an address.
		
		Args:
			address: Target address in hex format (e.g., "0x1400010a0")
			size: Size in bytes to analyze (0 for automatic detection)
			name: Name for the new structure
			
		Returns:
			Success/failure message with created structure details
		"""

		return ghidra_context.http_client.safe_post("auto_create_struct", {"address": address, "size": size, "name": name})

	@mcp.tool()
	def create_array_type(base_type: str, length: int, name: str = None) -> str:
		"""
		Create an array data type.
		
		This tool creates a new array data type based on an existing base type
		with the specified length.
		
		Args:
			base_type: Name of the base data type for the array
			length: Number of elements in the array
			name: Optional name for the array type
			
		Returns:
			Success or failure message with created array type details
		"""

		if not base_type or not isinstance(base_type, str):
			raise GhidraValidationError("Base type is required and must be a string")
		if not isinstance(length, int) or length <= 0:
			raise GhidraValidationError("Length must be a positive integer")
		
		data = {
			"base_type": base_type,
			"length": length
		}
		if name:
			data["name"] = name
		
		return ghidra_context.http_client.safe_post_json("create_array_type", data)


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
	def create_function_signature(name: str, return_type: str, parameters: str = None) -> str:
		"""
		Create a function signature data type.
		
		This tool creates a new function signature data type that can be used
		for function pointers and type definitions.
		
		Args:
			name: Name for the function signature
			return_type: Return type of the function
			parameters: Optional JSON string describing parameters (e.g., '[{"name": "param1", "type": "int"}]')
			
		Returns:
			Success or failure message with function signature creation details
		"""

		if not name or not isinstance(name, str):
			raise GhidraValidationError("Function name is required and must be a string")
		if not return_type or not isinstance(return_type, str):
			raise GhidraValidationError("Return type is required and must be a string")
		
		data = {
			"name": name,
			"return_type": return_type
		}
		if parameters:
			data["parameters"] = parameters
		
		return ghidra_context.http_client.safe_post_json("create_function_signature", data)
	
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
	def create_pointer_type(base_type: str, name: str = None) -> str:
		"""
		Create a pointer data type.
		
		This tool creates a new pointer data type pointing to the specified base type.
		
		Args:
			base_type: Name of the base data type for the pointer
			name: Optional name for the pointer type
			
		Returns:
			Success or failure message with created pointer type details
		"""

		if not base_type or not isinstance(base_type, str):
			raise GhidraValidationError("Base type is required and must be a string")
		
		data = {"base_type": base_type}
		if name:
			data["name"] = name

		return ghidra_context.http_client.safe_post_json("create_pointer_type", data)

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
	def create_typedef(name: str, base_type: str) -> str:
		"""
		Create a typedef (type alias) for an existing data type.
		
		Args:
			name: Name for the new typedef
			base_type: Name of the base data type to alias
			
		Returns:
			Success/failure message with typedef creation details
		"""

		return ghidra_context.http_client.safe_post("create_typedef", {"name": name, "base_type": base_type})

	@mcp.tool()
	def create_union(name: str, fields: list) -> str:
		"""
		Create a new union data type with specified fields.
		
		Args:
			name: Name for the new union
			fields: List of field definitions, each with:
					- name: Field name
					- type: Field data type (e.g., "int", "char", "DWORD")
					
		Returns:
			Success/failure message with created union details
			
		Example:
			fields = [
				{"name": "as_int", "type": "int"},
				{"name": "as_float", "type": "float"},
				{"name": "as_bytes", "type": "char[4]"}
			]
		"""

		fields_json = json.dumps(fields) if isinstance(fields, list) else str(fields)
		return ghidra_context.http_client.safe_post("create_union", {"name": name, "fields": fields_json})
