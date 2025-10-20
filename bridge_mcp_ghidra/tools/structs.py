import json
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
	def analyze_struct_field_usage(
		address: str,
		struct_name: str = None,
		max_functions: int = 10
	) -> str:
		"""
		Analyze how structure fields are accessed in decompiled code.

		This tool decompiles all functions that reference a structure and extracts usage patterns
		for each field, including variable names, access types, and purposes. This enables
		generating descriptive field names based on actual usage rather than generic placeholders.

		Args:
			address: Address of the structure instance in hex format (e.g., "0x6fb835b8")
			struct_name: Name of the structure type (optional - can be inferred if null)
			max_functions: Maximum number of referencing functions to analyze (default: 10)

		Returns:
			JSON string with field usage analysis:
			{
			"struct_address": "0x6fb835b8",
			"struct_name": "ConfigData",
			"struct_size": 28,
			"functions_analyzed": 5,
			"field_usage": {
				"0": {
				"field_name": "dwResourceType",
				"field_type": "dword",
				"offset": 0,
				"size": 4,
				"access_count": 12,
				"suggested_names": ["resourceType", "dwType", "nResourceId"],
				"usage_patterns": ["conditional_check", "assignment"]
				},
				...
			}
			}
		"""
		import json

		if not validate_hex_address(address):
			raise GhidraValidationError(f"Invalid hex address format: {address}")

		# Validate parameter bounds (must match Java constants)
		if not isinstance(max_functions, int) or max_functions < 1 or max_functions > 100:
			raise GhidraValidationError("max_functions must be between 1 and 100")

		data = {
			"address": address,
			"max_functions": max_functions
		}
		if struct_name:
			data["struct_name"] = struct_name

		result = ghidra_context.http_client.safe_post_json("analyze_struct_field_usage", data)

		# Format the JSON response for readability
		try:
			parsed = json.loads(result)
			return json.dumps(parsed, indent=2)
		except:
			return result
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
	def get_field_access_context(
		struct_address: str,
		field_offset: int,
		num_examples: int = 5
	) -> str:
		"""
		Get assembly/decompilation context for specific field offsets.

		This tool retrieves specific usage examples for a field at a given offset within a structure,
		including the assembly instructions, reference types, and containing functions. Useful for
		understanding how a particular field is accessed and what its purpose might be.

		Args:
			struct_address: Address of the structure instance in hex format (e.g., "0x6fb835b8")
			field_offset: Offset of the field within the structure (e.g., 4 for second DWORD)
			num_examples: Number of usage examples to return (default: 5)

		Returns:
			JSON string with field access contexts:
			{
			"struct_address": "0x6fb835b8",
			"field_offset": 4,
			"field_address": "0x6fb835bc",
			"examples": [
				{
				"access_address": "0x6fb6cae9",
				"ref_type": "DATA_READ",
				"assembly": "MOV EDX, [0x6fb835bc]",
				"function_name": "ProcessResource",
				"function_address": "0x6fb6ca00"
				},
				...
			]
			}
		"""

		if not validate_hex_address(struct_address):
			raise GhidraValidationError(f"Invalid hex address format: {struct_address}")

		# Validate parameter bounds (must match Java constants: MAX_FIELD_OFFSET=65536, MAX_FIELD_EXAMPLES=50)
		if not isinstance(field_offset, int) or field_offset < 0 or field_offset > 65536:
			raise GhidraValidationError("field_offset must be between 0 and 65536")

		if not isinstance(num_examples, int) or num_examples < 1 or num_examples > 50:
			raise GhidraValidationError("num_examples must be between 1 and 50")

		data = {
			"struct_address": struct_address,
			"field_offset": field_offset,
			"num_examples": num_examples
		}

		result = ghidra_context.http_client.safe_post_json("get_field_access_context", data)

		# Format the JSON response for readability
		try:
			parsed = json.loads(result)
			return json.dumps(parsed, indent=2)
		except:
			return result
	
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
	
	@mcp.tool()
	def suggest_field_names(
		struct_address: str,
		struct_size: int = 0
	) -> str:
		"""
		AI-assisted field name suggestions based on usage patterns and data types.

		This tool analyzes a structure's field types and generates suggested names following
		common naming conventions (Hungarian notation, camelCase, etc.). Useful for quickly
		generating descriptive names for structure fields based on their types.

		Args:
			struct_address: Address of the structure instance in hex format (e.g., "0x6fb835b8")
			struct_size: Size of the structure in bytes (optional - auto-detected if 0)

		Returns:
			JSON string with field name suggestions:
			{
			"struct_address": "0x6fb835b8",
			"struct_name": "ConfigData",
			"struct_size": 28,
			"suggestions": [
				{
				"offset": 0,
				"current_name": "field0",
				"field_type": "dword",
				"suggested_names": ["dwValue", "nCount", "dwFlags"],
				"confidence": "medium"
				},
				{
				"offset": 4,
				"current_name": "field1",
				"field_type": "pointer",
				"suggested_names": ["pData", "lpBuffer", "pNext"],
				"confidence": "high"
				},
				...
			]
			}
		"""
		import json

		if not validate_hex_address(struct_address):
			raise GhidraValidationError(f"Invalid hex address format: {struct_address}")

		# Validate parameter bounds (must match Java constant: MAX_FIELD_OFFSET=65536)
		if not isinstance(struct_size, int) or struct_size < 0 or struct_size > 65536:
			raise GhidraValidationError("struct_size must be between 0 and 65536")

		data = {
			"struct_address": struct_address,
			"struct_size": struct_size
		}

		result = ghidra_context.http_client.safe_post_json("suggest_field_names", data)

		# Format the JSON response for readability
		try:
			parsed = json.loads(result)
			return json.dumps(parsed, indent=2)
		except:
			return result
