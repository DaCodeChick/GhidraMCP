import json
from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context, GhidraValidationError, validate_hex_address
from .strings import inspect_memory_content

def _verify_content_before_classification(address: str) -> dict:
	"""
	Internal helper: Verify memory content before applying classification.

	This prevents misidentifying strings as numeric data by inspecting actual bytes.

	Args:
		address: Hex address to verify

	Returns:
		Dictionary with verification results:
		{
			"is_string": bool,
			"detected_string": str or None,
			"suggested_type": str or None,
			"printable_ratio": float,
			"recommendation": str
		}
	"""

	try:
		# Use inspect_memory_content to check what the data actually contains
		result = inspect_memory_content(address, length=64, detect_strings=True)
		data = json.loads(result)

		verification = {
			"is_string": data.get("is_likely_string", False),
			"detected_string": data.get("detected_string"),
			"suggested_type": data.get("suggested_type"),
			"printable_ratio": float(data.get("printable_ratio", 0.0)),
			"recommendation": ""
		}

		if verification["is_string"]:
			verification["recommendation"] = (
				f"WARNING: Content appears to be a string (\"{verification['detected_string']}\"). "
				f"Consider using classification='STRING' with type '{verification['suggested_type']}' "
				f"instead of numeric types."
			)
		else:
			verification["recommendation"] = "Content verification passed: not a string."

		return verification

	except Exception as e:
		ghidra_context.http_client.logger.warning(f"Content verification failed for {address}: {e}")
		return {
			"is_string": False,
			"detected_string": None,
			"suggested_type": None,
			"printable_ratio": 0.0,
			"recommendation": f"Content verification failed: {e}"
		}

def register_type_tools(mcp: FastMCP):
	"""Register data type management tools with the MCP server."""

	@mcp.tool()
	def analyze_data_types(address: str, depth: int = 1) -> list:
		"""
		Analyze data types at a given address with specified depth.
		
		Args:
			address: Target address in hex format (e.g., "0x1400010a0")
			depth: Analysis depth for following pointers and references (default: 1)
			
		Returns:
			Detailed analysis of data types at the specified address
		"""

		if not validate_hex_address(address):
			raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

		return ghidra_context.http_client.safe_get("analyze_data_types", {"address": address, "depth": depth})

	@mcp.tool()
	def apply_data_type(address: str, type_name: str, clear_existing: bool = True) -> str:
		"""
		Apply a specific data type at the given memory address.
		
		This tool applies a data type definition to a memory location, which helps
		in interpreting the raw bytes as structured data during analysis.
		
		Args:
			address: Target address in hex format (e.g., "0x1400010a0")
			type_name: Name of the data type to apply (e.g., "int", "MyStruct", "DWORD")
			clear_existing: Whether to clear existing data/code at the address (default: True)
			
		Returns:
			Success/failure message with details about the applied data type
		"""

		if not validate_hex_address(address):
			raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

		ghidra_context.http_client.logger.info(f"apply_data_type called with: address={address}, type_name={type_name}, clear_existing={clear_existing}")
		data = {
			"address": address, 
			"type_name": type_name,
			"clear_existing": clear_existing
		}
		ghidra_context.http_client.logger.info(f"Data being sent: {data}")
		result = ghidra_context.http_client.safe_post_json("apply_data_type", data)
		ghidra_context.http_client.logger.info(f"Result received: {result}")
		return result

	@mcp.tool()
	def clone_data_type(source_type: str, new_name: str) -> str:
		"""
		Clone/copy an existing data type with a new name.
		
		Args:
			source_type: Name of the source data type to clone
			new_name: Name for the cloned data type
			
		Returns:
			Success/failure message with cloning details
		"""

		return ghidra_context.http_client.safe_post("clone_data_type", {"source_type": source_type, "new_name": new_name})

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

	@mcp.tool()
	def delete_data_type(type_name: str) -> str:
		"""
		Delete a data type from the program.
		
		This tool removes a data type (struct, enum, typedef, etc.) from the program's
		data type manager. The type cannot be deleted if it's currently being used.
		
		Args:
			type_name: Name of the data type to delete
			
		Returns:
			Success or failure message with details
		"""

		if not type_name or not isinstance(type_name, str):
			raise GhidraValidationError("Type name is required and must be a string")

		return ghidra_context.http_client.safe_post_json("delete_data_type", {"type_name": type_name})

	@mcp.tool()
	def export_data_types(format: str = "c", category: str = None) -> str:
		"""
		Export data types in various formats.
		
		Args:
			format: Export format ("c", "json", "summary") - default: "c"
			category: Optional category filter for data types
			
		Returns:
			Exported data types in the specified format
		"""

		params = {"format": format}
		if category:
			params["category"] = category
		return ghidra_context.http_client.safe_get("export_data_types", params)

	@mcp.tool()
	def get_type_size(type_name: str) -> list:
		"""
		Get the size and alignment information for a data type.
		
		Args:
			type_name: Name of the data type to query
			
		Returns:
			Size, alignment, and path information for the data type
		"""

		return ghidra_context.http_client.safe_get("get_type_size", {"type_name": type_name})

	@mcp.tool()
	def get_valid_data_types(
		category: str = None
	) -> str:
		"""
		Get list of valid Ghidra data type strings (v1.5.0).
		Helps construct proper type definitions for create_struct and other type operations.

		Args:
			category: Optional category filter (not currently used)

		Returns:
			JSON with lists of builtin_types and windows_types
		"""
		params = {"category": category} if category else {}
		return ghidra_context.http_client.safe_get("get_valid_data_types", params)

	@mcp.tool()
	def list_data_types(category: str = None, offset: int = 0, limit: int = 100) -> list:
		"""
		List all data types available in the program with optional category filtering.
		
		This tool enumerates all data types defined in the program's data type manager,
		including built-in types, user-defined structs, enums, and imported types.
		
		Args:
			category: Optional category filter (e.g., "builtin", "struct", "enum", "pointer")
			offset: Pagination offset (default: 0)
			limit: Maximum number of data types to return (default: 100)
			
		Returns:
			List of data types with their names, categories, and sizes
		"""

		params = {"offset": offset, "limit": limit}
		if category:
			params["category"] = category
		return ghidra_context.http_client.safe_get("list_data_types", params)

	@mcp.tool()
	def search_data_types(pattern: str, offset: int = 0, limit: int = 100) -> list:
		"""
		Search for data types by name pattern.
		
		Args:
			pattern: Search pattern to match against data type names
			offset: Pagination offset (default: 0)
			limit: Maximum number of results to return (default: 100)
			
		Returns:
			List of matching data types with their details
		"""
		return ghidra_context.http_client.safe_get("search_data_types", {"pattern": pattern, "offset": offset, "limit": limit})

	@mcp.tool()
	def validate_data_type(
		address: str,
		type_name: str
	) -> str:
		"""
		Validate if a data type can be applied at a given address (v1.5.0).
		Checks memory availability, size compatibility, and alignment.

		Args:
			address: Target address in hex format
			type_name: Name of the data type to validate

		Returns:
			JSON with validation results including memory availability and size checks
		"""
		validate_hex_address(address)

		params = {"address": address, "type_name": type_name}
		return ghidra_context.http_client.safe_get("validate_data_type", params)

	@mcp.tool()
	def validate_data_type_exists(type_name: str) -> str:
		"""
		Check if a data type exists in Ghidra's type manager (v1.6.0).

		Args:
			type_name: Name of the data type to check (e.g., "DWORD", "MyStruct")

		Returns:
			JSON with validation results:
			{
			"exists": true|false,
			"type_category": "builtin"|"struct"|"typedef"|"pointer",
			"size": 4,
			"path": "/builtin/DWORD"
			}
		"""
		
		return ghidra_context.http_client.safe_get("validate_data_type_exists", {"type_name": type_name})
