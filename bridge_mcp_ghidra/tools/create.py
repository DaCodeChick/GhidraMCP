import json
from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context

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
		return ghidra_context.http_client.safe_post("create_enum", {"name": name, "values": values, "size": size})

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
		return ghidra_context.http_client.safe_post("create_label", {
			"address": address, 
			"name": name
		})
	
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
		return ghidra_context.http_client.safe_post("create_struct", {"name": name, "fields": fields})

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
