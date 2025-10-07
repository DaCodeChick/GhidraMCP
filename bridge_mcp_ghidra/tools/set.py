from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context, GhidraValidationError

def register_set_tools(mcp: FastMCP):
	"""Register set tools to MCP."""

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
	def convert_number(text: str, size: int = 4) -> str:
		"""
		Convert a number (decimal, hexadecimal) to different representations.
		
		Takes a number in various formats and converts it to decimal, hexadecimal,
		binary, and other useful representations.
		
		Args:
			text: Number to convert (can be decimal like "123" or hex like "0x7B")
			size: Size in bytes for representation (1, 2, 4, or 8, default: 4)
			
		Returns:
			String with multiple number representations
		"""
		return "\n".join(ghidra_context.http_client.safe_get("convert_number", {"text": text, "size": size}))

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
	def move_data_type_to_category(type_name: str, category_path: str) -> str:
		"""
		Move a data type to a different category.
		
		This tool moves an existing data type to a specified category.
		
		Args:
			type_name: Name of the data type to move
			category_path: Target category path
			
		Returns:
			Success or failure message with move operation details
		"""
		if not type_name or not isinstance(type_name, str):
			raise GhidraValidationError("Type name is required and must be a string")
		if not category_path or not isinstance(category_path, str):
			raise GhidraValidationError("Category path is required and must be a string")

		return ghidra_context.http_client.safe_post_json("move_data_type_to_category", {
			"type_name": type_name,
			"category_path": category_path
		})

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
	def set_function_prototype(function_address: str, prototype: str, calling_convention: str = None) -> str:
		"""
		Set a function's prototype and optionally its calling convention.
		
		Args:
			function_address: Memory address of the function in hex format (e.g., "0x1400010a0")
			prototype: Function prototype string (e.g., "int main(int argc, char* argv[])")
			calling_convention: Optional calling convention (e.g., "__cdecl", "__stdcall", "__fastcall", "__thiscall")

		Returns:
			Success or failure message indicating the result of the prototype update
		"""
		data = {"function_address": function_address, "prototype": prototype}
		if calling_convention:
			data["callingConvention"] = calling_convention
		return ghidra_context.http_client.safe_post_json("set_function_prototype", data)

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
	
	@mcp.tool()
	def write_bytes(address: str, bytes_hex: str) -> str:
		"""
		Writes a sequence of bytes to the specified address in the program's memory.

		Args:
			address: Destination address (e.g., "0x140001000")
			bytes_hex: Sequence of space-separated bytes in hexadecimal format (e.g., "90 90 90 90")

		Returns:
			Result of the operation (e.g., "Bytes written successfully" or a detailed error)
		"""
		return ghidra_context.http_client.safe_post("write_bytes", {"address": address, "bytes": bytes_hex})
