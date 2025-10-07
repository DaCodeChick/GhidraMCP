from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context

def register_set_tools(mcp: FastMCP):
	"""Register set tools to MCP."""

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
		return ghidra_context.http_client.safe_post("apply_data_type", {
			"address": address, 
			"type_name": type_name,
			"clear_existing": clear_existing
		})

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
	def set_function_prototype(function_address: str, prototype: str) -> str:
		"""
		Set a function's prototype.
		
		Args:
			function_address: Memory address of the function in hex format (e.g., "0x1400010a0")
			prototype: Function prototype string (e.g., "int main(int argc, char* argv[])")
			
		Returns:
			Success or failure message indicating the result of the prototype update
		"""
		return ghidra_context.http_client.safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

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
