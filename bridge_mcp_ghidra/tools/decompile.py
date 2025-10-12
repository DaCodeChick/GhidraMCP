from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context, GhidraValidationError, validate_function_name, validate_hex_address

def register_decompile_tools(mcp: FastMCP):
	"""Register decompile tools to MCP instance."""

	@mcp.tool()
	def batch_decompile(function_names: list) -> dict:
		"""
		Decompile multiple functions in a single request for better performance.
		
		Args:
			function_names: List of function names to decompile
			
		Returns:
			Dictionary mapping function names to their decompiled code
		"""
		
		# Validate all function names
		for name in function_names:
			if not validate_function_name(name):
				raise GhidraValidationError(f"Invalid function name: {name}")

		return ghidra_context.http_client.safe_get("batch_decompile", {"functions": ",".join(function_names)})

	@mcp.tool()
	def decompile_function(name: str) -> str:
		"""
		Decompile a specific function by name and return the decompiled C code.
		
		Args:
			name: Function name to decompile
			
		Returns:
			Decompiled C code as a string
		"""

		return ghidra_context.http_client.safe_post("decompile", name)
	
	@mcp.tool()
	def disassemble_function(address: str) -> list:
		"""
		Get assembly code (address: instruction; comment) for a function.
		
		Args:
			address: Memory address in hex format (e.g., "0x1400010a0")
			
		Returns:
			List of assembly instructions with addresses and comments
		"""

		if not validate_hex_address(address):
			raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

		return ghidra_context.http_client.safe_get("disassemble_function", {"address": address})
