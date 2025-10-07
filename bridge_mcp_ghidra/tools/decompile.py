from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context

def register_decompile_tools(mcp: FastMCP):
	"""Register decompile tools to MCP instance."""
	
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
		return ghidra_context.http_client.safe_get("disassemble_function", {"address": address})
