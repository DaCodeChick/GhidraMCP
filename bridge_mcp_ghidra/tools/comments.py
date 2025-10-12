from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context, GhidraValidationError, validate_hex_address

def register_comment_tools(mcp: FastMCP):
	"""Register comment tools for Ghidra context."""

	@mcp.tool()
	def set_decompiler_comment(address: str, comment: str) -> str:
		"""
		Set a comment for a given address in the function pseudocode.
		
		Args:
			address: Memory address in hex format (e.g., "0x1400010a0")
			comment: Comment text to add to the decompiled pseudocode
			
		Returns:
			Success or failure message indicating the result of the comment operation
		"""

		if not validate_hex_address(address):
			raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

		return ghidra_context.http_client.safe_post("set_decompiler_comment", {"address": address, "comment": comment})

	@mcp.tool()
	def set_disassembly_comment(address: str, comment: str) -> str:
		"""
		Set a comment for a given address in the function disassembly.
		
		Args:
			address: Memory address in hex format (e.g., "0x1400010a0")
			comment: Comment text to add to the assembly disassembly
			
		Returns:
			Success or failure message indicating the result of the comment operation
		"""

		if not validate_hex_address(address):
			raise GhidraValidationError(f"Invalid hexadecimal address: {address}")
	
		return ghidra_context.http_client.safe_post("set_disassembly_comment", {"address": address, "comment": comment})
