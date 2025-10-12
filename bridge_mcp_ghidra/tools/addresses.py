from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context

def register_address_tools(mcp: FastMCP):
	"""Register address-related tools to the MCP instance."""

	@mcp.tool()
	def get_current_address() -> str:
		"""
		Get the address currently selected by the user.
		
		Args:
			None
			
		Returns:
			Current cursor/selection address in hex format
		"""

		return "\n".join(ghidra_context.http_client.safe_get_uncached("get_current_address"))
	
	@mcp.tool()
	def get_function_jump_target_addresses(name: str, offset: int = 0, limit: int = 100) -> list:
		"""
		Get all jump target addresses from a function's disassembly.
		
		This tool analyzes the disassembly of a specified function and extracts all addresses
		that are targets of conditional and unconditional jump instructions (JMP, JE, JNE, JZ, etc.).
		
		Args:
			name: Function name to analyze for jump targets
			offset: Pagination offset (default: 0)
			limit: Maximum number of jump targets to return (default: 100)
			
		Returns:
			List of jump target addresses found in the function's disassembly
		"""

		return ghidra_context.http_client.safe_get("function_jump_targets", {"name": name, "offset": offset, "limit": limit})
