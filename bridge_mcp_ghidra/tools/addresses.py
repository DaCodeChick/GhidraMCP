from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context, validate_hex_address

def register_address_tools(mcp: FastMCP):
	"""Register address-related tools to the MCP instance."""

	@mcp.tool()
	def can_rename_at_address(address: str) -> str:
		"""
		Check what kind of symbol exists at an address (v1.6.0).

		Determines whether address contains defined data, undefined bytes,
		or code, helping choose between rename_data, create_label, etc.

		Args:
			address: Memory address in hex format

		Returns:
			JSON with address analysis:
			{
			"can_rename_data": true|false,
			"type": "defined_data"|"undefined"|"code"|"invalid",
			"current_name": "DAT_6fb385a0"|"FUN_6fb385a0"|null,
			"suggested_operation": "rename_data"|"create_label"|"rename_function"
			}
		"""
		
		validate_hex_address(address)
		return ghidra_context.http_client.safe_get("can_rename_at_address", {"address": address})

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
