from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context, GhidraValidationError, validate_hex_address

def register_comment_tools(mcp: FastMCP):
	"""Register comment tools for Ghidra context."""

	@mcp.tool()
	def batch_set_comments(
		function_address: str,
		decompiler_comments: list = None,
		disassembly_comments: list = None,
		plate_comment: str = None
	) -> str:
		"""
		Set multiple comments in a single operation (v1.5.0).
		Reduces API calls from 10+ to 1 for typical function documentation.

		Args:
			function_address: Function address for plate comment
			decompiler_comments: List of {"address": "0x...", "comment": "..."} for PRE_COMMENT
			disassembly_comments: List of {"address": "0x...", "comment": "..."} for EOL_COMMENT
			plate_comment: Function header summary comment

		Returns:
			JSON with success status and counts of comments set
		"""
		validate_hex_address(function_address)

		payload = {
			"function_address": function_address,
			"decompiler_comments": decompiler_comments or [],
			"disassembly_comments": disassembly_comments or [],
			"plate_comment": plate_comment
		}

		return ghidra_context.http_client.safe_post_json("batch_set_comments", payload)

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


	@mcp.tool()
	def set_plate_comment(
		function_address: str,
		comment: str
	) -> str:
		"""
		Set function plate (header) comment (v1.5.0).
		This comment appears above the function in both disassembly and decompiler views.

		Args:
			function_address: Function address in hex format (e.g., "0x401000")
			comment: Function header summary comment

		Returns:
			Success or failure message
		"""
		validate_hex_address(function_address)

		params = {"function_address": function_address, "comment": comment}
		return ghidra_context.http_client.safe_post("set_plate_comment", params)
