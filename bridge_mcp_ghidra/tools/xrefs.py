import json
from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context, GhidraValidationError, validate_hex_address

def register_xref_tools(mcp: FastMCP):
	"""Register cross-reference related tools."""

	@mcp.tool()
	def batch_decompile_xref_sources(
		target_address: str,
		include_function_names: bool = True,
		include_usage_context: bool = True
	) -> str:
		"""
		Decompile all functions that reference a target address in one batch operation.

		This tool finds all functions containing xrefs to the target address and
		decompiles them, providing usage context and variable type hints.

		Args:
			target_address: Address being referenced (e.g., "0x6fb835b8")
			include_function_names: Include function name analysis (default: True)
			include_usage_context: Extract specific usage lines (default: True)

		Returns:
			JSON string with decompiled functions:
			[
			{
				"function_name": "ProcessTimedSpellEffect...",
				"function_address": "0x6fb6a000",
				"xref_address": "0x6fb6a023",
				"decompiled_code": "...",
				"usage_lines": [
				"pFVar4 = &FrameThresholdDataTable;",
				"if ((int)pFVar4->threshold < iVar3) break;"
				],
				"variable_type_hints": {
				"threshold": "dword",
				"access_pattern": "structure_field"
				}
			}
			]
		"""

		if not validate_hex_address(target_address):
			raise GhidraValidationError(f"Invalid hex address format: {target_address}")

		data = {
			"target_address": target_address,
			"include_function_names": include_function_names,
			"include_usage_context": include_usage_context
		}

		result = ghidra_context.http_client.safe_post_json("batch_decompile_xref_sources", data)

		# Format the JSON response for readability
		try:
			parsed = json.loads(result)
			return json.dumps(parsed, indent=2)
		except:
			return result
	
	@mcp.tool()
	def get_assembly_context(
		xref_sources: str,
		context_instructions: int = 5,
		include_patterns: str = "LEA,MOV,CMP,IMUL,ADD,SUB"
	) -> str:
		"""
		Get assembly instructions with context for multiple xref source addresses.

		This tool retrieves assembly context around xref instructions to understand
		access patterns, data types, and usage context without manual disassembly.

		Args:
			xref_sources: Comma-separated xref source addresses (e.g., "0x6fb6cae9,0x6fb6c9fe")
						or JSON array string
			context_instructions: Number of instructions before/after to include (default: 5)
			include_patterns: Comma-separated instruction types to highlight (default: "LEA,MOV,CMP,IMUL,ADD,SUB")

		Returns:
			JSON string with assembly context:
			[
			{
				"xref_from": "0x6fb6cae9",
				"instruction": "MOV EDX, [0x6fb835b8]",
				"access_size": 4,
				"access_type": "READ",
				"context_before": ["0x6fb6cae4: PUSH EBX", ...],
				"context_after": ["0x6fb6caef: ADD EDX, EBX", ...],
				"pattern_detected": "array_index_check|dword_access|structure_field"
			}
			]
		"""

		# Parse input
		addr_list = []
		if xref_sources.startswith('['):
			try:
				addr_list = json.loads(xref_sources)
			except:
				raise GhidraValidationError("Invalid JSON array format for xref_sources")
		else:
			addr_list = [addr.strip() for addr in xref_sources.split(',')]

		# Validate all addresses
		for addr in addr_list:
			if not validate_hex_address(addr):
				raise GhidraValidationError(f"Invalid hex address format: {addr}")

		if not isinstance(context_instructions, int) or context_instructions < 0:
			raise GhidraValidationError("context_instructions must be a non-negative integer")

		pattern_list = [p.strip() for p in include_patterns.split(',')]

		data = {
			"xref_sources": addr_list,
			"context_instructions": context_instructions,
			"include_patterns": pattern_list
		}

		result = ghidra_context.http_client.safe_post_json("get_assembly_context", data)

		# Format the JSON response for readability
		try:
			parsed = json.loads(result)
			return json.dumps(parsed, indent=2)
		except:
			return result

	@mcp.tool()
	def get_bulk_xrefs(addresses: str) -> str:
		"""
		Get cross-references for multiple addresses in a single batch request.

		This tool retrieves xrefs for multiple addresses simultaneously, dramatically
		reducing the number of network round-trips required for byte-by-byte analysis.

		Args:
			addresses: Comma-separated list of hex addresses (e.g., "0x6fb835b8,0x6fb835b9,0x6fb835ba")
					or JSON array string (e.g., '["0x6fb835b8", "0x6fb835b9"]')

		Returns:
			JSON string with xref mappings:
			{
			"0x6fb835b8": [{"from": "0x6fb6cae9", "type": "DATA"}],
			"0x6fb835b9": [],
			"0x6fb835ba": [],
			"0x6fb835bc": [{"from": "0x6fb6c9fe", "type": "READ"}]
			}
		"""

		# Parse input - support both comma-separated and JSON array
		addr_list = []
		if addresses.startswith('['):
			try:
				addr_list = json.loads(addresses)
			except:
				raise GhidraValidationError("Invalid JSON array format for addresses")
		else:
			addr_list = [addr.strip() for addr in addresses.split(',')]

		# Validate all addresses
		for addr in addr_list:
			if not validate_hex_address(addr):
				raise GhidraValidationError(f"Invalid hex address format: {addr}")

		data = {"addresses": addr_list}
		result = ghidra_context.http_client.safe_post_json("get_bulk_xrefs", data)

		# Format the JSON response for readability
		try:
			parsed = json.loads(result)
			return json.dumps(parsed, indent=2)
		except:
			return result

	@mcp.tool()
	def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
		"""
		Get all references to the specified function by name.
		
		Args:
			name: Function name to search for
			offset: Pagination offset (default: 0)
			limit: Maximum number of references to return (default: 100)
			
		Returns:
			List of references to the specified function
		"""

		return ghidra_context.http_client.safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

	@mcp.tool()
	def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
		"""
		Get all references from the specified address (xref from).
		
		Args:
			address: Source address in hex format (e.g. "0x1400010a0")
			offset: Pagination offset (default: 0)
			limit: Maximum number of references to return (default: 100)
			
		Returns:
			List of references from the specified address
		"""

		if not validate_hex_address(address):
			raise GhidraValidationError(f"Invalid hexadecimal address: {address}")
		
		return ghidra_context.http_client.safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

	@mcp.tool()
	def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
		"""
		Get all references to the specified address (xref to).
		
		Args:
			address: Target address in hex format (e.g. "0x1400010a0")
			offset: Pagination offset (default: 0)
			limit: Maximum number of references to return (default: 100)
			
		Returns:
			List of references to the specified address
		"""

		if not validate_hex_address(address):
			raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

		return ghidra_context.http_client.safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})
