import json
from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context, GhidraValidationError, validate_hex_address

def register_array_tools(mcp: FastMCP):
	"""Register array-related tools in the MCP instance."""

	@mcp.tool()
	def create_array_type(base_type: str, length: int, name: str = None) -> str:
		"""
		Create an array data type.
		
		This tool creates a new array data type based on an existing base type
		with the specified length.
		
		Args:
			base_type: Name of the base data type for the array
			length: Number of elements in the array
			name: Optional name for the array type
			
		Returns:
			Success or failure message with created array type details
		"""

		if not base_type or not isinstance(base_type, str):
			raise GhidraValidationError("Base type is required and must be a string")
		if not isinstance(length, int) or length <= 0:
			raise GhidraValidationError("Length must be a positive integer")
		
		data = {
			"base_type": base_type,
			"length": length
		}
		if name:
			data["name"] = name
		
		return ghidra_context.http_client.safe_post_json("create_array_type", data)

	@mcp.tool()
	def detect_array_bounds(
		address: str,
		analyze_loop_bounds: bool = True,
		analyze_indexing: bool = True,
		max_scan_range: int = 2048
	) -> str:
		"""
		Automatically detect array/table size and element boundaries.

		This tool analyzes assembly patterns including loop bounds, array indexing,
		and comparison checks to determine the true size of arrays and tables.

		Args:
			address: Starting address of array/table in hex format (e.g., "0x6fb835d4")
			analyze_loop_bounds: Analyze loop CMP instructions for bounds (default: True)
			analyze_indexing: Analyze array indexing patterns for stride (default: True)
			max_scan_range: Maximum bytes to scan for table end (default: 2048)

		Returns:
			JSON string with array analysis:
			{
			"probable_element_size": 12,
			"probable_element_count": 4,
			"total_bytes": 48,
			"confidence": "high|medium|low",
			"evidence": [
				{"type": "loop_bound", "address": "0x6fb6a023", "instruction": "CMP ECX, 4"},
				{"type": "stride_pattern", "stride": 12, "occurrences": 8},
				{"type": "boundary", "address": "0x6fb83604", "reason": "comparison_limit"}
			],
			"loop_functions": ["ProcessTimedSpellEffect..."],
			"indexing_patterns": ["[base + index*12]", "LEA EDX, [EAX*3 + base]"]
			}
		"""

		if not validate_hex_address(address):
			raise GhidraValidationError(f"Invalid hex address format: {address}")

		if not isinstance(max_scan_range, int) or max_scan_range <= 0:
			raise GhidraValidationError("max_scan_range must be a positive integer")

		data = {
			"address": address,
			"analyze_loop_bounds": analyze_loop_bounds,
			"analyze_indexing": analyze_indexing,
			"max_scan_range": max_scan_range
		}

		result = ghidra_context.http_client.safe_post_json("detect_array_bounds", data)

		# Format the JSON response for readability
		try:
			parsed = json.loads(result)
			return json.dumps(parsed, indent=2)
		except:
			return result
