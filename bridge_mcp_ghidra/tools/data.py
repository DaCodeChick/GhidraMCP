import json
from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context, GhidraValidationError, validate_hex_address

def _check_if_data_defined(address: str) -> bool:
	"""
	Internal helper: Check if address has a defined data symbol.

	Args:
		address: Hex address to check

	Returns:
		True if data is defined, False if undefined
	"""

	try:
		result = ghidra_context.http_client.safe_post_json("analyze_data_region", {
			"address": address,
			"max_scan_bytes": 16,
			"include_xref_map": False,
			"include_assembly_patterns": False,
			"include_boundary_detection": False
		})

		if result and not result.startswith("Error"):
			data = json.loads(result)
			current_type = data.get("current_type", "undefined")
			# If current_type is "undefined", it's not a defined data item
			return current_type != "undefined"
	except Exception as e:
		ghidra_context.http_client.logger.warning(f"Failed to check if data defined at {address}: {e}")

	return False

def register_data_tools(mcp: FastMCP):
	"""Register data-related tools to the FastMCP instance."""

	@mcp.tool()
	def analyze_data_region(
		address: str,
		max_scan_bytes: int = 1024,
		include_xref_map: bool = True,
		include_assembly_patterns: bool = True,
		include_boundary_detection: bool = True
	) -> str:
		"""
		Comprehensive single-call analysis of a data region.

		This tool performs complete data region analysis including boundary detection,
		byte-by-byte xref mapping, stride detection, and classification hints.
		Replaces 20-30 individual tool calls with one efficient batch operation.

		Args:
			address: Starting address in hex format (e.g., "0x6fb835b8")
			max_scan_bytes: Maximum bytes to scan for boundary detection (default: 1024)
			include_xref_map: Include detailed byte-by-byte xref mapping (default: True)
			include_assembly_patterns: Include assembly pattern analysis (default: True)
			include_boundary_detection: Detect data region boundaries (default: True)

		Returns:
			JSON string with comprehensive analysis:
			{
			"start_address": "0x6fb835b8",
			"end_address": "0x6fb835d4",
			"byte_span": 28,
			"xref_map": {"0x6fb835b8": [{"from": "0x6fb6cae9", "type": "DATA"}], ...},
			"unique_xref_addresses": ["0x6fb835b8", "0x6fb835bc", ...],
			"unique_xref_count": 5,
			"classification_hint": "STRUCTURE|ARRAY|PRIMITIVE",
			"stride_detected": 4,
			"next_boundary_address": "0x6fb835d4",
			"next_boundary_reason": "different_xref_set|named_label|end_of_data",
			"current_name": "DAT_6fb835b8",
			"current_type": "undefined"
			}
		"""

		if not validate_hex_address(address):
			raise GhidraValidationError(f"Invalid hex address format: {address}")

		if not isinstance(max_scan_bytes, int) or max_scan_bytes <= 0:
			raise GhidraValidationError("max_scan_bytes must be a positive integer")

		data = {
			"address": address,
			"max_scan_bytes": max_scan_bytes,
			"include_xref_map": include_xref_map,
			"include_assembly_patterns": include_assembly_patterns,
			"include_boundary_detection": include_boundary_detection
		}

		result = ghidra_context.http_client.safe_post_json("analyze_data_region", data)

		# Format the JSON response for readability
		try:
			parsed = json.loads(result)
			return json.dumps(parsed, indent=2)
		except:
			return result
	
	@mcp.tool()
	def format_number_conversions(text: str, size: int = 4) -> str:
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
	def get_data_by_label(label: str) -> str:
		"""
		Get information about a data label.

		Args:
			label: Exact symbol / label name to look up in the program.

		Returns:
			A newline-separated string.  
			Each line has:  "<label> -> <address> : <value-representation>"
			If the label is not found, an explanatory message is returned.
		"""

		return "\n".join(ghidra_context.http_client.safe_get("get_data_by_label", {"label": label}))

	@mcp.tool()
	def inspect_memory_content(address: str, length: int = 64, detect_strings: bool = True) -> str:
		"""
		Read raw memory bytes and provide hex/ASCII representation with string detection hints.

		This tool helps prevent misidentification of strings as numeric data by:
		- Reading actual byte content in hex and ASCII format
		- Detecting printable ASCII characters and null terminators
		- Calculating string likelihood score
		- Suggesting appropriate data types (char[N] for strings, etc.)

		Args:
			address: Memory address in hex format (e.g., "0x6fb7ffbc")
			length: Number of bytes to read (default: 64)
			detect_strings: Enable string detection heuristics (default: True)

		Returns:
			JSON string with memory inspection results:
			{
			"address": "0x6fb7ffbc",
			"bytes_read": 64,
			"hex_dump": "4A 75 6C 79 00 ...",
			"ascii_repr": "July\\0...",
			"printable_count": 4,
			"printable_ratio": 0.80,
			"null_terminator_at": 4,
			"max_consecutive_printable": 4,
			"is_likely_string": true,
			"detected_string": "July",
			"suggested_type": "char[5]",
			"string_length": 5
			}
		"""

		if not validate_hex_address(address):
			raise GhidraValidationError(f"Invalid hex address format: {address}")

		if not isinstance(length, int) or length <= 0 or length > 4096:
			raise GhidraValidationError("length must be a positive integer <= 4096")

		params = {
			"address": address,
			"length": length,
			"detect_strings": str(detect_strings).lower()
		}

		result = "\n".join(ghidra_context.http_client.safe_get("inspect_memory_content", params))

		# Try to format as JSON for readability
		try:
			parsed = json.loads(result)
			return json.dumps(parsed, indent=2)
		except:
			return result

	@mcp.tool()
	def list_data_items(offset: int = 0, limit: int = 100) -> list:
		"""
		List defined data labels and their values with pagination.
		
		Args:
			offset: Pagination offset for starting position (default: 0)
			limit: Maximum number of data items to return (default: 100)
			
		Returns:
			List of data labels with their addresses, names, and values
		"""

		return ghidra_context.http_client.safe_get("data", {"offset": offset, "limit": limit})

	@mcp.tool()
	def list_segments(offset: int = 0, limit: int = 100) -> list:
		"""
		List all memory segments in the program with pagination.
		
		Args:
			offset: Pagination offset for starting position (default: 0)
			limit: Maximum number of segments to return (default: 100)
			
		Returns:
			List of memory segments with their addresses, names, and properties
		"""

		return ghidra_context.http_client.safe_get("segments", {"offset": offset, "limit": limit})

	@mcp.tool()
	def rename_data(address: str, new_name: str) -> str:
		"""
		Rename a data label at the specified address.
		
		Args:
			address: Memory address in hex format (e.g., "0x1400010a0")
			new_name: New name for the data label
			
		Returns:
			Success or failure message indicating the result of the rename operation
		"""

		if not validate_hex_address(address):
			raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

		response = ghidra_context.http_client.safe_post("renameData", {"address": address, "newName": new_name})

		# Validate response and provide clear success message
		if "success" in response.lower() or "renamed" in response.lower():
			return f"Successfully renamed data at {address} to '{new_name}'"
		elif "error" in response.lower() or "failed" in response.lower():
			return response  # Return original error message
		else:
			return f"Rename operation completed: {response}"
	
	@mcp.tool()
	def rename_data_smart(address: str, new_name: str) -> str:
		"""
		Intelligently rename data at an address, automatically detecting if it's
		defined data or undefined bytes and using the appropriate method.

		This tool automatically chooses between rename_data (for defined symbols)
		and create_label (for undefined addresses) based on the current state.

		Args:
			address: Memory address in hex format (e.g., "0x1400010a0")
			new_name: New name for the data label

		Returns:
			Success or failure message with details about the operation performed
		"""

		if not validate_hex_address(address):
			raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

		# Check if data is defined
		is_defined = _check_if_data_defined(address)

		if is_defined:
			# Use rename_data endpoint for defined symbols
			ghidra_context.http_client.logger.info(f"Address {address} has defined data, using rename_data")
			response = ghidra_context.http_client.safe_post("renameData", {"address": address, "newName": new_name})

			if "success" in response.lower() or "renamed" in response.lower():
				return f"✓ Renamed defined data at {address} to '{new_name}'"
			else:
				return f"Rename data attempted: {response}"
		else:
			# Use create_label for undefined addresses
			ghidra_context.http_client.logger.info(f"Address {address} is undefined, using create_label")
			response = ghidra_context.http_client.safe_post("create_label", {"address": address, "name": new_name})

			if "success" in response.lower() or "created" in response.lower():
				return f"✓ Created label '{new_name}' at {address} (was undefined)"
			else:
				return f"Create label attempted: {response}"

	@mcp.tool()
	def search_byte_patterns(pattern: str, mask: str = None) -> list:
		"""
		Search for byte patterns with optional masks (e.g., 'E8 ?? ?? ?? ??').
		Useful for finding shellcode, API calls, or specific instruction sequences.
		
		Args:
			pattern: Hexadecimal pattern to search for (e.g., "E8 ?? ?? ?? ??")
			mask: Optional mask for wildcards (use ? for wildcards)
			
		Returns:
			List of addresses where the pattern was found
		"""
		params = {"pattern": pattern}
		if mask:
			params["mask"] = mask
		return ghidra_context.http_client.safe_get("search_byte_patterns", params)

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
