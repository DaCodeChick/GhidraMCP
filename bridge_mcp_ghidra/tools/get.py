from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context, GhidraValidationError, validate_hex_address

def register_get_tools(mcp: FastMCP):
	"""Register the get endpoints."""

	@mcp.tool()
	def decrypt_strings_auto() -> list:
		"""
		Automatically identify and attempt to decrypt common string obfuscation patterns.
		Detects XOR encoding, Base64, ROT13, and simple stack strings.
		
		Returns:
			List of decrypted strings with their locations and decryption method
		"""
		
		return ghidra_context.http_client.safe_get("decrypt_strings_auto")

	@mcp.tool()
	def extract_iocs() -> dict:
		"""
		Extract Indicators of Compromise (IOCs) from the binary.
		Finds IP addresses, URLs, file paths, registry keys, and other artifacts.
		
		Returns:
			Dictionary of IOCs organized by type (IPs, URLs, files, etc.)
		"""

		return ghidra_context.http_client.safe_get("extract_iocs")

	@mcp.tool()
	def extract_iocs_with_context() -> dict:
		"""
		Enhanced IOC extraction with analysis context and confidence scoring.
		Provides context about where/how IOCs are used and categorizes them.
		
		Returns:
			Dictionary of IOCs with context, confidence scores, and usage analysis
		"""

		return ghidra_context.http_client.safe_get("extract_iocs_with_context")

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
	def get_current_function() -> str:
		"""
		Get the function currently selected by the user.
		
		Args:
			None
			
		Returns:
			Information about the currently selected function including name and address
		"""

		return "\n".join(ghidra_context.http_client.safe_get_uncached("get_current_function"))
	
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
	def get_entry_points() -> list:
		"""
		Get all entry points in the database.
		
		Returns all program entry points including the main entry point and any
		additional entry points defined in the program.
		
		Returns:
			List of entry points with their addresses and names
		"""

		return ghidra_context.http_client.safe_get("get_entry_points")

	@mcp.tool()
	def get_enum_values(enum_name: str) -> str:
		"""
		Get all values and names in an enumeration.
		
		Args:
			enum_name: Name of the enumeration to query
			
		Returns:
			List of all enumeration values with their names and numeric values
		"""

		return ghidra_context.http_client.safe_get("get_enum_values", {"enum_name": enum_name})

	@mcp.tool()
	def get_full_call_graph(format: str = "edges", limit: int = 500) -> list:
		"""
		Get the complete call graph for the entire program.
		
		This tool generates a comprehensive call graph showing all function call
		relationships in the program. Can be output in different formats.
		
		Args:
			format: Output format ("edges", "adjacency", "dot", "mermaid")
			limit: Maximum number of relationships to return (default: 500)
			
		Returns:
			Complete call graph in the specified format
		"""

		return ghidra_context.http_client.safe_get("full_call_graph", {"format": format, "limit": limit})

	@mcp.tool()
	def get_function_by_address(address: str) -> str:
		"""
		Get a function by its address.
		
		Args:
			address: Memory address in hex format (e.g., "0x1400010a0")
			
		Returns:
			Function information including name, signature, and address range
		"""

		if not validate_hex_address(address):
			raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

		return "\n".join(ghidra_context.http_client.safe_get("get_function_by_address", {"address": address}))
	
	@mcp.tool()
	def get_function_call_graph(name: str, depth: int = 2, direction: str = "both") -> list:
		"""
		Get a call graph subgraph centered on the specified function.
		
		This tool generates a localized call graph showing the relationships between
		a function and its callers/callees up to a specified depth.
		
		Args:
			name: Function name to center the graph on
			depth: Maximum depth to traverse (default: 2)
			direction: Direction to traverse ("callers", "callees", "both")
			
		Returns:
			List of call graph relationships in the format "caller -> callee"
		"""

		return ghidra_context.http_client.safe_get("function_call_graph", {"name": name, "depth": depth, "direction": direction})

	@mcp.tool()
	def get_function_callees(name: str, offset: int = 0, limit: int = 100) -> list:
		"""
		Get all functions called by the specified function (callees).
		
		This tool analyzes a function and returns all functions that it calls directly.
		Useful for understanding what functionality a function depends on.
		
		Args:
			name: Function name to analyze for callees
			offset: Pagination offset (default: 0)
			limit: Maximum number of callees to return (default: 100)
			
		Returns:
			List of functions called by the specified function
		"""

		return ghidra_context.http_client.safe_get("function_callees", {"name": name, "offset": offset, "limit": limit})

	@mcp.tool()
	def get_function_callers(name: str, offset: int = 0, limit: int = 100) -> list:
		"""
		Get all functions that call the specified function (callers).
		
		This tool finds all functions that call the specified function, helping to
		understand the function's usage throughout the program.
		
		Args:
			name: Function name to find callers for
			offset: Pagination offset (default: 0)
			limit: Maximum number of callers to return (default: 100)
			
		Returns:
			List of functions that call the specified function
		"""

		return ghidra_context.http_client.safe_get("function_callers", {"name": name, "offset": offset, "limit": limit})

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

	@mcp.tool()
	def get_function_labels(name: str, offset: int = 0, limit: int = 20) -> list:
		"""
		Get all labels within the specified function by name.
		
		Args:
			name: Function name to search for labels within
			offset: Pagination offset (default: 0)
			limit: Maximum number of labels to return (default: 20)
			
		Returns:
			List of labels found within the specified function
		"""

		return ghidra_context.http_client.safe_get("function_labels", {"name": name, "offset": offset, "limit": limit})

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
	def get_metadata() -> str:
		"""
		Get metadata about the current program/database.
		
		Returns program information including name, architecture, base address,
		entry points, and other relevant metadata.
		
		Returns:
			JSON string with program metadata
		"""

		return "\n".join(ghidra_context.http_client.safe_get("get_metadata"))
	
	@mcp.tool()
	def get_struct_layout(struct_name: str) -> list:
		"""
		Get the detailed layout of a structure including field offsets.
		
		Args:
			struct_name: Name of the structure to analyze
			
		Returns:
			Detailed structure layout with field offsets, sizes, and types
		"""

		return ghidra_context.http_client.safe_get("get_struct_layout", {"struct_name": struct_name})

	@mcp.tool()
	def get_type_size(type_name: str) -> list:
		"""
		Get the size and alignment information for a data type.
		
		Args:
			type_name: Name of the data type to query
			
		Returns:
			Size, alignment, and path information for the data type
		"""

		return ghidra_context.http_client.safe_get("get_type_size", {"type_name": type_name})

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

		if not ghidra_context.validate_hex_address(address):
			raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

		return ghidra_context.http_client.safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})
