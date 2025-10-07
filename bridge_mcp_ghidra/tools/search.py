from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context, GhidraValidationError

def register_search_tools(mcp: FastMCP):
	"""Register search tools in the MCP instance."""

	@mcp.tool()
	def detect_crypto_constants() -> list:
		"""
		Identify cryptographic constants and algorithms in the binary.
		Searches for known crypto constants like AES S-boxes, SHA constants, etc.
		
		Returns:
			List of potential crypto constants with algorithm identification
		"""
		return ghidra_context.http_client.safe_get("detect_crypto_constants")

	@mcp.tool()
	def detect_malware_behaviors() -> list:
		"""
		Automatically detect common malware behaviors and techniques.
		Analyzes code patterns to identify potential malicious functionality.
		
		Returns:
			List of detected behaviors with confidence scores and evidence
		"""
		return ghidra_context.http_client.safe_get("detect_malware_behaviors")

	@mcp.tool()
	def find_anti_analysis_techniques() -> list:
		"""
		Detect anti-analysis, anti-debugging, and evasion techniques.
		Looks for common obfuscation and evasion patterns used by malware.
		
		Returns:
			List of detected evasion techniques with locations and descriptions
		"""
		return ghidra_context.http_client.safe_get("find_anti_analysis_techniques")

	@mcp.tool()
	def find_dead_code(function_name: str) -> list:
		"""
		Identify potentially unreachable code blocks within a function.
		Useful for finding hidden functionality or dead code elimination.
		
		Args:
			function_name: Name of the function to analyze
			
		Returns:
			List of potentially unreachable code blocks with addresses
		"""
		if not ghidra_context.validate_function_name(function_name):
			raise GhidraValidationError(f"Invalid function name: {function_name}")

		return ghidra_context.http_client.safe_get("find_dead_code", {"function_name": function_name})

	@mcp.tool()
	def find_similar_functions(target_function: str, threshold: float = 0.8) -> list:
		"""
		Find functions similar to target using structural analysis.
		Uses control flow and instruction patterns to identify similar functions.
		
		Args:
			target_function: Name of the function to compare against
			threshold: Similarity threshold (0.0 to 1.0, higher = more similar)
			
		Returns:
			List of similar functions with similarity scores
		"""
		if not ghidra_context.validate_function_name(target_function):
			raise GhidraValidationError(f"Invalid function name: {target_function}")

		return ghidra_context.http_client.safe_get("find_similar_functions", {
			"target_function": target_function,
			"threshold": threshold
		})

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
	def search_data_types(pattern: str, offset: int = 0, limit: int = 100) -> list:
		"""
		Search for data types by name pattern.
		
		Args:
			pattern: Search pattern to match against data type names
			offset: Pagination offset (default: 0)
			limit: Maximum number of results to return (default: 100)
			
		Returns:
			List of matching data types with their details
		"""
		return ghidra_context.http_client.safe_get("search_data_types", {"pattern": pattern, "offset": offset, "limit": limit})

	@mcp.tool()
	def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
		"""
		Search for functions whose name contains the given substring.
		
		Args:
			query: Search string to match against function names
			offset: Pagination offset for starting position (default: 0)
			limit: Maximum number of results to return (default: 100)
			
		Returns:
			List of matching functions with their names and addresses
		"""
		if not query:
			return ["Error: query string is required"]
		return ghidra_context.http_client.safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})
