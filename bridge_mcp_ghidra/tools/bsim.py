from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context

def register_bsim_tools(mcp: FastMCP):
	"""Register the BSim tools to the MCP instance."""

	@mcp.tool()
	def bsim_disconnect() -> str:
		"""
		Disconnect from the current BSim database.
		Returns:
			Disconnection status message
		"""
		return ghidra_context.http_client.safe_post("bsim/disconnect", {})

	@mcp.tool()
	def bsim_get_match_decompile(
		executable_path: str,
		function_name: str,
		function_address: str,
	) -> str:
		"""
		Get the decompilation of a specific BSim match. This requires the matched 
		executable to be available in the Ghidra project.
		Args:
			executable_path: Path to the matched executable (from BSim match result)
			function_name: Name of the matched function
			function_address: Address of the matched function (e.g., "0x401000")
		Returns:
			Function prototype and decompiled C code for the matched function.
			Returns an error message if the program is not found in the project.
		"""
		return ghidra_context.http_client.safe_post("bsim/get_match_decompile", {
			"executable_path": executable_path,
			"function_name": function_name,
			"function_address": function_address,
		})

	@mcp.tool()
	def bsim_get_match_disassembly(
		executable_path: str,
		function_name: str,
		function_address: str,
	) -> str:
		"""
		Get the disassembly of a specific BSim match. This requires the matched 
		executable to be available in the Ghidra project.
		Args:
			executable_path: Path to the matched executable (from BSim match result)
			function_name: Name of the matched function
			function_address: Address of the matched function (e.g., "0x401000")
		Returns:
			Function prototype and assembly code for the matched function.
			Returns an error message if the program is not found in the project.
		"""
		return ghidra_context.http_client.safe_post("bsim/get_match_disassembly", {
			"executable_path": executable_path,
			"function_name": function_name,
			"function_address": function_address,
		})

	@mcp.tool()
	def bsim_query_all_functions(
		max_matches_per_function: int = 5,
		similarity_threshold: float = 0.7,
		confidence_threshold: float = 0.0,
		max_similarity: float | None = None,
		max_confidence: float | None = None,
		offset: int = 0,
		limit: int = 100,
	) -> str:
		"""
		Query all functions in the current program against the BSim database.
		Returns an overview of matches for all functions.
		Args:
			max_matches_per_function: Max matches per function (default: 5)
			similarity_threshold: Minimum similarity score (inclusive, 0.0-1.0, default: 0.7)
			confidence_threshold: Minimum confidence score (inclusive, 0.0-1.0, default: 0.0)
			max_similarity: Maximum similarity score (exclusive, 0.0-1.0, default: unbounded)
			max_confidence: Maximum confidence score (exclusive, 0.0-1.0, default: unbounded)
			offset: Pagination offset (default: 0)
			limit: Maximum number of results to return (default: 100)
		Returns:
			Summary and detailed results for all matching functions
		"""
		data = {
			"max_matches_per_function": str(max_matches_per_function),
			"similarity_threshold": str(similarity_threshold),
			"confidence_threshold": str(confidence_threshold),
			"offset": str(offset),
			"limit": str(limit),
		}

		if max_similarity is not None:
			data["max_similarity"] = str(max_similarity)
		if max_confidence is not None:
			data["max_confidence"] = str(max_confidence)

		return ghidra_context.http_client.safe_post("bsim/query_all_functions", data)

	@mcp.tool()
	def bsim_query_function(
		function_address: str,
		max_matches: int = 10,
		similarity_threshold: float = 0.7,
		confidence_threshold: float = 0.0,
		max_similarity: float | None = None,
		max_confidence: float | None = None,
		offset: int = 0,
		limit: int = 100,
	) -> str:
		"""
		Query a single function against the BSim database to find similar functions.
		Args:
			function_address: Address of the function to query (e.g., "0x401000")
			max_matches: Maximum number of matches to return (default: 10)
			similarity_threshold: Minimum similarity score (inclusive, 0.0-1.0, default: 0.7)
			confidence_threshold: Minimum confidence score (inclusive, 0.0-1.0, default: 0.0)
			max_similarity: Maximum similarity score (exclusive, 0.0-1.0, default: unbounded)
			max_confidence: Maximum confidence score (exclusive, 0.0-1.0, default: unbounded)
			offset: Pagination offset (default: 0)
			limit: Maximum number of results to return (default: 100)
		Returns:
			List of matching functions with similarity scores and metadata
		"""
		data = {
			"function_address": function_address,
			"max_matches": str(max_matches),
			"similarity_threshold": str(similarity_threshold),
			"confidence_threshold": str(confidence_threshold),
			"offset": str(offset),
			"limit": str(limit),
		}

		if max_similarity is not None:
			data["max_similarity"] = str(max_similarity)
		if max_confidence is not None:
			data["max_confidence"] = str(max_confidence)

		return ghidra_context.http_client.safe_post("bsim/query_function", data)

	@mcp.tool()
	def bsim_select_database(database_path: str) -> str:
		"""
		Select and connect to a BSim database for function similarity matching.
		Args:
			database_path: Path to BSim database file (e.g., "/path/to/database.bsim")
						or URL (e.g., "postgresql://host:port/dbname")
		Returns:
			Connection status and database information
		"""
		return ghidra_context.http_client.safe_post("bsim/select_database", {"database_path": database_path})
	
	@mcp.tool()
	def bsim_status() -> str:
		"""
		Get the current BSim database connection status.
		Returns:
			Current connection status and database path if connected
		"""
		return "\n".join(ghidra_context.http_client.safe_get("bsim/status"))
