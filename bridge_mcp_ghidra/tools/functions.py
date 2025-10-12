from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context, GhidraValidationError, validate_function_name, validate_hex_address

def register_function_tools(mcp: FastMCP):
	"""Register function-related tools to the FastMCP instance."""

	@mcp.tool()
	def analyze_control_flow(function_name: str) -> dict:
		"""
		Analyze control flow complexity, cyclomatic complexity, and basic blocks.
		Provides detailed analysis of function complexity and structure.
		
		Args:
			function_name: Name of the function to analyze
			
		Returns:
			Dictionary with control flow analysis results
		"""

		if not ghidra_context.validate_function_name(function_name):
			raise GhidraValidationError(f"Invalid function name: {function_name}")

		return ghidra_context.http_client.safe_get("analyze_control_flow", {"function_name": function_name})

	@mcp.tool()
	def analyze_function_complexity(function_name: str) -> dict:
		"""
		Calculate various complexity metrics for a function.
		Includes cyclomatic complexity, lines of code, branch count, etc.
		
		Args:
			function_name: Name of the function to analyze
			
		Returns:
			Dictionary with complexity metrics
		"""

		if not validate_function_name(function_name):
			raise GhidraValidationError(f"Invalid function name: {function_name}")

		return ghidra_context.http_client.safe_get("analyze_function_complexity", {"function_name": function_name})

	@mcp.tool()
	def batch_decompile_functions(function_names: list) -> dict:
		"""
		Decompile multiple functions in a single request for better performance.
		
		Args:
			function_names: List of function names to decompile
			
		Returns:
			Dictionary mapping function names to their decompiled code
		"""
		
		# Validate all function names
		for name in function_names:
			if not validate_function_name(name):
				raise GhidraValidationError(f"Invalid function name: {name}")

		return ghidra_context.http_client.safe_get("batch_decompile", {"functions": ",".join(function_names)})

	@mcp.tool()
	def batch_rename_functions(renames: dict) -> dict:
		"""
		Rename multiple functions atomically.
		
		Args:
			renames: Dictionary mapping old names to new names
			
		Returns:
			Dictionary with rename results and any errors
		"""

		# Validate all function names
		for old_name, new_name in renames.items():
			if not validate_function_name(old_name):
				raise GhidraValidationError(f"Invalid old function name: {old_name}")
			if not validate_function_name(new_name):
				raise GhidraValidationError(f"Invalid new function name: {new_name}")

		return ghidra_context.http_client.safe_get("batch_rename_functions", {"renames": str(renames)})

	@mcp.tool()
	def create_function_signature(name: str, return_type: str, parameters: str = None) -> str:
		"""
		Create a function signature data type.
		
		This tool creates a new function signature data type that can be used
		for function pointers and type definitions.
		
		Args:
			name: Name for the function signature
			return_type: Return type of the function
			parameters: Optional JSON string describing parameters (e.g., '[{"name": "param1", "type": "int"}]')
			
		Returns:
			Success or failure message with function signature creation details
		"""

		if not name or not isinstance(name, str):
			raise GhidraValidationError("Function name is required and must be a string")
		if not return_type or not isinstance(return_type, str):
			raise GhidraValidationError("Return type is required and must be a string")
		
		data = {
			"name": name,
			"return_type": return_type
		}
		if parameters:
			data["parameters"] = parameters
		
		return ghidra_context.http_client.safe_post_json("create_function_signature", data)
	
	@mcp.tool()
	def decompile_function(name: str) -> str:
		"""
		Decompile a specific function by name and return the decompiled C code.
		
		Args:
			name: Function name to decompile
			
		Returns:
			Decompiled C code as a string
		"""

		return ghidra_context.http_client.safe_post("decompile", name)
	
	@mcp.tool()
	def disassemble_function(address: str) -> list:
		"""
		Get assembly code (address: instruction; comment) for a function.
		
		Args:
			address: Memory address in hex format (e.g., "0x1400010a0")
			
		Returns:
			List of assembly instructions with addresses and comments
		"""

		if not validate_hex_address(address):
			raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

		return ghidra_context.http_client.safe_get("disassemble_function", {"address": address})

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
	def list_functions(offset: int = 0, limit: int = 100) -> list:
		"""
		List all function names in the program with pagination.
		
		Args:
			offset: Pagination offset for starting position (default: 0)
			limit: Maximum number of functions to return (default: 100)
			
		Returns:
			List of function names with pagination information
		"""

		return ghidra_context.http_client.safe_get("functions", {"offset": offset, "limit": limit})
	
	@mcp.tool()
	def rename_function(old_name: str, new_name: str) -> str:
		"""
		Rename a function by its current name to a new user-defined name.
		
		Args:
			old_name: Current name of the function to rename
			new_name: New name for the function
			
		Returns:
			Success or failure message indicating the result of the rename operation
		"""

		return ghidra_context.http_client.safe_post("renameFunction", {"oldName": old_name, "newName": new_name})
	
	@mcp.tool()
	def rename_function_by_address(function_address: str, new_name: str) -> str:
		"""
		Rename a function by its address.
		
		Args:
			function_address: Memory address of the function in hex format (e.g., "0x1400010a0")
			new_name: New name for the function
			
		Returns:
			Success or failure message indicating the result of the rename operation
		"""

		if not validate_hex_address(function_address):
			raise GhidraValidationError(f"Invalid hexadecimal address: {function_address}")

		return ghidra_context.http_client.safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

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
			raise GhidraValidationError("query string is required")
		return ghidra_context.http_client.safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

	@mcp.tool()
	def set_function_prototype(function_address: str, prototype: str, calling_convention: str = None) -> str:
		"""
		Set a function's prototype and optionally its calling convention.
		
		Args:
			function_address: Memory address of the function in hex format (e.g., "0x1400010a0")
			prototype: Function prototype string (e.g., "int main(int argc, char* argv[])")
			calling_convention: Optional calling convention (e.g., "__cdecl", "__stdcall", "__fastcall", "__thiscall")

		Returns:
			Success or failure message indicating the result of the prototype update
		"""

		if not validate_hex_address(function_address):
			raise GhidraValidationError(f"Invalid hexadecimal address: {function_address}")

		data = {"function_address": function_address, "prototype": prototype}
		if calling_convention:
			data["callingConvention"] = calling_convention
		return ghidra_context.http_client.safe_post_json("set_function_prototype", data)
