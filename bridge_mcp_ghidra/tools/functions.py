from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context, GhidraValidationError, validate_hex_address

def register_function_tools(mcp: FastMCP):
	"""Register function-related tools to the FastMCP instance."""

	@mcp.tool()
	def analyze_function_complete(
		name: str,
		include_xrefs: bool = True,
		include_callees: bool = True,
		include_callers: bool = True,
		include_disasm: bool = True,
		include_variables: bool = True
	) -> str:
		"""
		Comprehensive function analysis in a single call (v1.6.0).

		Replaces 5+ individual calls with one efficient operation, dramatically
		reducing network round-trips during function documentation.

		Args:
			name: Function name to analyze
			include_xrefs: Include cross-references to function
			include_callees: Include functions this function calls
			include_callers: Include functions that call this function
			include_disasm: Include disassembly listing
			include_variables: Include parameter and local variable info

		Returns:
			JSON with complete function analysis:
			{
			"decompiled_code": "void foo() { ... }",
			"xrefs": [{"from": "0x...", "type": "CALL"}],
			"callees": [{"name": "bar", "address": "0x..."}],
			"callers": [{"name": "main", "address": "0x..."}],
			"disassembly": [{"address": "0x...", "instruction": "MOV EAX, ..."}],
			"variables": {"parameters": [...], "locals": [...]}
			}
		"""

		params = {
			"name": name,
			"include_xrefs": include_xrefs,
			"include_callees": include_callees,
			"include_callers": include_callers,
			"include_disasm": include_disasm,
			"include_variables": include_variables
		}
		return ghidra_context.http_client.safe_get("analyze_function_complete", params)

	@mcp.tool()
	def analyze_function_completeness(
		function_address: str
	) -> str:
		"""
		Analyze how completely a function has been documented (v1.5.0).
		Checks for custom names, prototypes, comments, and undefined variables.

		Args:
			function_address: Function address in hex format

		Returns:
			JSON with completeness analysis including:
			- has_custom_name, has_prototype, has_calling_convention
			- has_plate_comment, undefined_variables
			- completeness_score (0-100)
		"""
		validate_hex_address(function_address)

		params = {"function_address": function_address}
		return ghidra_context.http_client.safe_get("analyze_function_completeness", params)

	@mcp.tool()
	def batch_rename_function_components(
		function_address: str,
		function_name: str = None,
		parameter_renames: dict = None,
		local_renames: dict = None,
		return_type: str = None
	) -> str:
		"""
		Rename function and all its components atomically (v1.5.0).
		Combines multiple rename operations into a single transaction.

		Args:
			function_address: Function address in hex format
			function_name: New name for the function (optional)
			parameter_renames: Dict of {"old_name": "new_name"} for parameters
			local_renames: Dict of {"old_name": "new_name"} for local variables
			return_type: New return type (optional)

		Returns:
			JSON with success status and counts of renamed components
		"""
		validate_hex_address(function_address)

		payload = {
			"function_address": function_address,
			"function_name": function_name,
			"parameter_renames": parameter_renames or {},
			"local_renames": local_renames or {},
			"return_type": return_type
		}

		return ghidra_context.http_client.safe_post_json("batch_rename_function_components", payload)

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
	def document_function_complete(
		function_address: str,
		new_name: str = None,
		prototype: str = None,
		calling_convention: str = None,
		variable_renames: dict = None,
		variable_types: dict = None,
		labels: list = None,
		plate_comment: str = None,
		decompiler_comments: list = None,
		disassembly_comments: list = None
	) -> str:
		"""
		Document a function completely in one atomic operation (v1.6.0).

		Combines rename, prototype, variables, labels, and comments into a
		single transaction. Either all changes succeed or all are rolled back.

		Replaces 15-20 individual MCP calls with one efficient operation.

		Args:
			function_address: Function address in hex format
			new_name: New function name (optional)
			prototype: Function prototype (optional)
			calling_convention: Calling convention (optional)
			variable_renames: Dict of {"old_name": "new_name"} (optional)
			variable_types: Dict of {"var_name": "type"} (optional)
			labels: List of {"address": "0x...", "name": "label"} (optional)
			plate_comment: Function header comment (optional)
			decompiler_comments: List of {"address": "0x...", "comment": "..."} (optional)
			disassembly_comments: List of {"address": "0x...", "comment": "..."} (optional)

		Returns:
			JSON with operation results:
			{
			"success": true,
			"function_renamed": true,
			"prototype_set": true,
			"variables_renamed": 5,
			"variables_typed": 3,
			"labels_created": 8,
			"comments_set": 25,
			"errors": []
			}

		Example:
			document_function_complete(
				function_address="0x6fb385a0",
				new_name="ProcessPlayerSkillCooldowns",
				prototype="void ProcessPlayerSkillCooldowns(void)",
				calling_convention="__cdecl",
				variable_renames={"param_1": "playerNode"},
				labels=[{"address": "0x6fb385c0", "name": "loop_next_player"}],
				plate_comment="Processes skill cooldowns for all players"
			)
		"""
		validate_hex_address(function_address)

		payload = {
			"function_address": function_address,
			"new_name": new_name,
			"prototype": prototype,
			"calling_convention": calling_convention,
			"variable_renames": variable_renames or {},
			"variable_types": variable_types or {},
			"labels": labels or [],
			"plate_comment": plate_comment,
			"decompiler_comments": decompiler_comments or [],
			"disassembly_comments": disassembly_comments or []
		}

		return ghidra_context.http_client.safe_post_json("document_function_complete", payload)

	@mcp.tool()
	def find_next_undefined_function(
		start_address: str = None,
		criteria: str = "name_pattern",
		pattern: str = "FUN_",
		direction: str = "ascending"
	) -> str:
		"""
		Find the next function needing analysis (v1.5.0).
		Intelligently searches for functions matching specified criteria.

		Args:
			start_address: Starting address for search (default: program min address)
			criteria: Search criteria (default: "name_pattern")
			pattern: Name pattern to match (default: "FUN_")
			direction: Search direction "ascending" or "descending" (default: "ascending")

		Returns:
			JSON with found function details or {"found": false}
		"""
		if start_address:
			validate_hex_address(start_address)

		params = {
			"start_address": start_address,
			"criteria": criteria,
			"pattern": pattern,
			"direction": direction
		}
		return ghidra_context.http_client.safe_get("find_next_undefined_function", params)

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
	def search_functions_enhanced(
		name_pattern: str = None,
		min_xrefs: int = None,
		max_xrefs: int = None,
		calling_convention: str = None,
		has_custom_name: bool = None,
		regex: bool = False,
		sort_by: str = "address",
		offset: int = 0,
		limit: int = 100
	) -> str:
		"""
		Enhanced function search with filtering and sorting (v1.6.0).

		Provides powerful search capabilities to find functions matching
		multiple criteria, with support for regex patterns and sorting.

		Args:
			name_pattern: Function name pattern (substring or regex)
			min_xrefs: Minimum number of cross-references
			max_xrefs: Maximum number of cross-references
			calling_convention: Filter by calling convention
			has_custom_name: True=user-named only, False=default names (FUN_) only
			regex: Enable regex pattern matching
			sort_by: Sort order: "address"|"name"|"xref_count" (default: "address")
			offset: Pagination offset
			limit: Maximum results to return

		Returns:
			JSON with search results:
			{
			"total": 150,
			"offset": 0,
			"limit": 100,
			"results": [
				{
				"name": "ProcessPlayerSkillCooldowns",
				"address": "0x6fb385a0",
				"xref_count": 5,
				"calling_convention": "__cdecl"
				}
			]
			}

		Example:
			# Find all FUN_ functions with 2+ xrefs, sorted by xref count
			search_functions_enhanced(
				name_pattern="FUN_",
				min_xrefs=2,
				sort_by="xref_count",
				limit=50
			)
		"""
		
		params = {
			"name_pattern": name_pattern,
			"min_xrefs": min_xrefs,
			"max_xrefs": max_xrefs,
			"calling_convention": calling_convention,
			"has_custom_name": has_custom_name,
			"regex": regex,
			"sort_by": sort_by,
			"offset": offset,
			"limit": limit
		}
		# Remove None values
		params = {k: v for k, v in params.items() if v is not None}

		return ghidra_context.http_client.safe_get("search_functions_enhanced", params)

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
	
	@mcp.tool()
	def validate_function_prototype(
		function_address: str,
		prototype: str,
		calling_convention: str = None
	) -> str:
		"""
		Validate a function prototype before applying it (v1.6.0).

		Checks if a prototype string can be successfully parsed and applied
		without actually modifying the function. Reports specific issues.

		Args:
			function_address: Function address in hex format
			prototype: Function prototype to validate (e.g., "int foo(char* bar)")
			calling_convention: Optional calling convention

		Returns:
			JSON with validation results:
			{
			"valid": true|false,
			"errors": ["Can't resolve return type: BOOL"],
			"warnings": ["Parameter name 'new' is a C++ keyword"],
			"parsed_return_type": "int",
			"parsed_parameters": [{"name": "bar", "type": "char*"}]
			}
		"""
		validate_hex_address(function_address)

		params = {
			"function_address": function_address,
			"prototype": prototype
		}
		if calling_convention:
			params["calling_convention"] = calling_convention

		return ghidra_context.http_client.safe_get("validate_function_prototype", params)
