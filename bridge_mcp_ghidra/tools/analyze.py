from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context, GhidraValidationError

def register_analyze_tools(mcp: FastMCP):
	"""Register analysis tools for Ghidra."""

	def analyze_api_call_chains() -> dict:
		"""
		Identify and visualize suspicious Windows API call sequences used by malware.
		Detects patterns like process injection, persistence, and anti-analysis techniques.
		
		Returns:
			Dictionary of detected API call patterns with threat assessment
		"""
		return ghidra_context.http_client.safe_get("analyze_api_call_chains")

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
	def analyze_data_types(address: str, depth: int = 1) -> list:
		"""
		Analyze data types at a given address with specified depth.
		
		Args:
			address: Target address in hex format (e.g., "0x1400010a0")
			depth: Analysis depth for following pointers and references (default: 1)
			
		Returns:
			Detailed analysis of data types at the specified address
		"""
		return ghidra_context.http_client.safe_get("analyze_data_types", {"address": address, "depth": depth})

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
		if not ghidra_context.validate_function_name(function_name):
			raise GhidraValidationError(f"Invalid function name: {function_name}")

		return ghidra_context.http_client.safe_get("analyze_function_complexity", {"function_name": function_name})
	