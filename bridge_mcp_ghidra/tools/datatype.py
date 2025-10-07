from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context

def register_datatype_tools(mcp: FastMCP):
	"""Register data type tools to MCP instance."""

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
	def clone_data_type(source_type: str, new_name: str) -> str:
		"""
		Clone/copy an existing data type with a new name.
		
		Args:
			source_type: Name of the source data type to clone
			new_name: Name for the cloned data type
			
		Returns:
			Success/failure message with cloning details
		"""
		return ghidra_context.http_client.safe_post("clone_data_type", {"source_type": source_type, "new_name": new_name})

	@mcp.tool()
	def export_data_types(format: str = "c", category: str = None) -> str:
		"""
		Export data types in various formats.
		
		Args:
			format: Export format ("c", "json", "summary") - default: "c"
			category: Optional category filter for data types
			
		Returns:
			Exported data types in the specified format
		"""
		params = {"format": format}
		if category:
			params["category"] = category
		return ghidra_context.http_client.safe_get("export_data_types", params)

	@mcp.tool()
	def import_data_types(source: str, format: str = "c") -> str:
		"""
		Import data types from various sources (placeholder for future implementation).
		
		Args:
			source: Source data containing type definitions
			format: Format of the source data ("c", "json") - default: "c"
			
		Returns:
			Import results and status
		"""
		return ghidra_context.http_client.safe_post("import_data_types", {"source": source, "format": format})

	@mcp.tool()
	def validate_data_type(address: str, type_name: str) -> str:
		"""
		Validate if a data type can be properly applied at a given address.
		
		Args:
			address: Target address in hex format (e.g., "0x1400010a0")
			type_name: Name of the data type to validate
			
		Returns:
			Validation results including memory availability, alignment, and conflicts
		"""
		return ghidra_context.http_client.safe_get("validate_data_type", {"address": address, "type_name": type_name})
