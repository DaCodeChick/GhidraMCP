from mcp.server.fastmcp import FastMCP
from urllib.parse import urljoin
from ..context import ghidra_context

def register_misc_tools(mcp: FastMCP):
	"""Register miscellaneous tools for Ghidra context."""

	@mcp.tool()
	def check_connection() -> str:
		"""
		Check if the Ghidra plugin is running and accessible.
		
		Returns:
			Connection status message
		"""
		try:
			response = ghidra_context.http_client.session.get(urljoin(ghidra_context.server_url, "check_connection"), timeout=ghidra_context.request_timeout)
			if response.ok:
				return response.text.strip()
			else:
				return f"Connection failed: HTTP {response.status_code}"
		except Exception as e:
			return f"Connection failed: {str(e)}"

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
	def get_metadata() -> str:
		"""
		Get metadata about the current program/database.
		
		Returns program information including name, architecture, base address,
		entry points, and other relevant metadata.
		
		Returns:
			JSON string with program metadata
		"""

		return "\n".join(ghidra_context.http_client.safe_get("get_metadata"))
