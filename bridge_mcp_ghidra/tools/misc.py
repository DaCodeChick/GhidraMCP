from mcp.server.fastmcp import FastMCP
import requests
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
			response = requests.get(urljoin(ghidra_context.server_url, "check_connection"), timeout=ghidra_context.request_timeout)
			if response.ok:
				return response.text.strip()
			else:
				return f"Connection failed: HTTP {response.status_code}"
		except Exception as e:
			return f"Connection failed: {str(e)}"
