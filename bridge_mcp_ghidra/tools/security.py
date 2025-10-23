from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context

def register_security_tools(mcp: FastMCP):
	"""Register security tools in the MCP server."""

	@mcp.tool()
	def extract_iocs() -> dict:
		"""
		Extract Indicators of Compromise (IOCs) from the binary.

		Functionality:
		- Extracts IPv4 addresses (filters out 0.0.0.0 and 255.255.255.255)
		- Finds HTTP/HTTPS URLs
		- Identifies Windows file paths (C:\...)
		- Detects registry keys (HKEY_*, HKLM, HKCU, etc.)
		- Scans up to 10,000 strings for performance
		- Returns up to 100 results per category

		Returns:
			Dictionary of IOCs organized by type:
			{
				"ips": ["192.168.1.1", ...],
				"urls": ["http://example.com", ...],
				"file_paths": ["C:\\Windows\\System32\\...", ...],
				"registry_keys": ["HKLM\\Software\\...", ...]
			}

		Example:
			iocs = extract_iocs()
			print(f"Found {len(iocs['ips'])} IP addresses")
		"""
		return ghidra_context.http_client.safe_get("extract_iocs")
