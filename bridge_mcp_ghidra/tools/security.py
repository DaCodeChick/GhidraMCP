from mcp.server.fastmcp import FastMCP
from ..context import ghidra_context

def register_security_tools(mcp: FastMCP):
	"""Register security analysis tools in the MCP server."""

	@mcp.tool()
	def analyze_api_call_chains() -> dict:
		"""
		Identify and visualize suspicious Windows API call sequences used by malware.
		Detects patterns like process injection, persistence, and anti-analysis techniques.
		
		Returns:
			Dictionary of detected API call patterns with threat assessment
		"""

		return ghidra_context.http_client.safe_get("analyze_api_call_chains")

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
	def find_anti_analysis_techniques() -> list:
		"""
		Detect anti-analysis, anti-debugging, and evasion techniques.
		Looks for common obfuscation and evasion patterns used by malware.
		
		Returns:
			List of detected evasion techniques with locations and descriptions
		"""
		return ghidra_context.http_client.safe_get("find_anti_analysis_techniques")
