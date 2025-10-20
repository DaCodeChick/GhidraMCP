import argparse
import logging
from mcp import FastMCP
from .client import GhidraHTTPClient
from .context import DEFAULT_GHIDRA_SERVER

def main():
	parser = argparse.ArgumentParser(description="MCP server for Ghidra")
	parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
						help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
	parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
						help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
	parser.add_argument("--mcp-port", type=int,
						help="Port to run MCP server on (only used for sse), default: 8089")
	parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
						help="Transport protocol for MCP, default: stdio")
	args = parser.parse_args()
	
	# Use the global variable to ensure it's properly updated
	global ghidra_server_url
	if args.ghidra_server:
		ghidra_server_url = args.ghidra_server

	client = GhidraHTTPClient(ghidra_server_url)
	mcp = FastMCP(ghidra_server_url)
	
	if args.transport == "sse":
		try:
			# Configure MCP settings
			mcp.settings.log_level = "INFO"
			if args.mcp_host:
				mcp.settings.host = args.mcp_host
			else:
				mcp.settings.host = "127.0.0.1"

			if args.mcp_port:
				mcp.settings.port = args.mcp_port
			else:
				mcp.settings.port = 8089

			client.logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
			client.logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
			client.logger.info(f"Using transport: {args.transport}")

			mcp.run(transport="sse")
		except KeyboardInterrupt:
			client.logger.info("Server stopped by user")
	else:
		mcp.run()


if __name__ == "__main__":
	main()
