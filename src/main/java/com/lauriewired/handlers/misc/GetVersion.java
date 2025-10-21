package com.lauriewired.handlers.misc;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;

import java.io.IOException;

import static com.lauriewired.util.ParseUtils.*;

public final class GetVersion extends Handler {
	/**
	 * Constructor for the GetVersion handler.
	 * 
	 * @param tool The PluginTool instance to use.
	 */
	public GetVersion(PluginTool tool) {
		super(tool, "/get_version");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		sendResponse(exchange, getVersion());
	}

	/**
	 * Retrieves the version information of the plugin and environment.
	 * 
	 * @return A JSON string containing version details.
	 */
	private String getVersion() {
		StringBuilder version = new StringBuilder();
		version.append("{\n");
		version.append("  \"plugin_version\": \"4.1\",\n");
		version.append("  \"plugin_name\": \"GhidraMCP\",\n");
		version.append("  \"ghidra_version\": \"11.4.2\",\n");
		version.append("  \"java_version\": \"").append(System.getProperty("java.version")).append("\",\n");
		version.append("}");
		return version.toString();
	}
}
