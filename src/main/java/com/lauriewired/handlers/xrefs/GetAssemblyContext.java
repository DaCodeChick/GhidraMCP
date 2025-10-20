package com.lauriewired.handlers.xrefs;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class GetAssemblyContext extends Handler {
	/**
	 * Constructs the handler with the specified plugin tool.
	 * 
	 * @param tool the plugin tool instance
	 */
	public GetAssemblyContext(PluginTool tool) {
		super(tool, "/get_assembly_context");
	}

	@Override
	public void handle(HttpExchange exchange) throws Exception {
		Map<String, Object> params = parseJsonParams(exchange);
		Object xrefSourcesObj = params.get("xref_sources");
		int contextInstructions = parseIntOrDefault(String.valueOf(params.get("context_instructions")), 5);
		Object includePatternsObj = params.get("include_patterns");

		String result = getAssemblyContext(xrefSourcesObj, contextInstructions, includePatternsObj);
		sendResponse(exchange, result);
	}

	/**
	 * Retrieves the assembly context for the specified cross-reference sources.
	 * 
	 * @param xrefSourcesObj the cross-reference source addresses
	 * @param contextInstructions the number of context instructions to include
	 * @param includePatternsObj patterns to include in the analysis
	 * @return a JSON string representing the assembly context
	 */
	private String getAssemblyContext(Object xrefSourcesObj, int contextInstructions,
									  Object includePatternsObj) {
		Program program = getCurrentProgram(tool);
		if (program == null) return "{\"error\": \"No program loaded\"}";

		StringBuilder json = new StringBuilder();
		json.append("{");

		try {
			List<String> xrefSources = new ArrayList<>();

			if (xrefSourcesObj instanceof List) {
				for (Object addr : (List<?>) xrefSourcesObj) {
					if (addr != null) {
						xrefSources.add(addr.toString());
					}
				}
			}

			Listing listing = program.getListing();
			boolean first = true;

			for (String addrStr : xrefSources) {
				if (!first) json.append(",");
				first = false;

				json.append("\"").append(addrStr).append("\": {");

				try {
					Address addr = program.getAddressFactory().getAddress(addrStr);
					if (addr != null) {
						json.append("\"address\": \"").append(addrStr).append("\",");
						json.append("\"context\": \"Placeholder assembly context\",");
						json.append("\"patterns_detected\": [\"data_access\"]");
					}
				} catch (Exception e) {
					json.append("\"error\": \"").append(escapeJson(e.getMessage())).append("\"");
				}

				json.append("}");
			}
		} catch (Exception e) {
			return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
		}

		json.append("}");
		return json.toString();
	}
}
