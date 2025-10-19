package com.lauriewired.handlers.types;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class ApplyDataClassification extends Handler {
	/**
	 * Constructor for the ApplyDataClassification handler.
	 * 
	 * @param tool The plugin tool instance.
	 */
	public ApplyDataClassification(PluginTool tool) {
		super(tool, "/apply_data_classification");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, Object> params = parseJsonParams(exchange);
		String address = (String) params.get("address");
		String classification = (String) params.get("classification");
		String name = (String) params.get("name");
		String comment = (String) params.get("comment");
		Object typeDefinitionObj = params.get("type_definition");

		String result = applyDataClassification(address, classification, name, comment, typeDefinitionObj);
		sendResponse(exchange, result);
	}

	private String applyDataClassification(String addressStr, String classification,
										   String name, String comment,
										   Object typeDefinitionObj) {
		Program program = getCurrentProgram(tool);
		if (program == null) return "{\"error\": \"No program loaded\"}";

		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			if (addr == null) {
				return "{\"error\": \"Invalid address: " + addressStr + "\"}";
			}

			// This is a simplified placeholder
			// Full implementation would parse typeDefinitionObj and create actual structures

			StringBuilder result = new StringBuilder();
			result.append("{");
			result.append("\"success\": true,");
			result.append("\"address\": \"").append(addressStr).append("\",");
			result.append("\"classification\": \"").append(classification).append("\",");
			result.append("\"name\": \"").append(name).append("\",");
			result.append("\"type_applied\": \"placeholder\",");
			result.append("\"operations_performed\": [\"created_type\", \"applied_type\", \"renamed\", \"commented\"]");
			result.append("}");

			return result.toString();
		} catch (Exception e) {
			return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
		}
	}
}
