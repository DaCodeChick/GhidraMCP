package com.lauriewired.handlers.xrefs;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to retrieve bulk cross-references to a list of addresses in the current program.
 * Expects a JSON payload with an "addresses" field containing an array of address strings or a
 * comma-separated string of addresses.
 * Responds with a JSON object mapping each address to an array of its cross-references.
 */
public final class GetBulkXrefs extends Handler {
	/**
	 * Constructor for the GetBulkXrefs handler.
	 *
	 * @param tool the Ghidra plugin tool
	 */
	public GetBulkXrefs(PluginTool tool) {
		super(tool, "/get_bulk_xrefs");
	}

	/**
	 * Handles HTTP requests to the /get_bulk_xrefs endpoint.
	 *
	 * @param exchange the HTTP exchange
	 * @throws Exception if an error occurs
	 */
	@Override
	public void handle(HttpExchange exchange) throws Exception {
		Map<String, Object> params = parseJsonParams(exchange);
		Object addressesObj = params.get("addresses");
		String result = getBulkXrefs(addressesObj);
		sendResponse(exchange, result);
	}

	/**
	 * Retrieves cross-references for a list of addresses in the current program.
	 *
	 * @param addressesObj an object representing the list of addresses (array or comma-separated string)
	 * @return a JSON string mapping each address to its cross-references
	 */
	private String getBulkXrefs(Object addressesObj) {
		Program program = getCurrentProgram(tool);
		if (program == null) return "{\"error\": \"No program loaded\"}";

		StringBuilder json = new StringBuilder();
		json.append("{");

		try {
			List<String> addresses = new ArrayList<>();

			// Parse addresses array
			if (addressesObj instanceof List) {
				for (Object addr : (List<?>) addressesObj) {
					if (addr != null) {
						addresses.add(addr.toString());
					}
				}
			} else if (addressesObj instanceof String) {
				// Handle comma-separated string
				String[] parts = ((String) addressesObj).split(",");
				for (String part : parts) {
					addresses.add(part.trim());
				}
			}

			ReferenceManager refMgr = program.getReferenceManager();
			boolean first = true;

			for (String addrStr : addresses) {
				if (!first) json.append(",");
				first = false;

				json.append("\"").append(addrStr).append("\": [");

				try {
					Address addr = program.getAddressFactory().getAddress(addrStr);
					if (addr != null) {
						ReferenceIterator refIter = refMgr.getReferencesTo(addr);
						boolean firstRef = true;

						while (refIter.hasNext()) {
							Reference ref = refIter.next();
							if (!firstRef) json.append(",");
							firstRef = false;

							json.append("{");
							json.append("\"from\": \"").append(ref.getFromAddress().toString()).append("\",");
							json.append("\"type\": \"").append(ref.getReferenceType().getName()).append("\"");
							json.append("}");
						}
					}
				} catch (Exception e) {
					// Address parsing failed, return empty array
				}

				json.append("]");
			}
		} catch (Exception e) {
			return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
		}

		json.append("}");
		return json.toString();
	}
}
