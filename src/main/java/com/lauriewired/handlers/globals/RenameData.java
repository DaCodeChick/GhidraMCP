package com.lauriewired.handlers.globals;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;

import java.io.IOException;
import java.util.Map;

import static com.lauriewired.util.GhidraUtils.renameDataAtAddress;
import static com.lauriewired.util.ParseUtils.parsePostParams;
import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for renaming data at a specific address in the current program.
 * Expects POST parameters: "address" (the address of the data) and "newName"
 * (the new name).
 */
public final class RenameData extends Handler {
	/**
	 * Constructs a new RenameData handler.
	 *
	 * @param tool the PluginTool instance to use for program access
	 */
	public RenameData(PluginTool tool) {
		super(tool, "/rename_data");
	}

	/**
	 * Handles the HTTP request to rename data at a specified address.
	 * Expects POST parameters "address" and "newName".
	 *
	 * @param exchange the HttpExchange object containing the request
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> params = parsePostParams(exchange);
		renameDataAtAddress(tool, params.get("address"), params.get("newName"));
		sendResponse(exchange, "Data renamed successfully");
	}
}
