package com.lauriewired.handlers.act;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

import java.io.IOException;

import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to check if the GhidraMCP plugin is running and if a program is loaded.
 * Responds with a message indicating the connection status.
 */
public final class CheckConnection extends Handler {
	/**
	 * Constructs a new CheckConnection handler.
	 *
	 * @param tool the plugin tool instance
	 */
	public CheckConnection(PluginTool tool) {
		super(tool, "/check_connection");
	}

	/**
	 * Handles the HTTP exchange by checking the connection status and sending the response.
	 * @param exchange the HTTP exchange object
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		sendResponse(exchange, checkConnection());
	}

	/**
	 * Checks the connection status and returns a message.
	 * @return a string message indicating the connection status
	 */
	private String checkConnection() {
		Program program = getCurrentProgram();
		if (program == null) {
			return "Connected: GhidraMCP plugin running, but no program loaded";
		}
		return "Connected: GhidraMCP plugin running with program '" + program.getName() + "'";
	}
}
