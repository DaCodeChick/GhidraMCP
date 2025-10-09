package com.lauriewired.handlers.bsim;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;

import static com.lauriewired.util.BSimUtils.disconnectBSimDatabase;
import static com.lauriewired.util.ParseUtils.sendResponse;

/**
 * Handler to disconnect from the BSim database
 */
public final class DisconnectBSimDatabase extends Handler {
	/**
	 * Constructor for the DisconnectBSimDatabase handler
	 * 
	 * @param tool The Ghidra PluginTool instance
	 */
	public DisconnectBSimDatabase(PluginTool tool) {
		super(tool, "/bsim/disconnect");
	}

	/**
	 * Handles the HTTP request to disconnect from the BSim database
	 *
	 * @param exchange The HTTP exchange object
	 * @throws Exception If an error occurs while handling the request
	 */
	@Override
	public void handle(HttpExchange exchange) throws Exception {
		sendResponse(exchange, disconnectBSimDatabase());
	}
}
