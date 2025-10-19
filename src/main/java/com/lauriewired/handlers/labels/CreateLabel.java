package com.lauriewired.handlers.labels;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;

import java.io.IOException;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.*;

/**
 * Handler to create a label at a specified address in the current program.
 * Expects POST parameters:
 * - address: The address where the label should be created (e.g.,
 * "0x00400000").
 * - name: The name of the label to create (e.g., "myLabel").
 * 
 * Example POST request body:
 * address=0x00400000&name=myLabel
 */
public final class CreateLabel extends Handler {
	/**
	 * Constructs a new CreateLabel handler.
	 *
	 * @param tool The PluginTool instance to interact with Ghidra.
	 */
	public CreateLabel(PluginTool tool) {
		super(tool, "/create_label");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> params = parsePostParams(exchange);
		String address = params.get("address");
		String name = params.get("name");
		String result = createLabel(tool, address, name);
		sendResponse(exchange, result);
	}
}
