package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;

import java.io.IOException;
import java.util.*;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class GetStruct extends Handler {
	public GetStruct(PluginTool tool) {
		super(tool, "/get_struct");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String structName = qparams.get("name");
		String category = qparams.get("category");
		if (structName == null) {
			sendResponse(exchange, "name is required");
			return;
		}
		sendResponse(exchange, getStruct(structName, category));
	}
}
