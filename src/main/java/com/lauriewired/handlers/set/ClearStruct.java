package com.lauriewired.handlers.set;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;

import java.io.IOException;
import java.util.*;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class ClearStruct extends Handler {
	public ClearStruct(PluginTool tool) {
		super("/clear_struct");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> params = parsePostParams(exchange);
		String structName = params.get("struct_name");
		String category = params.get("category");
		if (structName == null) {
			sendResponse(exchange, "struct_name is required");
			return;
		}
		sendResponse(exchange, clearStruct(structName, category));
	}
}
