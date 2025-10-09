package com.lauriewired.handlers.bsim;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;

import java.util.Map;

import static com.lauriewired.util.BSimUtils.*;
import static com.lauriewired.util.ParseUtils.*;

/**
 * Handler to get the disassembly of a function from a BSim match
 */
public final class GetBSimMatchDisassembly extends Handler {
	/**
	 * Constructor for the GetBSimMatchDisassembly handler
	 * 
	 * @param tool The Ghidra PluginTool instance
	 */
	public GetBSimMatchDisassembly(PluginTool tool) {
		super(tool, "/bsim/get_match_disassembly");
	}

	/**
	 * Handles the HTTP exchange to get the disassembly of a function from a BSim match
	 * 
	 * Expects POST parameters:
	 * - executable_path: The path to the executable
	 * - function_name: The name of the function
	 * - function_address: The address of the function
	 * 
	 * Responds with the disassembly of the specified function
	 */
	@Override
	public void handle(HttpExchange exchange) throws Exception {
		Map<String, String> params = parsePostParams(exchange);
		String executablePath = params.get("executable_path");
		String functionName = params.get("function_name");
		String functionAddress = params.get("function_address");
		sendResponse(exchange, getBSimMatchDisassembly(executablePath, functionName, functionAddress));
	}

	/**
	 * Retrieves the disassembly of a function from a BSim match
	 * 
	 * @param executablePath The path to the executable
	 * @param functionName The name of the function
	 * @param functionAddress The address of the function
	 * @return The disassembly of the specified function
	 */
	private String getBSimMatchDisassembly(String executablePath, String functionName, String functionAddress) {
        return getBSimMatchFunction(executablePath, functionName, functionAddress, true, false);
    }
}
