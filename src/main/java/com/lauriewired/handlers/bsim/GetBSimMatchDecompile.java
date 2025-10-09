package com.lauriewired.handlers.bsim;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;

import java.util.Map;

import static com.lauriewired.util.BSimUtils.*;
import static com.lauriewired.util.ParseUtils.*;

/**
 * Handler to get the decompiled code of a matched function from a binary analysis
 * using Binary Simulation (BSim).
 * 
 * Expects POST parameters:
 * - executable_path: The path to the executable being analyzed
 * - function_name: The name of the function to retrieve
 * - function_address: The address of the function to retrieve
 * 
 * Responds with the decompiled code of the matched function as a string.
 */
public final class GetBSimMatchDecompile extends Handler {
	/**
	 * Constructor for the GetBSimMatchDecompile handler
	 * 
	 * @param tool The Ghidra PluginTool instance
	 */
	public GetBSimMatchDecompile(PluginTool tool) {
		super(tool, "/bsim/get_match_decompile");
	}

	/**
	 * Handles the HTTP exchange to retrieve the decompiled code of a matched function.
	 * 
	 * @param exchange The HttpExchange object representing the HTTP request and response
	 * @throws Exception If an error occurs during processing
	 */
	@Override
	public void handle(HttpExchange exchange) throws Exception {
		Map<String, String> params = parsePostParams(exchange);
		String executablePath = params.get("executable_path");
		String functionName = params.get("function_name");
		String functionAddress = params.get("function_address");
		sendResponse(exchange, getBSimMatchDecompile(executablePath, functionName, functionAddress));
	}

	/**
	 * Retrieves the decompiled code of a matched function using BSim.
	 * 
	 * @param executablePath The path to the executable being analyzed
	 * @param functionName The name of the function to retrieve
	 * @param functionAddress The address of the function to retrieve
	 * @return The decompiled code of the matched function as a string
	 */
	private String getBSimMatchDecompile(String executablePath, String functionName, String functionAddress) {
        return getBSimMatchFunction(executablePath, functionName, functionAddress, false, true);
    }
}
