package com.lauriewired.handlers.functions;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static com.lauriewired.GhidraMCPPlugin.*;
import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to decompile a function by its name.
 * Expects the function name in the request body.
 */
public final class DecompileFunctionByName extends Handler {
	/**
	 * Constructs a new DecompileFunctionByName handler.
	 * 
	 * @param tool The Ghidra plugin tool instance.
	 */
	public DecompileFunctionByName(PluginTool tool) {
		super(tool, "/decompile");
	}

	/**
	 * Handles the HTTP request to decompile a function by its name.
	 * Reads the function name from the request body and returns the decompiled C
	 * pseudocode.
	 * 
	 * @param exchange The HTTP exchange containing the request and response.
	 * @throws IOException If an I/O error occurs during handling.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
		sendResponse(exchange, generateResponse(name));
	}

	/**
	 * Generates the decompiled C pseudocode for the function with the specified
	 * name.
	 * 
	 * @param name The name of the function to decompile.
	 * @return The decompiled C pseudocode or an error message if the function is
	 *         not found.
	 */
	private String generateResponse(String name) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";
		DecompInterface decomp = new DecompInterface();
		DecompileOptions options = new DecompileOptions();
		options.setRespectReadOnly(true);
		decomp.setOptions(options);
		decomp.openProgram(program);
		for (Function func : program.getFunctionManager().getFunctions(true)) {
			if (func.getName().equals(name)) {
				DecompileResults result = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, new ConsoleTaskMonitor());
				if (result != null && result.decompileCompleted()) {
					return result.getDecompiledFunction().getC();
				} else {
					return "Decompilation failed";
				}
			}
		}
		return "Function not found";
	}
}
