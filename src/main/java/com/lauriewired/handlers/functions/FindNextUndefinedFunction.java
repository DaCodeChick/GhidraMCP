package com.lauriewired.handlers.functions;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.Map;
import javax.swing.*;

import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class FindNextUndefinedFunction extends Handler {
	/**
	 * Constructor for the FindNextUndefinedFunction handler.
	 * 
	 * @param tool The plugin tool instance.
	 */
	public FindNextUndefinedFunction(PluginTool tool) {
		super(tool, "/find_next_undefined_function");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String startAddress = qparams.get("start_address");
		String criteria = qparams.get("criteria");
		String pattern = qparams.get("pattern");
		String direction = qparams.get("direction");

		String result = findNextUndefinedFunction(startAddress, criteria, pattern, direction);
		sendResponse(exchange, result);
	}

	/**
	 * Finds the next undefined function in the current program based on the given parameters.
	 * 
	 * @param startAddress The address to start the search from.
	 * @param criteria The search criteria (currently unused).
	 * @param pattern The pattern to match function names against.
	 * @param direction The search direction ("ascending" or "descending").
	 * @return A JSON string with the search result.
	 */
	@SuppressWarnings("deprecation")
	private String findNextUndefinedFunction(String startAddress, String criteria,
											String pattern, String direction) {
		Program program = getCurrentProgram(tool);
		if (program == null) {
			return "{\"error\": \"No program loaded\"}";
		}

		final StringBuilder result = new StringBuilder();
		final AtomicReference<String> errorMsg = new AtomicReference<>(null);

		try {
			SwingUtilities.invokeAndWait(() -> {
				try {
					FunctionManager funcMgr = program.getFunctionManager();
					Address start = startAddress != null ?
						program.getAddressFactory().getAddress(startAddress) :
						program.getMinAddress();

					String searchPattern = pattern != null ? pattern : "FUN_";
					boolean ascending = !"descending".equals(direction);

					FunctionIterator iter = ascending ?
						funcMgr.getFunctions(start, true) :
						funcMgr.getFunctions(start, false);

					Function found = null;
					while (iter.hasNext()) {
						Function func = iter.next();
						if (func.getName().startsWith(searchPattern)) {
							found = func;
							break;
						}
					}

					if (found != null) {
						result.append("{");
						result.append("\"found\": true, ");
						result.append("\"function_name\": \"").append(found.getName()).append("\", ");
						result.append("\"function_address\": \"").append(found.getEntryPoint().toString()).append("\", ");
						result.append("\"xref_count\": ").append(found.getSymbol().getReferenceCount());
						result.append("}");
					} else {
						result.append("{\"found\": false}");
					}
				} catch (Exception e) {
					errorMsg.set(e.getMessage());
				}
			});

			if (errorMsg.get() != null) {
				return "{\"error\": \"" + errorMsg.get().replace("\"", "\\\"") + "\"}";
			}
		} catch (Exception e) {
			return "{\"error\": \"" + e.getMessage().replace("\"", "\\\"") + "\"}";
		}

		return result.toString();
	}
}
