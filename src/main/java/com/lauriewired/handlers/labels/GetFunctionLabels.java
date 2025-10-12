package com.lauriewired.handlers.labels;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

import java.io.IOException;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to retrieve labels within a function specified by its name.
 */
public final class GetFunctionLabels extends Handler {
	/**
	 * Constructor to create a handler for retrieving labels within a function.
	 * 
	 * @param tool The plugin tool instance.
	 */
	public GetFunctionLabels(PluginTool tool) {
		super(tool, new String[] { "/function_labels" });
	}

	/**
	 * Handle HTTP GET request to retrieve labels within a function specified by its
	 * address.
	 * Query parameters:
	 * - address: The address of the function.
	 * - offset: The number of labels to skip (for pagination).
	 * - limit: The maximum number of labels to return.
	 * 
	 * @param exchange The HTTP exchange object.
	 * @throws IOException If an I/O error occurs.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String name = qparams.get("name");
		int offset = parseIntOrDefault(qparams.get("offset"), 0);
		int limit = parseIntOrDefault(qparams.get("limit"), 20);
		sendResponse(exchange, getFunctionLabels(name, offset, limit));
	}

	/**
	 * Get labels within a function specified by its name.
	 * 
	 * @param functionName The name of the function.
	 * @param offset       The number of labels to skip (for pagination).
	 * @param limit        The maximum number of labels to return.
	 */
	private String getFunctionLabels(String functionName, int offset, int limit) {
		Program program = getCurrentProgram(tool);
		if (program == null) {
			return "No program loaded";
		}

		StringBuilder sb = new StringBuilder();
		SymbolTable symbolTable = program.getSymbolTable();
		FunctionManager functionManager = program.getFunctionManager();

		// Find the function by name
		Function function = null;
		for (Function f : functionManager.getFunctions(true)) {
			if (f.getName().equals(functionName)) {
				function = f;
				break;
			}
		}

		if (function == null) {
			return "Function not found: " + functionName;
		}

		AddressSetView functionBody = function.getBody();
		SymbolIterator symbols = symbolTable.getSymbolIterator();
		int count = 0;
		int skipped = 0;

		while (symbols.hasNext() && count < limit) {
			Symbol symbol = symbols.next();

			// Check if symbol is within the function's address range
			if (symbol.getSymbolType() == SymbolType.LABEL &&
					functionBody.contains(symbol.getAddress())) {

				if (skipped < offset) {
					skipped++;
					continue;
				}

				if (sb.length() > 0) {
					sb.append("\n");
				}
				sb.append("Address: ").append(symbol.getAddress().toString())
						.append(", Name: ").append(symbol.getName())
						.append(", Source: ").append(symbol.getSource().toString());
				count++;
			}
		}

		if (sb.length() == 0) {
			return "No labels found in function: " + functionName;
		}

		return sb.toString();
	}
}
