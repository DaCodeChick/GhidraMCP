package com.lauriewired.handlers.globals;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to list global variables in the current program.
 * Supports pagination and filtering.
 * Query parameters:
 * - offset: starting index (default 0)
 * - limit: number of items to return (default 100)
 * - filter: substring to filter variable names (optional)
 * Example: /list_globals?offset=0&limit=50&filter=var
 * Returns a paginated list of global variables with their addresses and types.
 */
public final class ListGlobals extends Handler {
	/**
	 * Constructor for ListGlobals handler.
	 * 
	 * @param tool the PluginTool instance to interact with Ghidra
	 */
	public ListGlobals(PluginTool tool) {
		super(tool, "/list_globals");
	}

	/**
	 * Handles the HTTP exchange to list global variables.
	 * Parses query parameters for pagination and filtering.
	 * @param exchange the HttpExchange object representing the HTTP request and response
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		int offset = parseIntOrDefault(qparams.get("offset"), 0);
		int limit = parseIntOrDefault(qparams.get("limit"), 100);
		String filter = qparams.get("filter");
		sendResponse(exchange, listGlobals(offset, limit, filter));
	}

	/**
	 * Lists global variables in the current program with pagination and filtering.
	 * 
	 * @param offset starting index for pagination
	 * @param limit number of items to return
	 * @param filter substring to filter variable names (optional)
	 * @return a formatted string listing global variables
	 */
	private String listGlobals(int offset, int limit, String filter) {
		Program program = getCurrentProgram(tool);
		if (program == null) {
			return "No program loaded";
		}

		List<String> globals = new ArrayList<>();
		SymbolTable symbolTable = program.getSymbolTable();

		// Get all symbols in global namespace
		Namespace globalNamespace = program.getGlobalNamespace();
		SymbolIterator symbols = symbolTable.getSymbols(globalNamespace);

		while (symbols.hasNext()) {
			Symbol symbol = symbols.next();

			// Skip function symbols (they have their own listing)
			if (symbol.getSymbolType() == SymbolType.FUNCTION) {
				continue;
			}

			String symbolInfo = formatGlobalSymbol(symbol);

			// Apply filter if provided
			if (filter == null || filter.isEmpty() ||
					symbolInfo.toLowerCase().contains(filter.toLowerCase())) {
				globals.add(symbolInfo);
			}
		}

		return paginateList(globals, offset, limit);
	}

	/**
	 * Formats a global symbol into a readable string.
	 * 
	 * @param symbol the Symbol object to format
	 * @return a formatted string with symbol details
	 */
	private String formatGlobalSymbol(Symbol symbol) {
		StringBuilder info = new StringBuilder();
		info.append(symbol.getName());
		info.append(" @ ").append(symbol.getAddress());
		info.append(" [").append(symbol.getSymbolType()).append("]");

		// Add data type information if available
		if (symbol.getObject() instanceof Data) {
			Data data = (Data) symbol.getObject();
			DataType dt = data.getDataType();
			if (dt != null) {
				info.append(" (").append(dt.getName()).append(")");
			}
		}

		return info.toString();
	}
}
