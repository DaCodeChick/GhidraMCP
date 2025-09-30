package com.lauriewired.handlers.search;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to search data types in the current program.
 */
public final class SearchDataTypes extends Handler {
	/**
	 * Constructor for the SearchDataTypes handler.
	 * 
	 * @param tool The PluginTool instance to use.
	 */
	public SearchDataTypes(PluginTool tool) {
		super(tool, "/search_data_types");
	}

	/**
	 * Handles HTTP requests to search data types.
	 * Expects query parameters:
	 * - pattern: The search pattern (required).
	 * - offset: The starting index for pagination (default 0).
	 * - limit: The maximum number of results to return (default 100).
	 * Returns a list of matching data types with their names, sizes, and paths.
	 *
	 * @param exchange The HttpExchange object representing the HTTP request and
	 *                 response.
	 * @throws IOException If an I/O error occurs.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String pattern = qparams.get("pattern");
		int offset = parseIntOrDefault(qparams.get("offset"), 0);
		int limit = parseIntOrDefault(qparams.get("limit"), 100);
		sendResponse(exchange, searchDataTypes(pattern, offset, limit));
	}

	/**
	 * Searches data types in the current program matching the given pattern.
	 *
	 * @param pattern The search pattern.
	 * @param offset  The starting index for pagination.
	 * @param limit   The maximum number of results to return.
	 * @return A formatted string of matching data types or an error message.
	 */
	private String searchDataTypes(String pattern, int offset, int limit) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";
		if (pattern == null || pattern.isEmpty())
			return "Search pattern is required";

		List<String> matches = new ArrayList<>();
		DataTypeManager dtm = program.getDataTypeManager();

		Iterator<DataType> allTypes = dtm.getAllDataTypes();
		while (allTypes.hasNext()) {
			DataType dt = allTypes.next();
			String name = dt.getName();
			String path = dt.getPathName();

			if (name.toLowerCase().contains(pattern.toLowerCase()) ||
					path.toLowerCase().contains(pattern.toLowerCase())) {
				matches.add(String.format("%s | Size: %d | Path: %s",
						name, dt.getLength(), path));
			}
		}

		Collections.sort(matches);
		return paginateList(matches, offset, limit);
	}
}
