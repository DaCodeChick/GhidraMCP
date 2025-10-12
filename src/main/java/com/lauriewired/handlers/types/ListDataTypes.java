package com.lauriewired.handlers.types;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import static com.lauriewired.util.GhidraUtils.getCategoryName;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to list data types in the current program with optional filtering and pagination.
 * Supports query parameters:
 * - category: Filter data types by category name (case-insensitive substring match)
 * - offset: Pagination offset (default 0)
 * - limit: Number of results to return (default 100)
 */
public final class ListDataTypes extends Handler {
	/**
	 * Constructor for the ListDataTypes handler.
	 * @param tool The plugin tool instance.
	 */
	public ListDataTypes(PluginTool tool) {
		super(tool, "/list_data_types");
	}

	/**
	 * Handles the HTTP exchange to list data types.
	 * Parses query parameters for filtering and pagination.
	 * @param exchange The HTTP exchange object.
	 * @throws IOException If an I/O error occurs.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String category = qparams.get("category");
		int offset = parseIntOrDefault(qparams.get("offset"), 0);
		int limit = parseIntOrDefault(qparams.get("limit"), 100);
		sendResponse(exchange, listDataTypes(category, offset, limit));
	}

	/**
	 * Lists data types in the current program, applying optional category filtering and pagination.
	 * @param category Optional category filter (case-insensitive substring match).
	 * @param offset Pagination offset.
	 * @param limit Number of results to return.
	 * @return A formatted string listing the data types.
	 */
	private String listDataTypes(String category, int offset, int limit) {
		Program program = getCurrentProgram(tool);
		if (program == null) {
			return "No program loaded";
		}

		DataTypeManager dtm = program.getDataTypeManager();
		List<String> dataTypes = new ArrayList<>();

		// Get all data types from the manager
		Iterator<DataType> allTypes = dtm.getAllDataTypes();
		while (allTypes.hasNext()) {
			DataType dt = allTypes.next();

			// Apply category filter if specified
			if (category != null && !category.isEmpty()) {
				String dtCategory = getCategoryName(dt);
				if (!dtCategory.toLowerCase().contains(category.toLowerCase())) {
					continue;
				}
			}

			// Format: name | category | size | path
			String categoryName = getCategoryName(dt);
			int size = dt.getLength();
			String sizeStr = (size > 0) ? String.valueOf(size) : "variable";

			dataTypes.add(String.format("%s | %s | %s bytes | %s",
					dt.getName(), categoryName, sizeStr, dt.getPathName()));
		}

		// Apply pagination
		String result = paginateList(dataTypes, offset, limit);

		if (result.isEmpty()) {
			return "No data types found" + (category != null ? " for category: " + category : "");
		}

		return result;
	}
}
