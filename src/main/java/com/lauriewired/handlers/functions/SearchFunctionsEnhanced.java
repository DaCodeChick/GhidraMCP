package com.lauriewired.handlers.functions;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ReferenceManager;

import java.io.IOException;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import javax.swing.*;

import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class SearchFunctionsEnhanced extends Handler {
	/**
	 * Constructor for the SearchFunctionsEnhanced handler.
	 * 
	 * @param tool The plugin tool instance.
	 */
	public SearchFunctionsEnhanced(PluginTool tool) {
		super(tool, "/search_functions_enhanced");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String namePattern = qparams.get("name_pattern");
		Integer minXrefs = qparams.get("min_xrefs") != null ? Integer.parseInt(qparams.get("min_xrefs")) : null;
		Integer maxXrefs = qparams.get("max_xrefs") != null ? Integer.parseInt(qparams.get("max_xrefs")) : null;
		String callingConvention = qparams.get("calling_convention");
		Boolean hasCustomName = qparams.get("has_custom_name") != null ? Boolean.parseBoolean(qparams.get("has_custom_name")) : null;
		boolean regex = Boolean.parseBoolean(qparams.getOrDefault("regex", "false"));
		String sortBy = qparams.getOrDefault("sort_by", "address");
		int offset = parseIntOrDefault(qparams.get("offset"), 0);
		int limit = parseIntOrDefault(qparams.get("limit"), 100);

		String result = searchFunctionsEnhanced(namePattern, minXrefs, maxXrefs, callingConvention,
			hasCustomName, regex, sortBy, offset, limit);
		sendResponse(exchange, result);
	}

	/**
	 * Searches functions in the current program based on various criteria.
	 * 
	 * @param namePattern The name pattern to search for.
	 * @param minXrefs Minimum number of cross-references.
	 * @param maxXrefs Maximum number of cross-references.
	 * @param callingConvention The calling convention to filter by.
	 * @param hasCustomName Whether to filter by custom names.
	 * @param regex Whether the name pattern is a regex.
	 * @param sortBy The field to sort results by.
	 * @param offset The result offset for pagination.
	 * @param limit The maximum number of results to return.
	 * @return A JSON string containing the search results.
	 */
	private String searchFunctionsEnhanced(String namePattern, Integer minXrefs, Integer maxXrefs,
										  String callingConvention, Boolean hasCustomName, boolean regex,
										  String sortBy, int offset, int limit) {
		Program program = getCurrentProgram();
		if (program == null) {
			return "{\"error\": \"No program loaded\"}";
		}

		final StringBuilder result = new StringBuilder();
		final AtomicReference<String> errorMsg = new AtomicReference<>(null);

		try {
			SwingUtilities.invokeAndWait(() -> {
				try {
					List<Map<String, Object>> matches = new ArrayList<>();
					Pattern pattern = null;
					if (regex && namePattern != null) {
						try {
							pattern = Pattern.compile(namePattern);
						} catch (Exception e) {
							result.append("{\"error\": \"Invalid regex pattern: ").append(e.getMessage()).append("\"}");
							return;
						}
					}

					FunctionManager funcMgr = program.getFunctionManager();
					ReferenceManager refMgr = program.getReferenceManager();

					for (Function func : funcMgr.getFunctions(true)) {
						// Filter by name pattern
						if (namePattern != null && !namePattern.isEmpty()) {
							if (regex) {
								if (!pattern.matcher(func.getName()).find()) {
									continue;
								}
							} else {
								if (!func.getName().contains(namePattern)) {
									continue;
								}
							}
						}

						// Filter by custom name
						if (hasCustomName != null) {
							boolean isCustom = !func.getName().startsWith("FUN_");
							if (hasCustomName != isCustom) {
								continue;
							}
						}

						// Get xref count for filtering and sorting
						int xrefCount = func.getSymbol().getReferenceCount();

						// Filter by xref count
						if (minXrefs != null && xrefCount < minXrefs) {
							continue;
						}
						if (maxXrefs != null && xrefCount > maxXrefs) {
							continue;
						}

						// Create match entry
						Map<String, Object> match = new HashMap<>();
						match.put("name", func.getName());
						match.put("address", func.getEntryPoint().toString());
						match.put("xref_count", xrefCount);
						matches.add(match);
					}

					// Sort results
					if ("name".equals(sortBy)) {
						matches.sort((a, b) -> ((String)a.get("name")).compareTo((String)b.get("name")));
					} else if ("xref_count".equals(sortBy)) {
						matches.sort((a, b) -> Integer.compare((Integer)b.get("xref_count"), (Integer)a.get("xref_count")));
					} else {
						// Default: sort by address
						matches.sort((a, b) -> ((String)a.get("address")).compareTo((String)b.get("address")));
					}

					// Apply pagination
					int total = matches.size();
					int endIndex = Math.min(offset + limit, total);
					List<Map<String, Object>> page = matches.subList(Math.min(offset, total), endIndex);

					// Build JSON result
					result.append("{\"total\": ").append(total).append(", ");
					result.append("\"offset\": ").append(offset).append(", ");
					result.append("\"limit\": ").append(limit).append(", ");
					result.append("\"results\": [");

					for (int i = 0; i < page.size(); i++) {
						if (i > 0) result.append(", ");
						Map<String, Object> match = page.get(i);
						result.append("{\"name\": \"").append(match.get("name")).append("\", ");
						result.append("\"address\": \"").append(match.get("address")).append("\", ");
						result.append("\"xref_count\": ").append(match.get("xref_count")).append("}");
					}

					result.append("]}");

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
