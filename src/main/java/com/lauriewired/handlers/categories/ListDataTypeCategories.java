package com.lauriewired.handlers.categories;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to list all data type categories in the current program.
 * Supports pagination via 'offset' and 'limit' query parameters.
 */
public final class ListDataTypeCategories extends Handler {
	/**
	 * Constructor for ListDataTypeCategories handler.
	 *
	 * @param tool the PluginTool instance
	 */
	public ListDataTypeCategories(PluginTool tool) {
		super(tool, "/list_data_type_categories");
	}

	/**
	 * Handles the HTTP exchange to list data type categories.
	 * Supports 'offset' and 'limit' query parameters for pagination.
	 *
	 * @param exchange the HttpExchange object
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		int offset = parseIntOrDefault(qparams.get("offset"), 0);
		int limit = parseIntOrDefault(qparams.get("limit"), 100);
		sendResponse(exchange, listDataTypeCategories(offset, limit));
	}

	/**
	 * Lists all data type categories in the current program with pagination.
	 *
	 * @param offset the starting index for pagination
	 * @param limit  the maximum number of categories to return
	 * @return a string representation of the list of data type categories
	 */
	private String listDataTypeCategories(int offset, int limit) {
        Program program = getCurrentProgram(tool);
        if (program == null) return "No program loaded";

        try {
            DataTypeManager dtm = program.getDataTypeManager();
            List<String> categories = new ArrayList<>();
            
            // Get all categories recursively
            addCategoriesRecursively(dtm.getRootCategory(), categories, "");
            
            return paginateList(categories, offset, limit);
        } catch (Exception e) {
            return "Error listing categories: " + e.getMessage();
        }
    }

	/**
	 * Recursively adds category names to the list with their full paths.
	 *
	 * @param category   the current category
	 * @param categories the list to store category names
	 * @param parentPath the path of the parent category
	 */
	private void addCategoriesRecursively(Category category, List<String> categories, String parentPath) {
        for (Category subCategory : category.getCategories()) {
            String fullPath = parentPath.isEmpty() ? 
                            subCategory.getName() : 
                            parentPath + "/" + subCategory.getName();
            categories.add(fullPath);
            addCategoriesRecursively(subCategory, categories, fullPath);
        }
    }
}
