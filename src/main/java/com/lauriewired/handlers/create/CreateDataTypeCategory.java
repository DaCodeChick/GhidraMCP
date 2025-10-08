package com.lauriewired.handlers.create;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.util.Map;

import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to create a new data type category in the current program's data type manager.
 * Expects a POST request with a 'category_path' parameter specifying the path of the new category.
 */
public final class CreateDataTypeCategory extends Handler {
	/**
	 * Constructs a new CreateDataTypeCategory handler.
	 *
	 * @param tool The PluginTool instance to interact with Ghidra.
	 */
	public CreateDataTypeCategory(PluginTool tool) {
		super(tool, "/create_data_type_category");
	}

	/**
	 * Handles the HTTP request to create a new data type category.
	 *
	 * @param exchange The HTTP exchange containing the request and response.
	 * @throws IOException If an I/O error occurs.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> params = parsePostParams(exchange);
		String categoryPath = params.get("category_path");
		sendResponse(exchange, createDataTypeCategory(categoryPath));
	}

	/**
	 * Creates a new data type category in the current program's data type manager.
	 *
	 * @param categoryPath The path of the new category to create.
	 * @return A message indicating success or failure.
	 */
	private String createDataTypeCategory(String categoryPath) {
        Program program = getCurrentProgram(tool);
        if (program == null) return "No program loaded";
        if (categoryPath == null || categoryPath.isEmpty()) return "Category path is required";

        try {
            DataTypeManager dtm = program.getDataTypeManager();
            CategoryPath catPath = new CategoryPath(categoryPath);
            Category category = dtm.createCategory(catPath);
            
            return "Successfully created category: " + category.getCategoryPathName();
        } catch (Exception e) {
            return "Error creating category: " + e.getMessage();
        }
    }
}
