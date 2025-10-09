package com.lauriewired.handlers.set;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.Map;
import javax.swing.SwingUtilities;

import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to move a data type to a specified category.
 * Expects POST parameters:
 * - type_name: The name of the data type to move.
 * - category_path: The target category path (e.g., "/MyCategory/SubCategory").
 */
public final class MoveDataTypeToCategory extends Handler {
	/**
	 * Constructor for the new MoveDataTypeToCategory handler.
	 *
	 * @param tool the PluginTool instance to use for program access
	 */
	public MoveDataTypeToCategory(PluginTool tool) {
		super(tool, "/move_data_type_to_category");
	}

	/**
	 * Handles the HTTP exchange to move a data type to a specified category.
	 *
	 * @param exchange the HttpExchange object containing request and response data
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> params = parsePostParams(exchange);
		String typeName = params.get("type_name");
		String categoryPath = params.get("category_path");
		sendResponse(exchange, moveDataTypeToCategory(typeName, categoryPath));
	}

	/**
	 * Moves the specified data type to the given category path.
	 *
	 * @param typeName     the name of the data type to move
	 * @param categoryPath the target category path
	 * @return a message indicating success or failure
	 */
	private String moveDataTypeToCategory(String typeName, String categoryPath) {
        Program program = getCurrentProgram(tool);
        if (program == null) return "No program loaded";
        if (typeName == null || typeName.isEmpty()) return "Type name is required";
        if (categoryPath == null || categoryPath.isEmpty()) return "Category path is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Move data type to category");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);

                    if (dataType == null) {
                        result.append("Data type not found: ").append(typeName);
                        return;
                    }

                    CategoryPath catPath = new CategoryPath(categoryPath);
                    Category category = dtm.createCategory(catPath);
                    
                    // Move the data type
                    dataType.setCategoryPath(catPath);
                    
                    result.append("Successfully moved data type '").append(typeName)
                          .append("' to category '").append(categoryPath).append("'");
                    success.set(true);

                } catch (Exception e) {
                    result.append("Error moving data type: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute data type move on Swing thread: ").append(e.getMessage());
        }

        return result.toString();
    }
}
