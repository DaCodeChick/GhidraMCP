package com.lauriewired.handlers.types;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
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
 * Handler to delete a data type by name.
 * Expects JSON input with "type_name".
 * Returns success or error message.
 */
public final class DeleteDataType extends Handler {
	/**
	 * Constructor for the DeleteDataType handler.
	 * 
	 * @param tool The plugin tool instance.
	 */
	public DeleteDataType(PluginTool tool) {
		super(tool, "/delete_data_type");
	}

	/**
	 * Handles the HTTP exchange for deleting a data type.
	 * @param exchange The HTTP exchange object.
	 * @throws IOException If an I/O error occurs.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, Object> params = parseJsonParams(exchange);
		String typeName = (String) params.get("type_name");
		sendResponse(exchange, deleteDataType(typeName));
	}

	/**
	 * Deletes a data type by name from the current program.
	 * @param typeName The name of the data type to delete.
	 * @return A message indicating success or failure.
	 */
	private String deleteDataType(String typeName) {
        Program program = getCurrentProgram(tool);
        if (program == null) return "No program loaded";
        if (typeName == null || typeName.isEmpty()) return "Type name is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Delete data type");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);

                    if (dataType == null) {
                        result.append("Data type not found: ").append(typeName);
                        return;
                    }

                    // Check if type is in use (simplified check)
                    // Note: Ghidra will prevent deletion if type is in use during remove operation

                    boolean deleted = dtm.remove(dataType, null);
                    if (deleted) {
                        result.append("Data type '").append(typeName).append("' deleted successfully");
                        success.set(true);
                    } else {
                        result.append("Failed to delete data type '").append(typeName).append("'");
                    }

                } catch (Exception e) {
                    result.append("Error deleting data type: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute data type deletion on Swing thread: ").append(e.getMessage());
        }

        return result.toString();
    }
}
