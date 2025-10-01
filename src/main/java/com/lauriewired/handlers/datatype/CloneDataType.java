package com.lauriewired.handlers.datatype;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.swing.SwingUtilities;

import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to clone an existing data type in the current program's data type
 * manager.
 * Expects POST parameters:
 * - source_type: The name of the existing data type to clone.
 * - new_name: The name for the cloned data type.
 * Responds with success or error message.
 */
public final class CloneDataType extends Handler {
	/**
	 * Constructs a new CloneDataType handler.
	 *
	 * @param tool The PluginTool instance to interact with Ghidra.
	 */
	public CloneDataType(PluginTool tool) {
		super(tool, "/clone_data_type");
	}

	/**
	 * Handles the HTTP exchange to clone a data type.
	 * Expects POST parameters:
	 * - source_type: The name of the existing data type to clone.
	 * - new_name: The name for the cloned data type.
	 * 
	 * @param exchange The HttpExchange object representing the HTTP request and
	 *                 response.
	 * @throws IOException If an I/O error occurs.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, Object> params = parseJsonParams(exchange);
        String sourceType = (String) params.get("source_type");
        String newName = (String) params.get("new_name");
		sendResponse(exchange, cloneDataType(sourceType, newName));
	}

	/**
	 * Clones a data type in the current program's data type manager.
	 *
	 * @param sourceType The name of the existing data type to clone.
	 * @param newName    The name for the cloned data type.
	 * @return A message indicating success or failure.
	 */
	private String cloneDataType(String sourceType, String newName) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";
		if (sourceType == null || sourceType.isEmpty())
			return "Source type is required";
		if (newName == null || newName.isEmpty())
			return "New name is required";

		AtomicBoolean success = new AtomicBoolean(false);
		StringBuilder result = new StringBuilder();

		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Clone data type");
				try {
					DataTypeManager dtm = program.getDataTypeManager();
					DataType source = findDataTypeByNameInAllCategories(dtm, sourceType);

					if (source == null) {
						result.append("Source type not found: ").append(sourceType);
						return;
					}

					DataType cloned = source.clone(dtm);
					cloned.setName(newName);

					dtm.addDataType(cloned, DataTypeConflictHandler.REPLACE_HANDLER);
					result.append("Data type '").append(sourceType).append("' cloned as '").append(newName).append("'");
					success.set(true);
				} catch (Exception e) {
					result.append("Error cloning data type: ").append(e.getMessage());
				} finally {
					program.endTransaction(tx, success.get());
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			result.append("Failed to execute data type cloning on Swing thread: ").append(e.getMessage());
		}

		return result.toString();
	}
}
