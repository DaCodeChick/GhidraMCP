package com.lauriewired.handlers.set;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
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
 * Handler to remove a field from a structure in the current Ghidra program.
 * Expects JSON parameters:
 * {
 *   "base_type": "struct_name",
 *   "name": "field_name",
 *   "length": 1 (optional, default is 1)
 * }
 * 
 * Responds with a success or error message.
 */
public final class RemoveStructField extends Handler {
	/**
	 * Constructor for the RemoveStructField handler.
	 * 
	 * @param tool The plugin tool instance.
	 */
	public RemoveStructField(PluginTool tool) {
		super(tool, "/remove_struct_field");
	}

	/**
	 * Handles the HTTP exchange to remove a struct field.
	 * 
	 * @param exchange The HTTP exchange object.
	 * @throws IOException If an I/O error occurs.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, Object> params = parseJsonParams(exchange);
		String baseType = (String) params.get("base_type");
		Object lengthObj = params.get("length");
		int length = (lengthObj instanceof Integer) ? (Integer) lengthObj : 1;
		String name = (String) params.get("name");
		sendResponse(exchange, createArrayType(baseType, length, name));
	}

	/**
	 * Removes a field from a structure in the current program.
	 * 
	 * @param structName The name of the structure.
	 * @param fieldName The name of the field to remove.
	 * @return A message indicating success or failure.
	 */
	private String removeStructField(String structName, String fieldName) {
        Program program = getCurrentProgram(tool);
        if (program == null) return "No program loaded";
        if (structName == null || structName.isEmpty()) return "Structure name is required";
        if (fieldName == null || fieldName.isEmpty()) return "Field name is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Remove struct field");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dataType = findDataTypeByNameInAllCategories(dtm, structName);

                    if (dataType == null) {
                        result.append("Structure not found: ").append(structName);
                        return;
                    }

                    if (!(dataType instanceof Structure)) {
                        result.append("Data type '").append(structName).append("' is not a structure");
                        return;
                    }

                    Structure struct = (Structure) dataType;
                    DataTypeComponent[] components = struct.getDefinedComponents();
                    int targetOrdinal = -1;

                    // Find the field to remove
                    for (DataTypeComponent component : components) {
                        if (fieldName.equals(component.getFieldName())) {
                            targetOrdinal = component.getOrdinal();
                            break;
                        }
                    }

                    if (targetOrdinal == -1) {
                        result.append("Field '").append(fieldName).append("' not found in structure '").append(structName).append("'");
                        return;
                    }

                    struct.delete(targetOrdinal);
                    result.append("Successfully removed field '").append(fieldName).append("' from structure '").append(structName).append("'");
                    success.set(true);

                } catch (Exception e) {
                    result.append("Error removing struct field: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute struct field removal on Swing thread: ").append(e.getMessage());
        }

        return result.toString();
    }
}
