package com.lauriewired.handlers.structs;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
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
 * Handler to add a field to a structure in the current program.
 * Expects JSON parameters:
 * {
 *   "struct_name": "name_of_structure",
 *   "field_name": "name_of_new_field",
 *   "field_type": "data_type_of_new_field",
 *   "offset": optional_offset_integer
 * }
 * If offset is not provided, the field is added at the end of the structure.
 */
public final class AddStructField extends Handler {
	/**
	 * Constructor for the AddStructField handler.
	 * 
	 * @param tool The plugin tool instance.
	 */
	public AddStructField(PluginTool tool) {
		super(tool, "/add_struct_field", "/add_struct_members");
	}

	/**
	 * Handles the HTTP exchange to add a field to a structure.
	 * 
	 * @param exchange The HTTP exchange object.
	 * @throws IOException If an I/O error occurs.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, Object> params = parseJsonParams(exchange);
		String structName = (String) params.get("struct_name");
		String fieldName = (String) params.get("field_name");
		String fieldType = (String) params.get("field_type");
		Object offsetObj = params.get("offset");
		int offset = (offsetObj instanceof Integer) ? (Integer) offsetObj : -1;
		sendResponse(exchange, addStructField(structName, fieldName, fieldType, offset));
	}

	/**
	 * Adds a field to the specified structure in the current program.
	 * 
	 * @param structName The name of the structure to modify.
	 * @param fieldName The name of the new field to add.
	 * @param fieldType The data type of the new field.
	 * @param offset The offset at which to add the new field, or -1 to add at the end.
	 * @return A message indicating success or failure.
	 */
	private String addStructField(String structName, String fieldName, String fieldType, int offset) {
        Program program = getCurrentProgram(tool);
        if (program == null) return "No program loaded";
        if (structName == null || structName.isEmpty()) return "Structure name is required";
        if (fieldName == null || fieldName.isEmpty()) return "Field name is required";
        if (fieldType == null || fieldType.isEmpty()) return "Field type is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Add struct field");
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
                    DataType newFieldType = resolveDataType(tool, dtm, fieldType);
                    if (newFieldType == null) {
                        result.append("Field data type not found: ").append(fieldType);
                        return;
                    }

                    if (offset >= 0) {
                        // Add at specific offset
                        struct.insertAtOffset(offset, newFieldType, newFieldType.getLength(), fieldName, null);
                    } else {
                        // Add at end
                        struct.add(newFieldType, fieldName, null);
                    }

                    result.append("Successfully added field '").append(fieldName).append("' to structure '").append(structName).append("'");
                    success.set(true);

                } catch (Exception e) {
                    result.append("Error adding struct field: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute struct field addition on Swing thread: ").append(e.getMessage());
        }

        return result.toString();
    }
}
