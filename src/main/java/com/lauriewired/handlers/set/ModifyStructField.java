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
 * Handler to modify a field in a structure within the current program.
 * Expects JSON parameters:
 * - struct_name: Name of the structure containing the field.
 * - field_name: Name of the field to modify.
 * - new_type: (Optional) New data type for the field.
 * - new_name: (Optional) New name for the field.
 */
public final class ModifyStructField extends Handler {
	/**
	 * Constructor for the ModifyStructField handler.
	 * 
	 * @param tool The plugin tool instance.
	 */
	public ModifyStructField(PluginTool tool) {
		super(tool, "/modify_struct_field");
	}

	/**
	 * Handles HTTP requests to modify a field in a structure.
	 * Expects JSON parameters:
	 * - struct_name: Name of the structure containing the field.
	 * - field_name: Name of the field to modify.
	 * - new_type: (Optional) New data type for the field.
	 * - new_name: (Optional) New name for the field.
	 * 
	 * @param exchange The HTTP exchange object.
	 * @throws IOException If an I/O error occurs.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, Object> params = parseJsonParams(exchange);
		String structName = (String) params.get("struct_name");
		String fieldName = (String) params.get("field_name");
		String newType = (String) params.get("new_type");
		String newName = (String) params.get("new_name");
		sendResponse(exchange, modifyStructField(structName, fieldName, newType, newName));
	}

	/**
	 * Modifies a field in a structure within the current program.
	 * 
	 * @param structName The name of the structure containing the field.
	 * @param fieldName The name of the field to modify.
	 * @param newType (Optional) The new data type for the field.
	 * @param newName (Optional) The new name for the field.
	 * @return A message indicating success or failure.
	 */
	private String modifyStructField(String structName, String fieldName, String newType, String newName) {
        Program program = getCurrentProgram(tool);
        if (program == null) return "No program loaded";
        if (structName == null || structName.isEmpty()) return "Structure name is required";
        if (fieldName == null || fieldName.isEmpty()) return "Field name is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Modify struct field");
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
                    DataTypeComponent targetComponent = null;

                    // Find the field to modify
                    for (DataTypeComponent component : components) {
                        if (fieldName.equals(component.getFieldName())) {
                            targetComponent = component;
                            break;
                        }
                    }

                    if (targetComponent == null) {
                        result.append("Field '").append(fieldName).append("' not found in structure '").append(structName).append("'");
                        return;
                    }

                    // If new type is specified, change the field type
                    if (newType != null && !newType.isEmpty()) {
                        DataType newDataType = resolveDataType(tool, dtm, newType);
                        if (newDataType == null) {
                            result.append("New data type not found: ").append(newType);
                            return;
                        }
                        struct.replace(targetComponent.getOrdinal(), newDataType, newDataType.getLength());
                    }

                    // If new name is specified, change the field name
                    if (newName != null && !newName.isEmpty()) {
                        targetComponent = struct.getComponent(targetComponent.getOrdinal()); // Refresh component
                        targetComponent.setFieldName(newName);
                    }

                    result.append("Successfully modified field '").append(fieldName).append("' in structure '").append(structName).append("'");
                    success.set(true);

                } catch (Exception e) {
                    result.append("Error modifying struct field: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute struct field modification on Swing thread: ").append(e.getMessage());
        }

        return result.toString();
    }
}
