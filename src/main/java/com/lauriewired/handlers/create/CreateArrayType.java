package com.lauriewired.handlers.create;

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
 * Handler to create an array data type in the current Ghidra program.
 * Expects JSON parameters:
 * {
 *   "base_type": "int", // Base data type name
 *   "length": 10,       // Length of the array
 *   "name": "MyArray"   // Optional name for the new array type
 * }
 */
public final class CreateArrayType extends Handler {
	/**
	 * Constructs a new CreateArrayType handler.
	 *
	 * @param tool The PluginTool instance to interact with Ghidra.
	 */
	public CreateArrayType(PluginTool tool) {
		super(tool, "/create_array_type");
	}

	/**
	 * Handles the HTTP exchange to create an array data type.
	 *
	 * @param exchange The HttpExchange object containing request and response data.
	 * @throws IOException If an I/O error occurs during handling.
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
	 * Creates an array data type in the current program.
	 *
	 * @param baseType The base data type name.
	 * @param length   The length of the array.
	 * @param name     Optional name for the new array type.
	 * @return A message indicating success or failure.
	 */
	private String createArrayType(String baseType, int length, String name) {
        Program program = getCurrentProgram(tool);
        if (program == null) return "No program loaded";
        if (baseType == null || baseType.isEmpty()) return "Base type is required";
        if (length <= 0) return "Array length must be positive";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create array type");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType baseDataType = resolveDataType(tool, dtm, baseType);
                    
                    if (baseDataType == null) {
                        result.append("Base data type not found: ").append(baseType);
                        return;
                    }

                    ArrayDataType arrayType = new ArrayDataType(baseDataType, length, baseDataType.getLength());
                    
                    if (name != null && !name.isEmpty()) {
                        arrayType.setName(name);
                    }
                    
                    DataType addedType = dtm.addDataType(arrayType, DataTypeConflictHandler.REPLACE_HANDLER);
                    
                    result.append("Successfully created array type: ").append(addedType.getName())
                          .append(" (").append(baseType).append("[").append(length).append("])");
                    success.set(true);

                } catch (Exception e) {
                    result.append("Error creating array type: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute array type creation on Swing thread: ").append(e.getMessage());
        }

        return result.toString();
    }
}
