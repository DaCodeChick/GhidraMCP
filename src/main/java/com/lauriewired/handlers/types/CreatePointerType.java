package com.lauriewired.handlers.types;

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
 * Handler to create a pointer data type in the current Ghidra program.
 * Expects POST parameters:
 * - base_type: The base data type to point to (e.g., "int", "char", "void").
 * - name: Optional name for the new pointer type.
 * 
 * Example POST request body:
 * base_type=int&name=IntPointer
 */
public final class CreatePointerType extends Handler {
	/**
	 * Constructs a new CreatePointerType handler.
	 *
	 * @param tool The PluginTool instance to interact with Ghidra.
	 */
	public CreatePointerType(PluginTool tool) {
		super(tool, "/create_pointer_type");
	}

	/**
	 * Handles the HTTP exchange to create a pointer data type.
	 * Expects POST parameters:
	 * - base_type: The base data type to point to (e.g., "int", "char", "void").
	 * - name: Optional name for the new pointer type.
	 *
	 * @param exchange The HttpExchange object representing the HTTP request and response.
	 * @throws IOException If an I/O error occurs during handling.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> params = parsePostParams(exchange);
		String baseType = params.get("base_type");
		String name = params.get("name");
		sendResponse(exchange, createPointerType(baseType, name));
	}

	/**
	 * Creates a pointer data type in the current Ghidra program.
	 *
	 * @param baseType The base data type to point to (e.g., "int", "char", "void").
	 * @param name     Optional name for the new pointer type.
	 * @return A message indicating success or failure of the operation.
	 */
	private String createPointerType(String baseType, String name) {
        Program program = getCurrentProgram(tool);
        if (program == null) return "No program loaded";
        if (baseType == null || baseType.isEmpty()) return "Base type is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create pointer type");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType baseDataType = null;
                    
                    if ("void".equals(baseType)) {
                        baseDataType = dtm.getDataType("/void");
                        if (baseDataType == null) {
                            baseDataType = VoidDataType.dataType;
                        }
                    } else {
                        baseDataType = resolveDataType(tool, dtm, baseType);
                    }
                    
                    if (baseDataType == null) {
                        result.append("Base data type not found: ").append(baseType);
                        return;
                    }

                    PointerDataType pointerType = new PointerDataType(baseDataType);
                    
                    if (name != null && !name.isEmpty()) {
                        pointerType.setName(name);
                    }
                    
                    DataType addedType = dtm.addDataType(pointerType, DataTypeConflictHandler.REPLACE_HANDLER);
                    
                    result.append("Successfully created pointer type: ").append(addedType.getName())
                          .append(" (").append(baseType).append("*)");
                    success.set(true);

                } catch (Exception e) {
                    result.append("Error creating pointer type: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute pointer type creation on Swing thread: ").append(e.getMessage());
        }

        return result.toString();
    }
}
