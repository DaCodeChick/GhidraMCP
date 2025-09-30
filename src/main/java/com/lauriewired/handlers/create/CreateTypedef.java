package com.lauriewired.handlers.create;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
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
 * Handler to create a typedef in the current Ghidra program.
 * Expects POST parameters "name" (the name of the typedef) and "base_type" (the
 * existing type to alias).
 * Responds with success or error message.
 */
public final class CreateTypedef extends Handler {
	/**
	 * Constructs a new CreateTypedef handler.
	 *
	 * @param tool The PluginTool instance to interact with Ghidra.
	 */
	public CreateTypedef(PluginTool tool) {
		super(tool, "/create_typedef");
	}

	/**
	 * Handles HTTP requests to create a typedef.
	 * Expects POST parameters "name" and "base_type".
	 * Responds with success or error message.
	 * 
	 * @param exchange The HttpExchange object representing the HTTP request and
	 *                 response.
	 * @throws IOException If an I/O error occurs.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> params = parsePostParams(exchange);
		String name = params.get("name");
		String baseType = params.get("base_type");
		sendResponse(exchange, createTypedef(name, baseType));
	}

	/**
	 * Creates a typedef in the current Ghidra program.
	 *
	 * @param name     The name of the typedef to create.
	 * @param baseType The existing data type to alias.
	 * @return A message indicating success or failure.
	 */
	private String createTypedef(String name, String baseType) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";
		if (name == null || name.isEmpty())
			return "Typedef name is required";
		if (baseType == null || baseType.isEmpty())
			return "Base type is required";

		AtomicBoolean success = new AtomicBoolean(false);
		StringBuilder result = new StringBuilder();

		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Create typedef");
				try {
					DataTypeManager dtm = program.getDataTypeManager();
					DataType base = findDataTypeByNameInAllCategories(dtm, baseType);

					if (base == null) {
						result.append("Base type not found: ").append(baseType);
						return;
					}

					TypedefDataType typedef = new TypedefDataType(name, base);
					dtm.addDataType(typedef, DataTypeConflictHandler.REPLACE_HANDLER);

					result.append("Typedef '").append(name).append("' created as alias for '").append(baseType)
							.append("'");
					success.set(true);
				} catch (Exception e) {
					result.append("Error creating typedef: ").append(e.getMessage());
				} finally {
					program.endTransaction(tx, success.get());
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			result.append("Failed to execute typedef creation on Swing thread: ").append(e.getMessage());
		}

		return result.toString();
	}
}
