package com.lauriewired.handlers.create;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to create a new enumeration in Ghidra.
 * Expects a POST request with JSON body containing:
 * - name: The name of the enumeration (required)
 * - values: A JSON object mapping enum value names to their integer values
 * (required)
 * - size: The size of the enumeration (1, 2, 4, or 8 bytes, default is 4)
 */
public final class CreateEnum extends Handler {
	/**
	 * Constructs a new CreateEnum handler.
	 *
	 * @param tool The PluginTool instance to interact with Ghidra.
	 */
	public CreateEnum(PluginTool tool) {
		super(tool, "/create_enum");
	}

	/**
	 * Handles the HTTP request to create a new enum.
	 * Parses parameters from the POST request and creates the enum in Ghidra.
	 *
	 * @param exchange The HTTP exchange containing the request and response.
	 * @throws IOException If an I/O error occurs during handling.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, Object> params = parseJsonParams(exchange);
		String name = (String) params.get("name");
		Object valuesObj = params.get("values");
		String valuesJson = (valuesObj instanceof String) ? (String) valuesObj
				: (valuesObj != null ? valuesObj.toString() : null);
		Object sizeObj = params.get("size");
		int size = (sizeObj instanceof Integer) ? (Integer) sizeObj
				: parseIntOrDefault(sizeObj != null ? sizeObj.toString() : null, 4);
		sendResponse(exchange, createEnum(name, valuesJson, size));
	}

	/**
	 * Creates a new enumeration in the current Ghidra program.
	 * Validates parameters and handles errors appropriately.
	 * 
	 * @param name       The name of the enumeration.
	 * @param valuesJson A JSON string representing a map of enum value names to
	 *                   their integer
	 * @param size       The size of the enumeration (1, 2, 4, or 8 bytes).
	 * @return A success or error message.
	 */
	private String createEnum(String name, String valuesJson, int size) {
		Program program = getCurrentProgram();
		if (program == null) {
			return "No program loaded";
		}

		if (name == null || name.isEmpty()) {
			return "Enumeration name is required";
		}

		if (valuesJson == null || valuesJson.isEmpty()) {
			return "Values JSON is required";
		}

		if (size != 1 && size != 2 && size != 4 && size != 8) {
			return "Invalid size. Must be 1, 2, 4, or 8 bytes";
		}

		try {
			// Parse the values JSON
			Map<String, Long> values = parseValuesJson(valuesJson);

			if (values.isEmpty()) {
				return "No valid enum values provided";
			}

			DataTypeManager dtm = program.getDataTypeManager();

			// Check if enum already exists
			DataType existingType = dtm.getDataType("/" + name);
			if (existingType != null) {
				return "Enumeration with name '" + name + "' already exists";
			}

			// Create the enumeration
			int txId = program.startTransaction("Create Enumeration: " + name);
			try {
				EnumDataType enumDt = new EnumDataType(name, size);

				for (Map.Entry<String, Long> entry : values.entrySet()) {
					enumDt.add(entry.getKey(), entry.getValue());
				}

				// Add the enumeration to the data type manager
				dtm.addDataType(enumDt, null);

				program.endTransaction(txId, true);

				return "Successfully created enumeration '" + name + "' with " + values.size() +
						" values, size: " + size + " bytes";

			} catch (Exception e) {
				program.endTransaction(txId, false);
				return "Error creating enumeration: " + e.getMessage();
			}

		} catch (Exception e) {
			return "Error parsing values JSON: " + e.getMessage();
		}
	}
}
