package com.lauriewired.handlers.enums;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.util.Map;

import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to retrieve and display the values of a specified enumeration in the
 * current program.
 * The enumeration is identified by its name, which is provided as a query
 * parameter.
 * The response includes the enumeration's name, size, and a list of its values
 * with their names and corresponding integer values.
 * 
 */
public final class GetEnumValues extends Handler {
	/**
	 * Constructor for the GetEnumValues handler.
	 *
	 * @param tool the PluginTool instance to use for accessing the current program.
	 */
	public GetEnumValues(PluginTool tool) {
		super(tool, "/get_enum_values");
	}

	/**
	 * Handles the HTTP exchange to retrieve enumeration values.
	 * Expects a query parameter "enum_name" specifying the name of the enumeration.
	 * Responds with the enumeration's values or an error message if not found.
	 * 
	 * @param exchange the HttpExchange object representing the HTTP request and
	 *                 response.
	 * @throws IOException if an I/O error occurs during handling.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String enumName = qparams.get("enum_name");
		sendResponse(exchange, getEnumValues(enumName));
	}

	/**
	 * Retrieves the values of the specified enumeration from the current program.
	 *
	 * @param enumName the name of the enumeration to retrieve.
	 * @return a formatted string containing the enumeration's values or an error
	 *         message if not found.
	 */
	private String getEnumValues(String enumName) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";
		if (enumName == null || enumName.isEmpty())
			return "Enum name is required";

		DataTypeManager dtm = program.getDataTypeManager();
		DataType dataType = findDataTypeByNameInAllCategories(dtm, enumName);

		if (dataType == null) {
			return "Enumeration not found: " + enumName;
		}

		if (!(dataType instanceof ghidra.program.model.data.Enum)) {
			return "Data type is not an enumeration: " + enumName;
		}

		ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dataType;
		StringBuilder result = new StringBuilder();

		result.append("Enumeration: ").append(enumType.getName()).append("\n");
		result.append("Size: ").append(enumType.getLength()).append(" bytes\n\n");
		result.append("Values:\n");
		result.append("Name | Value\n");
		result.append("-----|------\n");

		String[] names = enumType.getNames();
		for (String valueName : names) {
			long value = enumType.getValue(valueName);
			result.append(String.format("%-20s | %d (0x%X)\n", valueName, value, value));
		}

		return result.toString();
	}
}
