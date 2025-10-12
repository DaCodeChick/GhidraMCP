package com.lauriewired.handlers.structs;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.util.Map;

import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to retrieve the layout of a structure by its name in the current
 * Ghidra program.
 * The structure layout includes field names, types, offsets, and sizes.
 * Example usage: /get_struct_layout?struct_name=MyStruct
 */
public final class GetStructLayout extends Handler {
	/**
	 * Constructor for the GetStructLayout handler.
	 *
	 * @param tool the PluginTool instance to use for accessing the current program.
	 */
	public GetStructLayout(PluginTool tool) {
		super(tool, "/get_struct", "/get_struct_layout");
	}

	/**
	 * Handles the HTTP exchange to retrieve the structure layout.
	 * Expects a query parameter "struct_name" specifying the name of the structure.
	 *
	 * @param exchange the HttpExchange object representing the HTTP request and
	 *                 response.
	 * @throws IOException if an I/O error occurs during handling.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String structName = qparams.get("struct_name");
		sendResponse(exchange, getStructLayout(structName));
	}

	/**
	 * Retrieves the layout of the specified structure in the current program.
	 *
	 * @param structName the name of the structure to retrieve.
	 * @return a formatted string representing the structure layout, or an error
	 *         message if not found or invalid.
	 */
	private String getStructLayout(String structName) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";
		if (structName == null || structName.isEmpty())
			return "Struct name is required";

		DataTypeManager dtm = program.getDataTypeManager();
		DataType dataType = findDataTypeByNameInAllCategories(dtm, structName);

		if (dataType == null) {
			return "Structure not found: " + structName;
		}

		if (!(dataType instanceof Structure)) {
			return "Data type is not a structure: " + structName;
		}

		Structure struct = (Structure) dataType;
		StringBuilder result = new StringBuilder();

		result.append("Structure: ").append(struct.getName()).append("\n");
		result.append("Size: ").append(struct.getLength()).append(" bytes\n");
		result.append("Alignment: ").append(struct.getAlignment()).append("\n\n");
		result.append("Layout:\n");
		result.append("Offset | Size | Type | Name\n");
		result.append("-------|------|------|-----\n");

		for (DataTypeComponent component : struct.getDefinedComponents()) {
			result.append(String.format("%6d | %4d | %-20s | %s\n",
					component.getOffset(),
					component.getLength(),
					component.getDataType().getName(),
					component.getFieldName() != null ? component.getFieldName() : "(unnamed)"));
		}

		return result.toString();
	}
}
