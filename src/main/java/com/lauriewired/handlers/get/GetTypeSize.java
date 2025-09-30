package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.util.Map;

import static com.lauriewired.util.GhidraUtils.findDataTypeByNameInAllCategories;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to get the size of a data type by its name.
 * Example usage: /get_type_size?type_name=int
 * Returns the size of the specified data type.
 * If the type is not found, returns an error message.
 */
public final class GetTypeSize extends Handler {
	/**
	 * Constructor for the GetTypeSize handler.
	 * 
	 * @param tool The PluginTool instance to use.
	 */
	public GetTypeSize(PluginTool tool) {
		super(tool, "/get_type_size");
	}

	/**
	 * Handles the HTTP exchange to get the size of a data type.
	 * Expects a query parameter "type_name" specifying the name of the data type.
	 * Responds with the size of the data type or an error message if not found.
	 * @param exchange The HttpExchange object representing the HTTP request and response.
	 * @throws IOException If an I/O error occurs.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String typeName = qparams.get("type_name");
		sendResponse(exchange, getTypeSize(typeName));
	}

	/**
	 * Retrieves the size of the specified data type.
	 * 
	 * @param typeName The name of the data type to look up.
	 * @return A string containing the size of the data type or an error message if not found.
	 */
	private String getTypeSize(String typeName) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";
		if (typeName == null || typeName.isEmpty())
			return "Type name is required";

		DataTypeManager dtm = program.getDataTypeManager();
		DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);

		if (dataType == null) {
			return "Data type not found: " + typeName;
		}

		int size = dataType.getLength();
		return String.format("Type: %s\nSize: %d bytes\nAlignment: %d\nPath: %s",
				dataType.getName(),
				size,
				dataType.getAlignment(),
				dataType.getPathName());
	}
}
