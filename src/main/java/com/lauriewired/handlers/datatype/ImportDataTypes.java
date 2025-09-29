package com.lauriewired.handlers.datatype;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;

import java.io.IOException;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for importing data types into the current Ghidra program.
 * This handler processes POST requests with parameters for the source
 * of the data types and the format (e.g., "c" for C header files).
 */
public final class ImportDataTypes extends Handler {
	/**
	 * Constructor for the ImportDataTypes handler.
	 *
	 * @param tool The Ghidra plugin tool instance.
	 */
	public ImportDataTypes(PluginTool tool) {
		super(tool, "/import_data_types");
	}

	/**
	 * Handles HTTP POST requests to import data types.
	 * Expects parameters:
	 * - source: The source of the data types (e.g., file path or URL).
	 * - format: The format of the data types (e.g., "c" for C header files).
	 * Defaults to "c" if not provided.
	 * Responds with a message indicating the result of the import operation.
	 * @param exchange The HttpExchange object representing the HTTP request and response.
	 * @throws IOException If an I/O error occurs during request handling.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> params = parsePostParams(exchange);
		String source = params.get("source");
		String format = params.getOrDefault("format", "c");
		sendResponse(exchange, importDataTypes(source, format));
	}

	/**
	 * Imports data types into the current Ghidra program based on the provided source and format.
	 * This is a placeholder implementation; actual import logic should be implemented as needed.
	 *
	 * @param source The source of the data types (e.g., file path or URL).
	 * @param format The format of the data types (e.g., "c" for C header files).
	 * @return A message indicating the result of the import operation.
	 */
	private String importDataTypes(String source, String format) {
		// This is a placeholder for import functionality
		// In a real implementation, you would parse the source based on format
		return "Import functionality not yet implemented. Source: " + source + ", Format: " + format;
	}
}