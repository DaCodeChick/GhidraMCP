package com.lauriewired.handlers.types;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.Map;
import javax.swing.*;

import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class ValidateDataTypeExists extends Handler {
	/**
	 * Constructor for the ValidateDataTypeExists handler.
	 * 
	 * @param tool The PluginTool instance to use.
	 */
	public ValidateDataTypeExists(PluginTool tool) {
		super(tool, "/validate_data_type_exists");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String typeName = qparams.get("type_name");

		String result = validateDataTypeExists(typeName);
		sendResponse(exchange, result);
	}

	/**
	 * Validates if a data type exists in the current program's data type manager.
	 *
	 * @param typeName The name of the data type to validate.
	 * @return A JSON string indicating whether the data type exists, along with its category and size if it does.
	 */
	private String validateDataTypeExists(String typeName) {
		Program program = getCurrentProgram(tool);
		if (program == null) {
			return "{\"error\": \"No program loaded\"}";
		}

		final StringBuilder result = new StringBuilder();
		final AtomicReference<String> errorMsg = new AtomicReference<>(null);

		try {
			SwingUtilities.invokeAndWait(() -> {
				try {
					DataTypeManager dtm = program.getDataTypeManager();
					DataType dt = dtm.getDataType(typeName);

					result.append("{\"exists\": ").append(dt != null);
					if (dt != null) {
						result.append(", \"category\": \"").append(dt.getCategoryPath().getPath()).append("\"");
						result.append(", \"size\": ").append(dt.getLength());
					}
					result.append("}");
				} catch (Exception e) {
					errorMsg.set(e.getMessage());
				}
			});

			if (errorMsg.get() != null) {
				return "{\"error\": \"" + errorMsg.get().replace("\"", "\\\"") + "\"}";
			}
		} catch (Exception e) {
			return "{\"error\": \"" + e.getMessage().replace("\"", "\\\"") + "\"}";
		}

		return result.toString();
	}
}
