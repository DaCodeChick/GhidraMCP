package com.lauriewired.handlers.types;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.Map;
import javax.swing.*;

import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class GetValidDataTypes extends Handler {
	/**
	 * Constructor for the GetValidDataTypes handler.
	 * 
	 * @param tool The PluginTool instance to use.
	 */
	public GetValidDataTypes(PluginTool tool) {
		super(tool, "/get_valid_data_types");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String category = qparams.get("category");

		String result = getValidDataTypes(category);
		sendResponse(exchange, result);
	}

	/**
	 * Retrieves valid data types based on the specified category.
	 *
	 * @param category The category of data types to retrieve.
	 * @return A JSON string containing the valid data types or an error message.
	 */
	private String getValidDataTypes(String category) {
		Program program = getCurrentProgram(tool);
		if (program == null) {
			return "{\"error\": \"No program loaded\"}";
		}

		final StringBuilder result = new StringBuilder();
		final AtomicReference<String> errorMsg = new AtomicReference<>(null);

		try {
			SwingUtilities.invokeAndWait(() -> {
				try {
					result.append("{");
					result.append("\"builtin_types\": [");

					// Common builtin types
					String[] builtinTypes = {
						"void", "byte", "char", "short", "int", "long", "longlong",
						"float", "double", "pointer", "bool",
						"undefined", "undefined1", "undefined2", "undefined4", "undefined8",
						"uchar", "ushort", "uint", "ulong", "ulonglong",
						"sbyte", "sword", "sdword", "sqword",
						"word", "dword", "qword"
					};

					for (int i = 0; i < builtinTypes.length; i++) {
						if (i > 0) result.append(", ");
						result.append("\"").append(builtinTypes[i]).append("\"");
					}

					result.append("], ");
					result.append("\"windows_types\": [");

					String[] windowsTypes = {
						"BOOL", "BOOLEAN", "BYTE", "CHAR", "DWORD", "QWORD", "WORD",
						"HANDLE", "HMODULE", "HWND", "LPVOID", "PVOID",
						"LPCSTR", "LPSTR", "LPCWSTR", "LPWSTR",
						"SIZE_T", "ULONG", "USHORT"
					};

					for (int i = 0; i < windowsTypes.length; i++) {
						if (i > 0) result.append(", ");
						result.append("\"").append(windowsTypes[i]).append("\"");
					}

					result.append("]");
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
