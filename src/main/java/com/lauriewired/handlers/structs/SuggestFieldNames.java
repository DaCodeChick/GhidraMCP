package com.lauriewired.handlers.structs;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Data;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.List;
import java.util.Map;
import javax.swing.SwingUtilities;

import static com.lauriewired.GhidraMCPPlugin.*;
import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to suggest field names for structure fields based on their data types and common naming conventions.
 */
public final class SuggestFieldNames extends Handler {
	/**
	 * Constructor for the SuggestFieldNames handler.
	 * 
	 * @param tool The plugin tool instance.
	 */
	public SuggestFieldNames(PluginTool tool) {
		super(tool, "/suggest_field_names");
	}

	/**
	 * Handles the HTTP exchange to suggest field names for structure fields.
	 * @param exchange The HTTP exchange object.
	 * @throws IOException If an I/O error occurs.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, Object> params = parseJsonParams(exchange);
		String structAddress = (String) params.get("struct_address");
		int structSize = parseIntOrDefault(String.valueOf(params.get("struct_size")), 0);

		String result = suggestFieldNames(structAddress, structSize);
		sendResponse(exchange, result);
	}

	/**
	 * Capitalizes the first letter of a string.
	 * @param str The input string.
	 * @return The string with the first letter capitalized.
	 */
	private String capitalizeFirst(String str) {
		if (str == null || str.isEmpty()) return str;
		return Character.toUpperCase(str.charAt(0)) + str.substring(1);
	}

	/**
	 * Generates field name suggestions based on the data type of the component.
	 * @param component The data type component.
	 * @return A list of suggested field names.
	 */
	private List<String> generateFieldNameSuggestions(DataTypeComponent component) {
		List<String> suggestions = new ArrayList<>();
		String typeName = component.getDataType().getName().toLowerCase();
		String currentName = component.getFieldName();

		// Hungarian notation suggestions based on type
		if (typeName.contains("pointer") || typeName.startsWith("p")) {
			suggestions.add("p" + capitalizeFirst(currentName));
			suggestions.add("lp" + capitalizeFirst(currentName));
		} else if (typeName.contains("dword")) {
			suggestions.add("dw" + capitalizeFirst(currentName));
		} else if (typeName.contains("word")) {
			suggestions.add("w" + capitalizeFirst(currentName));
		} else if (typeName.contains("byte") || typeName.contains("char")) {
			suggestions.add("b" + capitalizeFirst(currentName));
			suggestions.add("sz" + capitalizeFirst(currentName));
		} else if (typeName.contains("int")) {
			suggestions.add("n" + capitalizeFirst(currentName));
			suggestions.add("i" + capitalizeFirst(currentName));
		}

		// Add generic suggestions
		suggestions.add(currentName + "Value");
		suggestions.add(currentName + "Data");

		return suggestions;
	}

	/**
	 * Suggests field names for the structure at the given address.
	 * @param structAddressStr The address of the structure.
	 * @param structSize The size of the structure.
	 * @return A JSON string containing the suggested field names.
	 */
	private String suggestFieldNames(String structAddressStr, int structSize) {
		// Validate input parameters
		if (structSize < 0 || structSize > MAX_FIELD_OFFSET) {
			return "{\"error\": \"structSize must be between 0 and " + MAX_FIELD_OFFSET + "\"}";
		}

		final AtomicReference<String> result = new AtomicReference<>();

		// CRITICAL FIX #1: Thread safety - wrap in SwingUtilities.invokeAndWait
		try {
			SwingUtilities.invokeAndWait(() -> {
				try {
					Program program = getCurrentProgram(tool);
					if (program == null) {
						result.set("{\"error\": \"No program loaded\"}");
						return;
					}

					Address addr = program.getAddressFactory().getAddress(structAddressStr);
					if (addr == null) {
						result.set("{\"error\": \"Invalid address: " + structAddressStr + "\"}");
						return;
					}

					Msg.info(this, "Generating field name suggestions for structure at " + structAddressStr);

					// Get data at address
					Data data = program.getListing().getDataAt(addr);
					DataType dataType = (data != null) ? data.getDataType() : null;

					if (dataType == null || !(dataType instanceof Structure)) {
						result.set("{\"error\": \"No structure data type found at " + structAddressStr + "\"}");
						return;
					}

					Structure struct = (Structure) dataType;

					// MAJOR FIX #5: Validate structure size
					DataTypeComponent[] components = struct.getComponents();
					if (components.length > MAX_STRUCT_FIELDS) {
						result.set("{\"error\": \"Structure too large: " + components.length +
								   " fields (max " + MAX_STRUCT_FIELDS + ")\"}");
						return;
					}

					StringBuilder json = new StringBuilder();
					json.append("{");
					json.append("\"struct_address\": \"").append(structAddressStr).append("\",");
					json.append("\"struct_name\": \"").append(escapeJson(struct.getName())).append("\",");
					json.append("\"struct_size\": ").append(struct.getLength()).append(",");
					json.append("\"suggestions\": [");

					boolean first = true;
					for (DataTypeComponent component : components) {
						if (!first) json.append(",");
						first = false;

						json.append("{");
						json.append("\"offset\": ").append(component.getOffset()).append(",");
						json.append("\"current_name\": \"").append(escapeJson(component.getFieldName())).append("\",");
						json.append("\"field_type\": \"").append(escapeJson(component.getDataType().getName())).append("\",");

						// Generate suggestions based on type and patterns
						List<String> suggestions = generateFieldNameSuggestions(component);

						// Ensure we always have fallback suggestions
						if (suggestions.isEmpty()) {
							suggestions.add(component.getFieldName() + "Value");
							suggestions.add(component.getFieldName() + "Data");
						}

						json.append("\"suggested_names\": [");
						for (int i = 0; i < suggestions.size(); i++) {
							if (i > 0) json.append(",");
							json.append("\"").append(escapeJson(suggestions.get(i))).append("\"");
						}
						json.append("],");

						json.append("\"confidence\": \"medium\"");  // Placeholder confidence level
						json.append("}");
					}

					json.append("]");
					json.append("}");

					Msg.info(this, "Generated suggestions for " + components.length + " fields");
					result.set(json.toString());

				} catch (Exception e) {
					Msg.error(this, "Error in suggestFieldNames", e);
					result.set("{\"error\": \"" + escapeJson(e.getMessage()) + "\"}");
				}
			});
		} catch (InvocationTargetException | InterruptedException e) {
			Msg.error(this, "Thread synchronization error in suggestFieldNames", e);
			return "{\"error\": \"Thread synchronization error: " + escapeJson(e.getMessage()) + "\"}";
		}

		return result.get();
	}
}
