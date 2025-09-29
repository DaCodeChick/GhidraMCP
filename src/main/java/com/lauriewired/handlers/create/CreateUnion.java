package com.lauriewired.handlers.create;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidNameException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.swing.SwingUtilities;

import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to create a union in the current Ghidra program.
 * Expects JSON parameters:
 * - name: The name of the union (String)
 * - fields: A list of field definitions, where each field is an object with:
 *   - name: The name of the field (String)
 *   - type: The data type of the field (String)
 */
public final class CreateUnion extends Handler {
	/**
	 * Constructs a new CreateUnion handler.
	 *
	 * @param tool The PluginTool instance to interact with Ghidra.
	 */
	public CreateUnion(PluginTool tool) {
		super(tool, "/create_union");
	}

	/**
	 * Handles HTTP requests to create a union.
	 * Expects JSON parameters:
	 * - name: The name of the union (String)
	 * - fields: A list of field definitions, where each field is an object with:
	 *   - name: The name of the field (String)
	 *   - type: The data type of the field (String)
	 *
	 * Example JSON body:
	 * {
	 *   "name": "MyUnion",
	 *   "fields": [
	 *     {"name": "field1", "type": "int"},
	 *     {"name": "field2", "type": "float"}
	 *   ]
	 * }
	 *
	 * @param exchange The HttpExchange object representing the HTTP request and response.
	 * @throws IOException If an I/O error occurs.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		try {
			Map<String, Object> params = parseJsonParams(exchange);
			String name = (String) params.get("name");
			Object fieldsObj = params.get("fields");
			// Convert to JSON string like struct endpoint does
			String fieldsJson = (fieldsObj instanceof String) ? (String) fieldsObj
					: (fieldsObj != null ? fieldsObj.toString() : null);
			sendResponse(exchange, createUnion(name, fieldsJson));
		} catch (Exception e) {
			sendResponse(exchange, "Union endpoint error: " + e.getMessage());
		}
	}

	/**
	 * Creates a union in the current program with the specified name and fields.
	 * @param name The name of the union.
	 * @param fieldsObj The fields definition object (should be a List of Maps).
	 * @return A result message indicating success or failure.
	 */
	private String createUnionDirect(String name, Object fieldsObj) {
		Program program = getCurrentProgram();
		if (program == null)
			return "No program loaded";
		if (name == null || name.isEmpty())
			return "Union name is required";
		if (fieldsObj == null)
			return "Fields are required";

		AtomicBoolean success = new AtomicBoolean(false);
		StringBuilder result = new StringBuilder();

		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Create union");
				try {
					DataTypeManager dtm = program.getDataTypeManager();
					UnionDataType union = new UnionDataType(name);

					// Handle fields object directly (should be a List of Maps)
					if (fieldsObj instanceof java.util.List) {
						@SuppressWarnings("unchecked")
						java.util.List<Object> fieldsList = (java.util.List<Object>) fieldsObj;

						for (Object fieldObj : fieldsList) {
							if (fieldObj instanceof java.util.Map) {
								@SuppressWarnings("unchecked")
								java.util.Map<String, Object> fieldMap = (java.util.Map<String, Object>) fieldObj;

								String fieldName = (String) fieldMap.get("name");
								String fieldType = (String) fieldMap.get("type");

								if (fieldName != null && fieldType != null) {
									DataType dt = findDataTypeByNameInAllCategories(dtm, fieldType);
									if (dt != null) {
										union.add(dt, fieldName, null);
										result.append("Added field: ").append(fieldName).append(" (").append(fieldType)
												.append(")\n");
									} else {
										result.append("Warning: Data type not found for field ").append(fieldName)
												.append(": ").append(fieldType).append("\n");
									}
								}
							}
						}
					} else {
						result.append("Invalid fields format - expected list of field objects");
						return;
					}

					dtm.addDataType(union, DataTypeConflictHandler.REPLACE_HANDLER);
					result.append("Union '").append(name).append("' created successfully with ")
							.append(union.getNumComponents()).append(" fields");
					success.set(true);
				} catch (Exception e) {
					result.append("Error creating union: ").append(e.getMessage());
				} finally {
					program.endTransaction(tx, success.get());
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			result.append("Failed to execute union creation on Swing thread: ").append(e.getMessage());
		}

		return result.toString();
	}

	/**
	 * Simple test method to verify the endpoint is reachable and parameters are parsed.
	 * @param name The name of the union.
	 * @param fieldsObj The fields definition object.
	 * @return A success message with the provided name.
	 */
	private String createUnionSimple(String name, Object fieldsObj) {
		// Even simpler test - don't access any Ghidra APIs
		if (name == null || name.isEmpty())
			return "Union name is required";
		if (fieldsObj == null)
			return "Fields are required";

		return "Union endpoint test successful - name: " + name;
	}

	/**
	 * Creates a union in the current program with the specified name and fields JSON.
	 * @param name The name of the union.
	 * @param fieldsJson The fields definition JSON string.
	 * @return A result message indicating success or failure.
	 */
	private String createUnion(String name, String fieldsJson) {
		Program program = getCurrentProgram();
		if (program == null)
			return "No program loaded";
		if (name == null || name.isEmpty())
			return "Union name is required";
		if (fieldsJson == null || fieldsJson.isEmpty())
			return "Fields JSON is required";

		AtomicBoolean success = new AtomicBoolean(false);
		StringBuilder result = new StringBuilder();

		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Create union");
				try {
					DataTypeManager dtm = program.getDataTypeManager();
					UnionDataType union = new UnionDataType(name);

					// Parse fields from JSON using the same method as structs
					List<FieldDefinition> fields = parseFieldsJson(fieldsJson);

					if (fields.isEmpty()) {
						result.append("No valid fields provided");
						return;
					}

					// Process each field for the union (use resolveDataType like structs do)
					for (FieldDefinition field : fields) {
						DataType dt = resolveDataType(dtm, field.type);
						if (dt != null) {
							union.add(dt, field.name, null);
							result.append("Added field: ").append(field.name).append(" (").append(field.type)
									.append(")\n");
						} else {
							result.append("Warning: Data type not found for field ").append(field.name).append(": ")
									.append(field.type).append("\n");
						}
					}

					dtm.addDataType(union, DataTypeConflictHandler.REPLACE_HANDLER);
					result.append("Union '").append(name).append("' created successfully with ")
							.append(union.getNumComponents()).append(" fields");
					success.set(true);
				} catch (Exception e) {
					result.append("Error creating union: ").append(e.getMessage());
				} finally {
					program.endTransaction(tx, success.get());
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			result.append("Failed to execute union creation on Swing thread: ").append(e.getMessage());
		}

		return result.toString();
	}
}
