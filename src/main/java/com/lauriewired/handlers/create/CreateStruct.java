package com.lauriewired.handlers.create;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to create a new struct in Ghidra based on provided JSON parameters.
 * Expects a POST request with parameters:
 * - name: The name of the structure (required)
 * - fields: A JSON array of field definitions (required)
 */
public final class CreateStruct extends Handler {
	/**
	 * Constructs a new CreateStruct handler.
	 *
	 * @param tool The PluginTool instance to interact with Ghidra.
	 */
	public CreateStruct(PluginTool tool) {
		super(tool, "/create_struct");
	}

	/**
	 * Handles the HTTP request to create a new struct.
	 * Parses parameters from the POST request and creates the struct in Ghidra.
	 *
	 * @param exchange The HTTP exchange containing the request and response.
	 * @throws IOException If an I/O error occurs during handling.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, Object> params = parseJsonParams(exchange);
		String name = (String) params.get("name");
		Object fieldsObj = params.get("fields");
		String fieldsJson = (fieldsObj instanceof String) ? (String) fieldsObj
				: (fieldsObj != null ? fieldsObj.toString() : null);
		sendResponse(exchange, createStruct(name, fieldsJson));
	}

	/**
	 * Creates a new structure in the current Ghidra program.
	 *
	 * @param name       The name of the structure to create.
	 * @param fieldsJson A JSON array string defining the fields of the structure.
	 * @return A message indicating success or failure.
	 */
	private String createStruct(String name, String fieldsJson) {
		Program program = getCurrentProgram();
		if (program == null) {
			return "No program loaded";
		}

		if (name == null || name.isEmpty()) {
			return "Structure name is required";
		}

		if (fieldsJson == null || fieldsJson.isEmpty()) {
			return "Fields JSON is required";
		}

		try {
			// Parse the fields JSON (simplified parsing for basic structure)
			// Expected format:
			// [{"name":"field1","type":"int"},{"name":"field2","type":"char"}]
			List<FieldDefinition> fields = parseFieldsJson(fieldsJson);

			if (fields.isEmpty()) {
				return "No valid fields provided";
			}

			DataTypeManager dtm = program.getDataTypeManager();

			// Check if struct already exists
			DataType existingType = dtm.getDataType("/" + name);
			if (existingType != null) {
				return "Structure with name '" + name + "' already exists";
			}

			// Create the structure
			int txId = program.startTransaction("Create Structure: " + name);
			try {
				StructureDataType struct = new StructureDataType(name, 0);

				// Add fields sequentially for simplicity
				for (FieldDefinition field : fields) {
					DataType fieldType = resolveDataType(dtm, field.type);
					if (fieldType == null) {
						return "Unknown field type: " + field.type;
					}

					// Add field to the end of the structure
					struct.add(fieldType, fieldType.getLength(), field.name, "");
				}

				// Add the structure to the data type manager
				DataType createdStruct = dtm.addDataType(struct, null);

				program.endTransaction(txId, true);

				return "Successfully created structure '" + name + "' with " + fields.size() +
						" fields, total size: " + createdStruct.getLength() + " bytes";

			} catch (Exception e) {
				program.endTransaction(txId, false);
				return "Error creating structure: " + e.getMessage();
			}

		} catch (Exception e) {
			return "Error parsing fields JSON: " + e.getMessage();
		}
	}
}
