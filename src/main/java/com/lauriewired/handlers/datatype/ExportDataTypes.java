package com.lauriewired.handlers.datatype;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NoValueException;
import ghidra.util.exception.VersionException;

import java.io.IOException;
import java.util.Iterator;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to export data types from the current program in various formats.
 * Supported formats include C declarations, JSON, and a simple summary.
 * Optional filtering by category is also supported.
 */
public final class ExportDataTypes extends Handler {
	/**
	 * Constructor for the ExportDataTypes handler.
	 *
	 * @param tool The Ghidra plugin tool instance.
	 */
	public ExportDataTypes(PluginTool tool) {
		super(tool, "/export_data_types");
	}

	/**
	 * Handles HTTP requests to export data types.
	 * Supported query parameters:
	 * - format: The export format ("c", "json", or "summary"). Default is "c".
	 * - category: Optional category path to filter data types.
	 *
	 * @param exchange The HTTP exchange object.
	 * @throws IOException If an I/O error occurs.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String format = qparams.getOrDefault("format", "c");
		String category = qparams.get("category");
		sendResponse(exchange, exportDataTypes(format, category));
	}

	/**
	 * Exports data types from the current program in the specified format and
	 * category.
	 *
	 * @param format   The export format ("c", "json", or "summary").
	 * @param category Optional category path to filter data types.
	 * @return A string containing the exported data types.
	 */
	private String exportDataTypes(String format, String category) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";

		StringBuilder result = new StringBuilder();
		DataTypeManager dtm = program.getDataTypeManager();

		result.append("Exporting data types in ").append(format).append(" format");
		if (category != null && !category.isEmpty()) {
			result.append(" (category: ").append(category).append(")");
		}
		result.append(":\n\n");

		Iterator<DataType> allTypes = dtm.getAllDataTypes();
		int count = 0;

		while (allTypes.hasNext()) {
			DataType dt = allTypes.next();

			// Filter by category if specified
			if (category != null && !category.isEmpty()) {
				if (!dt.getCategoryPath().toString().toLowerCase().contains(category.toLowerCase())) {
					continue;
				}
			}

			switch (format.toLowerCase()) {
				case "c":
					result.append(exportDataTypeAsC(dt)).append("\n");
					break;
				case "json":
					result.append(exportDataTypeAsJson(dt)).append("\n");
					break;
				case "summary":
				default:
					result.append(dt.getName()).append(" | Size: ").append(dt.getLength())
							.append(" | Path: ").append(dt.getPathName()).append("\n");
					break;
			}
			count++;
		}

		result.append("\nExported ").append(count).append(" data types");
		return result.toString();
	}

	/**
	 * Exports a single data type as a C declaration.
	 *
	 * @param dataType The data type to export.
	 * @return A string containing the C declaration of the data type.
	 */
	private String exportDataTypeAsC(DataType dataType) {
		if (dataType instanceof Structure) {
			Structure struct = (Structure) dataType;
			StringBuilder c = new StringBuilder();
			c.append("struct ").append(struct.getName()).append(" {\n");
			for (DataTypeComponent comp : struct.getDefinedComponents()) {
				c.append("    ").append(comp.getDataType().getName()).append(" ");
				if (comp.getFieldName() != null) {
					c.append(comp.getFieldName());
				} else {
					c.append("field_").append(comp.getOffset());
				}
				c.append(";\n");
			}
			c.append("};");
			return c.toString();
		} else if (dataType instanceof ghidra.program.model.data.Enum) {
			ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dataType;
			StringBuilder c = new StringBuilder();
			c.append("enum ").append(enumType.getName()).append(" {\n");
			String[] names = enumType.getNames();
			for (int i = 0; i < names.length; i++) {
				c.append("    ").append(names[i]).append(" = ").append(enumType.getValue(names[i]));
				if (i < names.length - 1)
					c.append(",");
				c.append("\n");
			}
			c.append("};");
			return c.toString();
		} else {
			return "/* " + dataType.getName() + " - size: " + dataType.getLength() + " */";
		}
	}

	/**
	 * Exports a single data type as a JSON object.
	 *
	 * @param dataType The data type to export.
	 * @return A string containing the JSON representation of the data type.
	 */
	private String exportDataTypeAsJson(DataType dataType) {
		StringBuilder json = new StringBuilder();
		json.append("{");
		json.append("\"name\":\"").append(dataType.getName()).append("\",");
		json.append("\"size\":").append(dataType.getLength()).append(",");
		json.append("\"type\":\"").append(dataType.getClass().getSimpleName()).append("\",");
		json.append("\"path\":\"").append(dataType.getPathName()).append("\"");
		json.append("}");
		return json.toString();
	}
}