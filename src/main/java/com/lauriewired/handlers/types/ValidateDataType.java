package com.lauriewired.handlers.types;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;

import java.io.IOException;
import java.util.Map;

import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to validate if a data type can be applied at a specific address in
 * the current program.
 * It checks for memory availability, alignment, and existing data conflicts.
 * Expects query parameters:
 * - address: The address to validate (e.g., "0x00400000").
 * - type_name: The name of the data type to validate (e.g., "int", "MyStruct").
 * Returns a detailed validation report.
 */
public final class ValidateDataType extends Handler {
	/**
	 * Constructor for the ValidateDataType handler.
	 *
	 * @param tool The Ghidra plugin tool instance.
	 */
	public ValidateDataType(PluginTool tool) {
		super(tool, "/validate_data_type");
	}

	/**
	 * Handles the HTTP exchange for validating a data type at a given address.
	 * Expects query parameters "address" and "type_name".
	 * Returns a validation report.
	 * 
	 * @param exchange The HTTP exchange object.
	 * @throws IOException If an I/O error occurs.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String address = qparams.get("address");
		String typeName = qparams.get("type_name");

		String result = validateDataType(address, typeName);
		sendResponse(exchange, result);
	}

	/**
	 * Validates if a data type can be applied at a specific address in the current
	 * program.
	 *
	 * @param addressStr The address to validate (e.g., "0x00400000").
	 * @param typeName   The name of the data type to validate (e.g., "int",
	 *                   "MyStruct").
	 * @return A detailed validation report.
	 */
	private String validateDataType(String addressStr, String typeName) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";
		if (addressStr == null || addressStr.isEmpty())
			return "Address is required";
		if (typeName == null || typeName.isEmpty())
			return "Type name is required";

		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			DataTypeManager dtm = program.getDataTypeManager();
			DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);

			if (dataType == null) {
				return "Data type not found: " + typeName;
			}

			StringBuilder result = new StringBuilder();
			result.append("Validation for type '").append(typeName).append("' at address ").append(addressStr)
					.append(":\n\n");

			// Check if memory is available
			Memory memory = program.getMemory();
			int typeSize = dataType.getLength();
			Address endAddr = addr.add(typeSize - 1);

			if (!memory.contains(addr) || !memory.contains(endAddr)) {
				result.append("❌ Memory range not available\n");
				result.append("   Required: ").append(addr).append(" - ").append(endAddr).append("\n");
				return result.toString();
			}

			result.append("✅ Memory range available\n");
			result.append("   Range: ").append(addr).append(" - ").append(endAddr).append(" (").append(typeSize)
					.append(" bytes)\n");

			// Check alignment
			long alignment = dataType.getAlignment();
			if (alignment > 1 && addr.getOffset() % alignment != 0) {
				result.append("⚠️  Alignment warning: Address not aligned to ").append(alignment)
						.append("-byte boundary\n");
			} else {
				result.append("✅ Proper alignment\n");
			}

			// Check if there's existing data
			Data existingData = program.getListing().getDefinedDataAt(addr);
			if (existingData != null) {
				result.append("⚠️  Existing data: ").append(existingData.getDataType().getName()).append("\n");
			} else {
				result.append("✅ No conflicting data\n");
			}

			return result.toString();
		} catch (Exception e) {
			return "Error validating data type: " + e.getMessage();
		}
	}
}