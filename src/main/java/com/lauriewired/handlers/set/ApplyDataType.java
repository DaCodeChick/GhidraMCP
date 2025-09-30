package com.lauriewired.handlers.set;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.util.Map;

import static com.lauriewired.util.GhidraUtils.resolveDataType;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to set a data type at a specified address in the current program.
 * Expects JSON parameters:
 * - address: The address to set the data type at (required)
 * - type_name: The name of the data type to apply (required)
 * - clear_existing: Whether to clear existing code/data at the address
 * (optional, default: true)
 */
public final class ApplyDataType extends Handler {
	/**
	 * Constructor for the ApplyDataType handler.
	 * 
	 * @param tool The plugin tool instance.
	 */
	public ApplyDataType(PluginTool tool) {
		super(tool, "/apply_data_type", "/set_global_data_type");
	}

	/**
	 * Handles the HTTP exchange to set a data type at a specified address.
	 * Expects JSON parameters:
	 * - address: The address to set the data type at (required)
	 * - type_name: The name of the data type to apply (required)
	 * - clear_existing: Whether to clear existing code/data at the address
	 * (optional, default: true)
	 * 
	 * @param exchange The HTTP exchange object.
	 * @throws IOException If an I/O error occurs.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, Object> params = parseJsonParams(exchange);
		String address = (String) params.get("address");
		String typeName = (String) params.get("type_name");
		Object clearObj = params.get("clear_existing");
		boolean clearExisting = (clearObj instanceof Boolean) ? (Boolean) clearObj
				: Boolean.parseBoolean(clearObj != null ? clearObj.toString() : "true");
		sendResponse(exchange, applyDataType(address, typeName, clearExisting));
	}

	/**
	 * Applies the specified data type at the given address in the current program.
	 * 
	 * @param addressStr    The address to set the data type at.
	 * @param typeName      The name of the data type to apply.
	 * @param clearExisting Whether to clear existing code/data at the address.
	 * @return A message indicating the result of the operation.
	 */
	private String applyDataType(String addressStr, String typeName, boolean clearExisting) {
		Program program = getCurrentProgram(tool);
		if (program == null) {
			return "No program loaded";
		}

		if (addressStr == null || addressStr.isEmpty()) {
			return "Address is required";
		}

		if (typeName == null || typeName.isEmpty()) {
			return "Data type name is required";
		}

		try {
			Address address = program.getAddressFactory().getAddress(addressStr);
			if (address == null) {
				return "Invalid address: " + addressStr;
			}

			DataTypeManager dtm = program.getDataTypeManager();
			DataType dataType = resolveDataType(tool, dtm, typeName);

			if (dataType == null) {
				return "Unknown data type: " + typeName;
			}

			Listing listing = program.getListing();

			// Check if address is in a valid memory block
			if (!program.getMemory().contains(address)) {
				return "Address is not in program memory: " + addressStr;
			}

			int txId = program.startTransaction("Apply Data Type: " + typeName);
			try {
				// Clear existing code/data if requested
				if (clearExisting) {
					CodeUnit existingCU = listing.getCodeUnitAt(address);
					if (existingCU != null) {
						listing.clearCodeUnits(address,
								address.add(Math.max(dataType.getLength() - 1, 0)), false);
					}
				}

				// Apply the data type
				Data data = listing.createData(address, dataType);

				program.endTransaction(txId, true);

				String result = "Successfully applied data type '" + typeName + "' at " +
						addressStr + " (size: " + dataType.getLength() + " bytes)";

				// Add value information if available
				if (data != null && data.getValue() != null) {
					result += "\nValue: " + data.getValue().toString();
				}

				return result;

			} catch (Exception e) {
				program.endTransaction(txId, false);
				return "Error applying data type: " + e.getMessage();
			}

		} catch (Exception e) {
			return "Error processing request: " + e.getMessage();
		}
	}
}
