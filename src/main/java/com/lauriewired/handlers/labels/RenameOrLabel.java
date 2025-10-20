package com.lauriewired.handlers.labels;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.util.Map;

import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for renaming data or creating a label at a specified address.
 * If data is defined at the address, it renames the data; otherwise, it creates a label.
 * Expects 'address' and 'name' parameters in the POST request.
 */
public final class RenameOrLabel extends Handler {
	/**
	 * Constructor for the RenameOrLabel handler.
	 *
	 * @param tool the PluginTool instance
	 */
	public RenameOrLabel(PluginTool tool) {
		super(tool, "/rename_or_label");
	}

	/**
	 * Handles HTTP requests to rename data or create a label at a specified address.
	 * Expects 'address' and 'name' parameters in the POST request.
	 *
	 * @param exchange the HttpExchange object representing the HTTP request and response
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> params = parsePostParams(exchange);
		String address = params.get("address");
		String name = params.get("name");
		String result = renameOrLabel(address, name);
		sendResponse(exchange, result);
	}

	/**
	 * Renames data at the specified address or creates a label if no data is defined.
	 *
	 * @param addressStr the address as a string
	 * @param newName    the new name for the data or label
	 * @return a success message or an error message
	 */
	private String renameOrLabel(String addressStr, String newName) {
        Program program = getCurrentProgram(tool);
        if (program == null) {
            return "Error: No program loaded";
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return "Error: Address is required";
        }

        if (newName == null || newName.isEmpty()) {
            return "Error: Name is required";
        }

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return "Error: Invalid address: " + addressStr;
            }

            Listing listing = program.getListing();
            Data data = listing.getDefinedDataAt(address);

            if (data != null) {
                // Defined data exists - use rename_data logic
                return renameDataAtAddress(addressStr, newName);
            } else {
                // No defined data - use create_label logic
                return createLabel(addressStr, newName);
            }

        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}
