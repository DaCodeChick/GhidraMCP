package com.lauriewired.handlers.create;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;

import java.io.IOException;
import java.util.Map;

import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to create a label at a specified address in the current program.
 * Expects POST parameters:
 * - address: The address where the label should be created (e.g.,
 * "0x00400000").
 * - name: The name of the label to create (e.g., "myLabel").
 * 
 * Example POST request body:
 * address=0x00400000&name=myLabel
 */
public final class CreateLabel extends Handler {
	/**
	 * Constructs a new CreateLabel handler.
	 *
	 * @param tool The PluginTool instance to interact with Ghidra.
	 */
	public CreateLabel(PluginTool tool) {
		super(tool, "/create_label");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> params = parsePostParams(exchange);
		String address = params.get("address");
		String name = params.get("name");
		String result = createLabel(address, name);
		sendResponse(exchange, result);
	}

	private String createLabel(String addressStr, String labelName) {
		Program program = getCurrentProgram();
		if (program == null) {
			return "No program loaded";
		}

		if (addressStr == null || addressStr.isEmpty()) {
			return "Address is required";
		}

		if (labelName == null || labelName.isEmpty()) {
			return "Label name is required";
		}

		try {
			Address address = program.getAddressFactory().getAddress(addressStr);
			if (address == null) {
				return "Invalid address: " + addressStr;
			}

			SymbolTable symbolTable = program.getSymbolTable();

			// Check if a label with this name already exists at this address
			Symbol[] existingSymbols = symbolTable.getSymbols(address);
			for (Symbol symbol : existingSymbols) {
				if (symbol.getName().equals(labelName) && symbol.getSymbolType() == SymbolType.LABEL) {
					return "Label '" + labelName + "' already exists at address " + addressStr;
				}
			}

			// Check if the label name is already used elsewhere (optional warning)
			SymbolIterator existingLabels = symbolTable.getSymbolIterator(labelName, true);
			if (existingLabels.hasNext()) {
				Symbol existingSymbol = existingLabels.next();
				if (existingSymbol.getSymbolType() == SymbolType.LABEL) {
					// Allow creation but warn about duplicate name
					Msg.warn(this, "Label name '" + labelName + "' already exists at address " +
							existingSymbol.getAddress() + ". Creating duplicate at " + addressStr);
				}
			}

			// Create the label
			int transactionId = program.startTransaction("Create Label");
			try {
				Symbol newSymbol = symbolTable.createLabel(address, labelName, SourceType.USER_DEFINED);
				if (newSymbol != null) {
					return "Successfully created label '" + labelName + "' at address " + addressStr;
				} else {
					return "Failed to create label '" + labelName + "' at address " + addressStr;
				}
			} catch (Exception e) {
				return "Error creating label: " + e.getMessage();
			} finally {
				program.endTransaction(transactionId, true);
			}

		} catch (Exception e) {
			return "Error processing request: " + e.getMessage();
		}
	}
}
