package com.lauriewired.handlers.set;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

import java.io.IOException;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.parsePostParams;
import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/** Handler for renaming labels in a function */
public final class RenameLabel extends Handler {
	/**
	 * Constructor for the RenameLabel handler.
	 *
	 * @param tool the PluginTool instance
	 */
	public RenameLabel(PluginTool tool) {
		super(tool, "/rename_label");
	}

	/**
	 * Handles HTTP POST request to rename a label in a function.
	 *
	 * Expects the following parameters in the request body:
	 * - address: The address of the function containing the label.
	 * - oldName: The current name of the label to be renamed.
	 * - newName: The new name for the label.
	 * 
	 * @param exchange the HttpExchange object
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> params = parsePostParams(exchange);
		String address = params.get("address");
		String oldName = params.get("oldName");
		String newName = params.get("newName");
		String result = renameLabel(address, oldName, newName);
		sendResponse(exchange, result);
	}

	/**
	 * Renames a label at a specified address in the current program.
	 *
	 * @param addressStr The address of the label to rename.
	 * @param oldName    The current name of the label.
	 * @param newName    The new name for the label.
	 * @return A message indicating success or failure of the operation.
	 */
	private String renameLabel(String addressStr, String oldName, String newName) {
		Program program = getCurrentProgram();
		if (program == null) {
			return "No program loaded";
		}

		try {
			Address address = program.getAddressFactory().getAddress(addressStr);
			if (address == null) {
				return "Invalid address: " + addressStr;
			}

			SymbolTable symbolTable = program.getSymbolTable();
			Symbol[] symbols = symbolTable.getSymbols(address);

			// Find the specific symbol with the old name
			Symbol targetSymbol = null;
			for (Symbol symbol : symbols) {
				if (symbol.getName().equals(oldName) && symbol.getSymbolType() == SymbolType.LABEL) {
					targetSymbol = symbol;
					break;
				}
			}

			if (targetSymbol == null) {
				return "Label not found: " + oldName + " at address " + addressStr;
			}

			// Check if new name already exists at this address
			for (Symbol symbol : symbols) {
				if (symbol.getName().equals(newName) && symbol.getSymbolType() == SymbolType.LABEL) {
					return "Label with name '" + newName + "' already exists at address " + addressStr;
				}
			}

			// Perform the rename
			int transactionId = program.startTransaction("Rename Label");
			try {
				targetSymbol.setName(newName, SourceType.USER_DEFINED);
				return "Successfully renamed label from '" + oldName + "' to '" + newName + "' at address "
						+ addressStr;
			} catch (Exception e) {
				return "Error renaming label: " + e.getMessage();
			} finally {
				program.endTransaction(transactionId, true);
			}

		} catch (Exception e) {
			return "Error processing request: " + e.getMessage();
		}
	}
}
