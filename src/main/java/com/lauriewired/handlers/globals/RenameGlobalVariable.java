package com.lauriewired.handlers.globals;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to rename a global variable in the current program.
 * Accepts POST requests with 'old_name' and 'new_name' parameters.
 * Responds with success or failure message.
 */
public final class RenameGlobalVariable extends Handler {
	/**
	 * Constructs a new RenameGlobalVariable handler.
	 *
	 * @param tool the PluginTool instance to use for program access
	 */
	public RenameGlobalVariable(PluginTool tool) {
		super(tool, "/rename_global_variable");
	}

	/**
	 * Handles the HTTP exchange to rename a global variable.
	 * Expects 'old_name' and 'new_name' parameters in the POST request body.
	 * Renames the variable if found and responds with success or failure message.
	 * 
	 * @param exchange the HttpExchange object representing the request and response
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> params = parsePostParams(exchange);
		String oldName = params.get("old_name");
		String newName = params.get("new_name");
		String result = renameGlobalVariable(oldName, newName);
		sendResponse(exchange, result);
	}

	/**
	 * Renames a global variable in the current program.
	 *
	 * @param oldName the current name of the global variable
	 * @param newName the new name to assign to the global variable
	 * @return true if the variable was renamed successfully, false otherwise
	 */
	private boolean renameGlobalVariable(String oldName, String newName) {
		Program program = getCurrentProgram(tool);
		if (program == null) {
			return false;
		}

		if (oldName == null || oldName.isEmpty() || newName == null || newName.isEmpty()) {
			return false;
		}

		int txId = program.startTransaction("Rename Global Variable");
		try {
			SymbolTable symbolTable = program.getSymbolTable();

			// Find the symbol by name in global namespace
			Namespace globalNamespace = program.getGlobalNamespace();
			List<Symbol> symbols = symbolTable.getSymbols(oldName, globalNamespace);

			if (symbols.isEmpty()) {
				// Try finding in any namespace
				SymbolIterator allSymbols = symbolTable.getSymbols(oldName);
				while (allSymbols.hasNext()) {
					Symbol symbol = allSymbols.next();
					if (symbol.getSymbolType() != SymbolType.FUNCTION) {
						symbols.add(symbol);
						break; // Take the first non-function match
					}
				}
			}

			if (symbols.isEmpty()) {
				program.endTransaction(txId, false);
				return false;
			}

			// Rename the first matching symbol
			Symbol symbol = symbols.get(0);
			symbol.setName(newName, SourceType.USER_DEFINED);

			program.endTransaction(txId, true);
			return true;

		} catch (Exception e) {
			program.endTransaction(txId, false);
			Msg.error(this, "Error renaming global variable: " + e.getMessage());
			return false;
		}
	}
}
