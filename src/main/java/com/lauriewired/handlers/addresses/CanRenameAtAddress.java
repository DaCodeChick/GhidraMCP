package com.lauriewired.handlers.addresses;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.Map;
import javax.swing.*;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class CanRenameAtAddress extends Handler {
	/**
	 * Constructs a new CanRenameAtAddress handler.
	 *
	 * @param tool the PluginTool instance to use for program access
	 */
	public CanRenameAtAddress(PluginTool tool) {
		super(tool, "/can_rename_at_address");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String address = qparams.get("address");

		String result = canRenameAtAddress(address);
		sendResponse(exchange, result);
	}

	/**
	 * Determines if a rename operation can be performed at the specified address.
	 *
	 * @param addressStr the address as a string
	 * @return a JSON string indicating whether renaming is possible and relevant details
	 */
	private String canRenameAtAddress(String addressStr) {
		Program program = getCurrentProgram(tool);
		if (program == null) {
			return "{\"error\": \"No program loaded\"}";
		}

		final StringBuilder result = new StringBuilder();
		final AtomicReference<String> errorMsg = new AtomicReference<>(null);

		try {
			SwingUtilities.invokeAndWait(() -> {
				try {
					Address addr = program.getAddressFactory().getAddress(addressStr);
					if (addr == null) {
						result.append("{\"can_rename\": false, \"error\": \"Invalid address\"}");
						return;
					}

					result.append("{\"can_rename\": true");

					// Check if it's a function
					Function func = program.getFunctionManager().getFunctionAt(addr);
					if (func != null) {
						result.append(", \"type\": \"function\"");
						result.append(", \"suggested_operation\": \"rename_function\"");
						result.append(", \"current_name\": \"").append(func.getName()).append("\"");
						result.append("}");
						return;
					}

					// Check if it's defined data
					Data data = program.getListing().getDefinedDataAt(addr);
					if (data != null) {
						result.append(", \"type\": \"defined_data\"");
						result.append(", \"suggested_operation\": \"rename_data\"");
						Symbol symbol = program.getSymbolTable().getPrimarySymbol(addr);
						if (symbol != null) {
							result.append(", \"current_name\": \"").append(symbol.getName()).append("\"");
						}
						result.append("}");
						return;
					}

					// Check if it's undefined (can create label)
					result.append(", \"type\": \"undefined\"");
					result.append(", \"suggested_operation\": \"create_label\"");
					result.append("}");
				} catch (Exception e) {
					errorMsg.set(e.getMessage());
				}
			});

			if (errorMsg.get() != null) {
				return "{\"error\": \"" + errorMsg.get().replace("\"", "\\\"") + "\"}";
			}
		} catch (Exception e) {
			return "{\"error\": \"" + e.getMessage().replace("\"", "\\\"") + "\"}";
		}

		return result.toString();
	}
}
