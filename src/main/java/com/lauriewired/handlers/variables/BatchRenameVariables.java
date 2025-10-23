package com.lauriewired.handlers.variables;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;

import java.io.IOException;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicBoolean;;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.List;
import java.util.Map;
import javax.swing.*;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class BatchRenameVariables extends Handler {
	/**
	 * Constructor for the BatchRenameVariables handler.
	 *
	 * @param tool the PluginTool instance
	 */
	public BatchRenameVariables(PluginTool tool) {
		super(tool, "/batch_rename_variables");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, Object> params = parseJsonParams(exchange);
		String functionAddress = (String) params.get("function_address");
		@SuppressWarnings("unchecked")
		Map<String, String> variableRenames = (Map<String, String>) params.get("variable_renames");

		String result = batchRenameVariables(functionAddress, variableRenames);
		sendResponse(exchange, result);
	}

	/**
	 * Batch renames variables in a function based on the provided mapping.
	 *
	 * @param functionAddress the address of the function
	 * @param variableRenames a map of current variable names to new variable names
	 * @return a JSON string indicating success or failure and details
	 */
	private String batchRenameVariables(String functionAddress, Map<String, String> variableRenames) {
		Program program = getCurrentProgram(tool);
		if (program == null) {
			return "{\"error\": \"No program loaded\"}";
		}

		final StringBuilder result = new StringBuilder();
		result.append("{");
		final AtomicBoolean success = new AtomicBoolean(false);
		final AtomicInteger variablesRenamed = new AtomicInteger(0);
		final AtomicInteger variablesFailed = new AtomicInteger(0);
		final List<String> errors = new ArrayList<>();

		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Batch Rename Variables");
				// Suppress events during batch operation to prevent re-analysis on each rename
				int eventTx = program.startTransaction("Suppress Events");
				program.flushEvents();  // Flush any pending events before we start
				
				try {
					Address addr = program.getAddressFactory().getAddress(functionAddress);
					if (addr == null) {
						result.append("\"error\": \"Invalid address: ").append(functionAddress).append("\"");
						return;
					}

					Function func = program.getFunctionManager().getFunctionAt(addr);
					if (func == null) {
						result.append("\"error\": \"No function at address: ").append(functionAddress).append("\"");
						return;
					}

					if (variableRenames != null && !variableRenames.isEmpty()) {
						// Rename parameters (events suppressed - no re-analysis per rename)
						for (Parameter param : func.getParameters()) {
							String newName = variableRenames.get(param.getName());
							if (newName != null && !newName.isEmpty()) {
								try {
									param.setName(newName, SourceType.USER_DEFINED);
									variablesRenamed.incrementAndGet();
								} catch (Exception e) {
									variablesFailed.incrementAndGet();
									errors.add("Failed to rename " + param.getName() + " to " + newName + ": " + e.getMessage());
								}
							}
						}

						// Rename local variables (events suppressed - no re-analysis per rename)
						for (Variable local : func.getLocalVariables()) {
							String newName = variableRenames.get(local.getName());
							if (newName != null && !newName.isEmpty()) {
								try {
									local.setName(newName, SourceType.USER_DEFINED);
									variablesRenamed.incrementAndGet();
								} catch (Exception e) {
									variablesFailed.incrementAndGet();
									errors.add("Failed to rename " + local.getName() + " to " + newName + ": " + e.getMessage());
								}
							}
						}
					}

					success.set(true);
				} catch (Exception e) {
					result.append("\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\"");
					Msg.error(this, "Error in batch rename variables", e);
				} finally {
					// End event suppression transaction - this triggers ONE re-analysis for all renames
					program.endTransaction(eventTx, success.get());
					program.flushEvents();  // Force event processing now that we're done
					program.endTransaction(tx, success.get());
				}
			});

			if (success.get()) {
				result.append("\"success\": true, ");
				result.append("\"variables_renamed\": ").append(variablesRenamed.get()).append(", ");
				result.append("\"variables_failed\": ").append(variablesFailed.get());
				if (!errors.isEmpty()) {
					result.append(", \"errors\": [");
					for (int i = 0; i < errors.size(); i++) {
						if (i > 0) result.append(", ");
						result.append("\"").append(errors.get(i).replace("\"", "\\\"")).append("\"");
					}
					result.append("]");
				}
			}
		} catch (Exception e) {
			result.append("\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\"");
		}

		result.append("}");
		return result.toString();
	}
}
