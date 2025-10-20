package com.lauriewired.handlers.variables;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.Map;
import javax.swing.*;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class BatchSetVariableTypes extends Handler {
	/**
	 * Constructor for the BatchSetVariableTypes handler.
	 *
	 * @param tool the PluginTool instance
	 */
	public BatchSetVariableTypes(PluginTool tool) {
		super(tool, "/batch_set_variable_types");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, Object> params = parseJsonParams(exchange);
		String functionAddress = (String) params.get("function_address");
		@SuppressWarnings("unchecked")
		Map<String, String> variableTypes = (Map<String, String>) params.get("variable_types");

		String result = batchSetVariableTypes(functionAddress, variableTypes);
		sendResponse(exchange, result);
	}

	/**
	 * Batch sets variable types for parameters and local variables in a function.
	 *
	 * @param functionAddress the address of the function
	 * @param variableTypes   a map of variable names to their new types
	 * @return a JSON string indicating success or failure
	 */
	@SuppressWarnings("deprecation")
	private String batchSetVariableTypes(String functionAddress, Map<String, String> variableTypes) {
		Program program = getCurrentProgram(tool);
		if (program == null) {
			return "{\"error\": \"No program loaded\"}";
		}

		final StringBuilder result = new StringBuilder();
		result.append("{");
		final AtomicBoolean success = new AtomicBoolean(false);
		final AtomicReference<Integer> typesSet = new AtomicReference<>(0);

		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Batch Set Variable Types");
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

					DataTypeManager dtm = program.getDataTypeManager();

					if (variableTypes != null) {
						// Set parameter types
						for (Parameter param : func.getParameters()) {
							String newType = variableTypes.get(param.getName());
							if (newType != null) {
								DataType dt = dtm.getDataType(newType);
								if (dt != null) {
									param.setDataType(dt, SourceType.USER_DEFINED);
									typesSet.getAndSet(typesSet.get() + 1);
								}
							}
						}

						// Set local variable types
						for (Variable local : func.getLocalVariables()) {
							String newType = variableTypes.get(local.getName());
							if (newType != null) {
								DataType dt = dtm.getDataType(newType);
								if (dt != null) {
									local.setDataType(dt, SourceType.USER_DEFINED);
									typesSet.getAndSet(typesSet.get() + 1);
								}
							}
						}
					}

					success.set(true);
				} catch (Exception e) {
					result.append("\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\"");
					Msg.error(this, "Error in batch set variable types", e);
				} finally {
					program.endTransaction(tx, success.get());
				}
			});

			if (success.get()) {
				result.append("\"success\": true, ");
				result.append("\"variables_typed\": ").append(typesSet.get());
			}
		} catch (Exception e) {
			result.append("\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\"");
		}

		result.append("}");
		return result.toString();
	}
}
