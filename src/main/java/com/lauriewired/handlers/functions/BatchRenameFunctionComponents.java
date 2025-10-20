package com.lauriewired.handlers.functions;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Variable;
import ghidra.util.Msg;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.Map;
import javax.swing.*;

import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class BatchRenameFunctionComponents extends Handler {
	/**
	 * Constructor for the BatchRenameFunctionComponents handler.
	 * 
	 * @param tool The plugin tool instance.
	 */
	public BatchRenameFunctionComponents(PluginTool tool) {
		super(tool, "/batch_rename_function_components");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, Object> params = parseJsonParams(exchange);
		String functionAddress = (String) params.get("function_address");
		String functionName = (String) params.get("function_name");
		@SuppressWarnings("unchecked")
		Map<String, String> parameterRenames = (Map<String, String>) params.get("parameter_renames");
		@SuppressWarnings("unchecked")
		Map<String, String> localRenames = (Map<String, String>) params.get("local_renames");
		String returnType = (String) params.get("return_type");

		String result = batchRenameFunctionComponents(functionAddress, functionName, parameterRenames, localRenames, returnType);
		sendResponse(exchange, result);
	}

	/**
	 * Batch renames function components including the function name, parameters,
	 * local variables, and return type.
	 * 
	 * @param functionAddress   The address of the function to rename components for.
	 * @param functionName      The new name for the function.
	 * @param parameterRenames  A map of current parameter names to new names.
	 * @param localRenames      A map of current local variable names to new names.
	 * @param returnType        The new return type for the function.
	 * @return A JSON string indicating success or failure and details of the renaming.
	 */
	@SuppressWarnings("deprecation")
	private String batchRenameFunctionComponents(String functionAddress, String functionName,
												Map<String, String> parameterRenames,
												Map<String, String> localRenames,
												String returnType) {
		Program program = getCurrentProgram(tool);
		if (program == null) {
			return "{\"error\": \"No program loaded\"}";
		}

		final StringBuilder result = new StringBuilder();
		result.append("{");
		final AtomicBoolean success = new AtomicBoolean(false);
		final AtomicReference<Integer> paramsRenamed = new AtomicReference<>(0);
		final AtomicReference<Integer> localsRenamed = new AtomicReference<>(0);

		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Batch Rename Function Components");
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

					// Rename function
					if (functionName != null && !functionName.isEmpty()) {
						func.setName(functionName, SourceType.USER_DEFINED);
					}

					// Rename parameters
					if (parameterRenames != null && !parameterRenames.isEmpty()) {
						Parameter[] params = func.getParameters();
						for (Parameter param : params) {
							String newName = parameterRenames.get(param.getName());
							if (newName != null && !newName.isEmpty()) {
								param.setName(newName, SourceType.USER_DEFINED);
								paramsRenamed.getAndSet(paramsRenamed.get() + 1);
							}
						}
					}

					// Rename local variables
					if (localRenames != null && !localRenames.isEmpty()) {
						Variable[] locals = func.getLocalVariables();
						for (Variable local : locals) {
							String newName = localRenames.get(local.getName());
							if (newName != null && !newName.isEmpty()) {
								local.setName(newName, SourceType.USER_DEFINED);
								localsRenamed.getAndSet(localsRenamed.get() + 1);
							}
						}
					}

					// Set return type if provided
					if (returnType != null && !returnType.isEmpty()) {
						DataTypeManager dtm = program.getDataTypeManager();
						DataType dt = dtm.getDataType(returnType);
						if (dt != null) {
							func.setReturnType(dt, SourceType.USER_DEFINED);
						}
					}

					success.set(true);
				} catch (Exception e) {
					result.append("\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\"");
					Msg.error(this, "Error in batch rename", e);
				} finally {
					program.endTransaction(tx, success.get());
				}
			});

			if (success.get()) {
				result.append("\"success\": true, ");
				result.append("\"function_renamed\": ").append(functionName != null).append(", ");
				result.append("\"parameters_renamed\": ").append(paramsRenamed.get()).append(", ");
				result.append("\"locals_renamed\": ").append(localsRenamed.get());
			}
		} catch (Exception e) {
			result.append("\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\"");
		}

		result.append("}");
		return result.toString();
	}
}
