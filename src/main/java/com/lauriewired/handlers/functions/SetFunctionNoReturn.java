package com.lauriewired.handlers.functions;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.Map;
import javax.swing.*;

import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class SetFunctionNoReturn extends Handler {
	/**
	 * Constructor for the SetFunctionNoReturn handler.
	 * 
	 * @param tool The plugin tool instance.
	 */
	public SetFunctionNoReturn(PluginTool tool) {
		super(tool, "/set_function_no_return");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> params = parsePostParams(exchange);
		String functionAddress = params.get("function_address");
		String noReturnStr = params.get("no_return");

		if (functionAddress == null || functionAddress.isEmpty()) {
			sendResponse(exchange, "Error: function_address parameter is required");
			return;
		}

		// Parse no_return as boolean (default to false if not provided or invalid)
		boolean noReturn = false;
		if (noReturnStr != null && !noReturnStr.isEmpty()) {
			noReturn = Boolean.parseBoolean(noReturnStr);
		}

		String result = setFunctionNoReturn(functionAddress, noReturn);
		sendResponse(exchange, result);
	}

	/**
	 * Sets the no-return attribute of a function at the specified address.
	 * 
	 * @param functionAddrStr The address of the function as a string.
	 * @param noReturn        True to set as non-returning, false otherwise.
	 * @return A message indicating success or failure.
	 */
	private String setFunctionNoReturn(String functionAddrStr, boolean noReturn) {
		// Input validation
		Program program = getCurrentProgram(tool);
		if (program == null) {
			return "Error: No program loaded";
		}

		if (functionAddrStr == null || functionAddrStr.isEmpty()) {
			return "Error: Function address is required";
		}

		final StringBuilder resultMsg = new StringBuilder();
		final AtomicBoolean success = new AtomicBoolean(false);

		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Set function no return");
				try {
					Address addr = program.getAddressFactory().getAddress(functionAddrStr);
					if (addr == null) {
						resultMsg.append("Error: Invalid address: ").append(functionAddrStr);
						return;
					}

					Function func = getFunctionForAddress(program, addr);
					if (func == null) {
						resultMsg.append("Error: No function found at address ").append(functionAddrStr);
						return;
					}

					String oldState = func.hasNoReturn() ? "non-returning" : "returning";

					// Set the no-return attribute
					func.setNoReturn(noReturn);

					String newState = noReturn ? "non-returning" : "returning";
					success.set(true);

					resultMsg.append("Success: Set function '").append(func.getName())
							.append("' at ").append(functionAddrStr)
							.append(" from ").append(oldState)
							.append(" to ").append(newState);

					Msg.info(this, "Set no-return=" + noReturn + " for function " + func.getName() + " at " + functionAddrStr);

				} catch (Exception e) {
					resultMsg.append("Error: ").append(e.getMessage());
					Msg.error(this, "Error setting function no-return attribute", e);
				} finally {
					program.endTransaction(tx, success.get());
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			resultMsg.append("Error: Failed to execute on Swing thread: ").append(e.getMessage());
			Msg.error(this, "Failed to execute set no-return on Swing thread", e);
		}

		return resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure";
	}
}
