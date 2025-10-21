package com.lauriewired.handlers.functions;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.app.decompiler.ConsoleTaskMonitor;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompInterface;
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

public final class ForceDecompile extends Handler {
	/**
	 * Constructor for the ForceDecompile handler.
	 * 
	 * @param tool The plugin tool instance.
	 */
	public ForceDecompile(PluginTool tool) {
		super(tool, "/force_decompile");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> params = parsePostParams(exchange);
		String functionAddress = params.get("function_address");

		if (functionAddress == null || functionAddress.isEmpty()) {
			sendResponse(exchange, "Error: function_address parameter is required");
			return;
		}

		String result = forceDecompile(functionAddress);
		sendResponse(exchange, result);
	}

	/**
	 * Forces the decompilation of a function at the specified address.
	 * @param functionAddrStr The address of the function to decompile.
	 * @return A message indicating success or failure.
	 */
	private String forceDecompile(String functionAddrStr) {
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
				try {
					Address addr = program.getAddressFactory().getAddress(functionAddrStr);
					if (addr == null) {
						resultMsg.append("Error: Invalid function address: ").append(functionAddrStr);
						return;
					}

					Function func = program.getFunctionManager().getFunctionAt(addr);
					if (func == null) {
						resultMsg.append("Error: No function found at address ").append(functionAddrStr);
						return;
					}

					// Create new decompiler interface
					DecompInterface decompiler = new DecompInterface();
					decompiler.openProgram(program);

					try {
						// Force a fresh decompilation
						decompiler.setSimplificationStyle("normalize");
						DecompileResults results = decompiler.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, new ConsoleTaskMonitor());

						if (results == null || !results.decompileCompleted()) {
							resultMsg.append("Error: Decompilation failed for function ").append(func.getName());
							return;
						}

						// Get the decompiled C code
						String decompiledCode = results.getDecompiledFunction().getC();

						success.set(true);
						resultMsg.append("Success: Forced redecompilation of ").append(func.getName()).append("\n\n");
						resultMsg.append(decompiledCode);

						Msg.info(this, "Forced decompilation for function: " + func.getName());

					} finally {
						decompiler.dispose();
					}

				} catch (Exception e) {
					resultMsg.append("Error: ").append(e.getMessage());
					Msg.error(this, "Error forcing decompilation", e);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			resultMsg.append("Error: Failed to execute on Swing thread: ").append(e.getMessage());
			Msg.error(this, "Failed to execute force decompile on Swing thread", e);
		}

		return resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure";
	}
}
