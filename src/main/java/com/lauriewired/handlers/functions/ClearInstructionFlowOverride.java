package com.lauriewired.handlers.functions;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.List;
import java.util.Map;
import javax.swing.*;

import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class ClearInstructionFlowOverride extends Handler {
	/**
	 * Constructor for the ClearInstructionFlowOverride handler.
	 * 
	 * @param tool The plugin tool instance.
	 */
	public ClearInstructionFlowOverride(PluginTool tool) {
		super(tool, "/clear_instruction_flow_override");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> params = parsePostParams(exchange);
		String instructionAddress = params.get("address");

		if (instructionAddress == null || instructionAddress.isEmpty()) {
			sendResponse(exchange, "Error: address parameter is required");
			return;
		}

		String result = clearInstructionFlowOverride(instructionAddress);
		sendResponse(exchange, result);
	}

	/**
	 * Clears the instruction flow override at the specified address.
	 * 
	 * @param instructionAddrStr The instruction address as a string.
	 * @return A result message indicating success or failure.
	 */
	private String clearInstructionFlowOverride(String instructionAddrStr) {
		// Input validation
		Program program = getCurrentProgram(tool);
		if (program == null) {
			return "Error: No program loaded";
		}

		if (instructionAddrStr == null || instructionAddrStr.isEmpty()) {
			return "Error: Instruction address is required";
		}

		final StringBuilder resultMsg = new StringBuilder();
		final AtomicBoolean success = new AtomicBoolean(false);

		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Clear instruction flow override");
				try {
					Address addr = program.getAddressFactory().getAddress(instructionAddrStr);
					if (addr == null) {
						resultMsg.append("Error: Invalid address: ").append(instructionAddrStr);
						return;
					}

					// Get the instruction at the address
					Listing listing = program.getListing();
					ghidra.program.model.listing.Instruction instruction = listing.getInstructionAt(addr);

					if (instruction == null) {
						resultMsg.append("Error: No instruction found at address ").append(instructionAddrStr);
						return;
					}

					// Get the current flow override type (if any)
					ghidra.program.model.listing.FlowOverride oldOverride = instruction.getFlowOverride();

					// Clear the flow override by setting to NONE
					instruction.setFlowOverride(ghidra.program.model.listing.FlowOverride.NONE);

					success.set(true);
					resultMsg.append("Success: Cleared flow override at ").append(instructionAddrStr);
					resultMsg.append(" (was: ").append(oldOverride.toString()).append(", now: NONE)");

					// Get the instruction's mnemonic for logging
					String mnemonic = instruction.getMnemonicString();
					Msg.info(this, "Cleared flow override for instruction '" + mnemonic + "' at " + instructionAddrStr +
							 " (previous override: " + oldOverride + ")");

				} catch (Exception e) {
					resultMsg.append("Error: ").append(e.getMessage());
					Msg.error(this, "Error clearing instruction flow override", e);
				} finally {
					program.endTransaction(tx, success.get());
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			resultMsg.append("Error: Failed to execute on Swing thread: ").append(e.getMessage());
			Msg.error(this, "Failed to execute clear flow override on Swing thread", e);
		}

		return resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure";
	}
}
