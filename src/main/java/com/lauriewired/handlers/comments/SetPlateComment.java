package com.lauriewired.handlers.comments;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.Map;
import javax.swing.SwingUtilities;

import static com.lauriewired.util.ParseUtils.*;

public final class SetPlateComment extends Handler {
	/**
	 * Constructor for the SetPlateComment handler
	 * 
	 * @param tool The Ghidra PluginTool instance
	 */
	public SetPlateComment(PluginTool tool) {
		super(tool, "/set_plate_comment");
	}

	@Override
	public void handle(HttpExchange exchange) throws Exception {
		Map<String, String> params = parsePostParams(exchange);
		String functionAddress = params.get("function_address");
		String comment = params.get("comment");

		String result = setPlateComment(functionAddress, comment);
		sendResponse(exchange, result);
	}

	/**
	 * Sets the plate comment for a function at the specified address
	 * 
	 * @param functionAddress The address of the function
	 * @param comment The comment to set
	 * @return A result message indicating success or failure
	 */
	@SuppressWarnings("deprecation")
	private String setPlateComment(String functionAddress, String comment) {
		Program program = getCurrentProgram();
		if (program == null) {
			return "Error: No program loaded";
		}

		if (functionAddress == null || functionAddress.isEmpty()) {
			return "Error: Function address is required";
		}

		if (comment == null) {
			return "Error: Comment is required";
		}

		final StringBuilder resultMsg = new StringBuilder();
		final AtomicBoolean success = new AtomicBoolean(false);

		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Set Plate Comment");
				try {
					Address addr = program.getAddressFactory().getAddress(functionAddress);
					if (addr == null) {
						resultMsg.append("Error: Invalid address: ").append(functionAddress);
						return;
					}

					Function func = program.getFunctionManager().getFunctionAt(addr);
					if (func == null) {
						resultMsg.append("Error: No function at address: ").append(functionAddress);
						return;
					}

					func.setComment(comment);
					success.set(true);
					resultMsg.append("Success: Set plate comment for function at ").append(functionAddress);
				} catch (Exception e) {
					resultMsg.append("Error: ").append(e.getMessage());
					Msg.error(this, "Error setting plate comment", e);
				} finally {
					program.endTransaction(tx, success.get());
				}
			});

			// Force event processing to ensure changes propagate to decompiler cache
			if (success.get()) {
				program.flushEvents();
				// Small delay to ensure decompiler cache refresh
				try {
					Thread.sleep(50);
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
				}
			}
		} catch (Exception e) {
			resultMsg.append("Error: Failed to execute on Swing thread: ").append(e.getMessage());
		}

		return resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure";
	}
}
