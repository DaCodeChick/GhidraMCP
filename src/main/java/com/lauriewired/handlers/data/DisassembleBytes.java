package com.lauriewired.handlers.data;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.Map;
import javax.swing.SwingUtilities;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class DisassembleBytes extends Handler {
	/**
	 * Constructor for the DisassembleBytes handler.
	 * 
	 * @param tool The PluginTool instance to use.
	 */
	public DisassembleBytes(PluginTool tool) {
		super(tool, "/disassemble_bytes");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, Object> params = parseJsonParams(exchange);
		String startAddress = (String) params.get("start_address");
		String endAddress = (String) params.get("end_address");
		Integer length = params.get("length") != null ? ((Number) params.get("length")).intValue() : null;
		boolean restrictToExecuteMemory = params.get("restrict_to_execute_memory") != null ?
			(Boolean) params.get("restrict_to_execute_memory") : true;

		String result = disassembleBytes(startAddress, endAddress, length, restrictToExecuteMemory);
		sendResponse(exchange, result);
	}

	private String disassembleBytes(String startAddress, String endAddress, Integer length,
								   boolean restrictToExecuteMemory) {
		Program program = getCurrentProgram(tool);
		if (program == null) {
			return "{\"error\": \"No program loaded\"}";
		}

		if (startAddress == null || startAddress.isEmpty()) {
			return "{\"error\": \"start_address parameter required\"}";
		}

		final StringBuilder result = new StringBuilder();
		final AtomicReference<String> errorMsg = new AtomicReference<>();

		try {
			Msg.debug(this, "disassembleBytes: Starting disassembly at " + startAddress +
					 (length != null ? " with length " + length : "") +
					 (endAddress != null ? " to " + endAddress : ""));

			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Disassemble Bytes");
				boolean success = false;

				try {
					// Parse start address
					Address start = program.getAddressFactory().getAddress(startAddress);
					if (start == null) {
						errorMsg.set("Invalid start address: " + startAddress);
						return;
					}

					// Determine end address
					Address end;
					if (endAddress != null && !endAddress.isEmpty()) {
						// Use explicit end address (exclusive)
						end = program.getAddressFactory().getAddress(endAddress);
						if (end == null) {
							errorMsg.set("Invalid end address: " + endAddress);
							return;
						}
						// Make end address inclusive for AddressSet
						try {
							end = end.subtract(1);
						} catch (Exception e) {
							errorMsg.set("End address calculation failed: " + e.getMessage());
							return;
						}
					} else if (length != null && length > 0) {
						// Use length to calculate end address
						try {
							end = start.add(length - 1);
						} catch (Exception e) {
							errorMsg.set("End address calculation from length failed: " + e.getMessage());
							return;
						}
					} else {
						// Auto-detect length (scan until we hit existing code/data)
						Listing listing = program.getListing();
						Address current = start;
						int maxBytes = 100; // Safety limit
						int count = 0;

						while (count < maxBytes) {
							CodeUnit cu = listing.getCodeUnitAt(current);

							// Stop if we hit an existing instruction
							if (cu instanceof Instruction) {
								break;
							}

							// Stop if we hit defined data
							if (cu instanceof Data && ((Data) cu).isDefined()) {
								break;
							}

							count++;
							try {
								current = current.add(1);
							} catch (Exception e) {
								break;
							}
						}

						if (count == 0) {
							errorMsg.set("No undefined bytes found at address (already disassembled or defined data)");
							return;
						}

						// end is now one past the last undefined byte
						try {
							end = current.subtract(1);
						} catch (Exception e) {
							end = current;
						}
					}

					// Create address set
					AddressSet addressSet = new AddressSet(start, end);
					long numBytes = addressSet.getNumAddresses();

					// Execute disassembly
					ghidra.app.cmd.disassemble.DisassembleCommand cmd =
						new ghidra.app.cmd.disassemble.DisassembleCommand(addressSet, null, restrictToExecuteMemory);

					// Prevent auto-analysis cascade
					cmd.setSeedContext(null);
					cmd.setInitialContext(null);

					if (cmd.applyTo(program, ghidra.util.task.TaskMonitor.DUMMY)) {
						// Success - build result
						Msg.debug(this, "disassembleBytes: Successfully disassembled " + numBytes + " byte(s) from " + start + " to " + end);
						result.append("{");
						result.append("\"success\": true, ");
						result.append("\"start_address\": \"").append(start).append("\", ");
						result.append("\"end_address\": \"").append(end).append("\", ");
						result.append("\"bytes_disassembled\": ").append(numBytes).append(", ");
						result.append("\"message\": \"Successfully disassembled ").append(numBytes).append(" byte(s)\"");
						result.append("}");
						success = true;
					} else {
						errorMsg.set("Disassembly failed: " + cmd.getStatusMsg());
						Msg.error(this, "disassembleBytes: Disassembly command failed - " + cmd.getStatusMsg());
					}

				} catch (Exception e) {
					errorMsg.set("Exception during disassembly: " + e.getMessage());
					Msg.error(this, "disassembleBytes: Exception during disassembly", e);
				} finally {
					program.endTransaction(tx, success);
				}
			});

			Msg.debug(this, "disassembleBytes: invokeAndWait completed");

			if (errorMsg.get() != null) {
				Msg.error(this, "disassembleBytes: Returning error response - " + errorMsg.get());
				return "{\"error\": \"" + errorMsg.get().replace("\"", "\\\"") + "\"}";
			}
		} catch (Exception e) {
			Msg.error(this, "disassembleBytes: Exception in outer try block", e);
			return "{\"error\": \"" + e.getMessage().replace("\"", "\\\"") + "\"}";
		}

		String response = result.toString();
		Msg.debug(this, "disassembleBytes: Returning success response, length=" + response.length());
		return response;
	}
}
