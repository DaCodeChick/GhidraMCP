package com.lauriewired.handlers.comments;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.List;
import java.util.Map;
import javax.swing.SwingUtilities;

import static com.lauriewired.util.GhidraUtils.getCurrentProgram;
import static com.lauriewired.util.ParseUtils.*;

public final class BatchSetComments extends Handler {
	/**
	 * Constructor for the BatchSetComments handler
	 * 
	 * @param tool The Ghidra PluginTool instance
	 */
	public BatchSetComments(PluginTool tool) {
		super(tool, "/batch_set_comments");
	}

	@Override
	public void handle(HttpExchange exchange) throws Exception {
		Map<String, Object> params = parseJsonParams(exchange);
		String functionAddress = (String) params.get("function_address");

		// Convert List<Object> to List<Map<String, String>>
		List<Map<String, String>> decompilerComments = convertToMapList(params.get("decompiler_comments"));
		List<Map<String, String>> disassemblyComments = convertToMapList(params.get("disassembly_comments"));
		String plateComment = (String) params.get("plate_comment");

		String result = batchSetComments(functionAddress, decompilerComments, disassemblyComments, plateComment);
		sendResponse(exchange, result);
	}

	/**
	 * Batch set comments in the current program
	 * 
	 * @param functionAddress      The address of the function for plate comment
	 * @param decompilerComments   List of decompiler comments to set
	 * @param disassemblyComments  List of disassembly comments to set
	 * @param plateComment         The plate comment to set
	 * @return JSON string with the result of the operation
	 */
	@SuppressWarnings("deprecation")
	private String batchSetComments(String functionAddress, List<Map<String, String>> decompilerComments,
									List<Map<String, String>> disassemblyComments, String plateComment) {
		Program program = getCurrentProgram(tool);
		if (program == null) {
			return "{\"error\": \"No program loaded\"}";
		}

		final StringBuilder result = new StringBuilder();
		result.append("{");
		final AtomicBoolean success = new AtomicBoolean(false);
		final AtomicReference<Integer> decompilerCount = new AtomicReference<>(0);
		final AtomicReference<Integer> disassemblyCount = new AtomicReference<>(0);
		final AtomicReference<Boolean> plateSet = new AtomicReference<>(false);

		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Batch Set Comments");
				try {
					// Set plate comment if provided
					if (plateComment != null && functionAddress != null) {
						Address funcAddr = program.getAddressFactory().getAddress(functionAddress);
						if (funcAddr != null) {
							Function func = program.getFunctionManager().getFunctionAt(funcAddr);
							if (func != null) {
								func.setComment(plateComment);
								plateSet.set(true);
							}
						}
					}

					// Set decompiler comments (PRE_COMMENT)
					if (decompilerComments != null) {
						for (Map<String, String> commentEntry : decompilerComments) {
							String addr = commentEntry.get("address");
							String comment = commentEntry.get("comment");
							if (addr != null && comment != null) {
								Address address = program.getAddressFactory().getAddress(addr);
								if (address != null) {
									program.getListing().setComment(address, CodeUnit.PRE_COMMENT, comment);
									decompilerCount.getAndSet(decompilerCount.get() + 1);
								}
							}
						}
					}

					// Set disassembly comments (EOL_COMMENT)
					if (disassemblyComments != null) {
						for (Map<String, String> commentEntry : disassemblyComments) {
							String addr = commentEntry.get("address");
							String comment = commentEntry.get("comment");
							if (addr != null && comment != null) {
								Address address = program.getAddressFactory().getAddress(addr);
								if (address != null) {
									program.getListing().setComment(address, CodeUnit.EOL_COMMENT, comment);
									disassemblyCount.getAndSet(disassemblyCount.get() + 1);
								}
							}
						}
					}

					success.set(true);
				} catch (Exception e) {
					result.append("\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\"");
					Msg.error(this, "Error in batch set comments", e);
				} finally {
					program.endTransaction(tx, success.get());
				}
			});

			if (success.get()) {
				result.append("\"success\": true, ");
				result.append("\"decompiler_comments_set\": ").append(decompilerCount.get()).append(", ");
				result.append("\"disassembly_comments_set\": ").append(disassemblyCount.get()).append(", ");
				result.append("\"plate_comment_set\": ").append(plateSet.get());
			}
		} catch (Exception e) {
			result.append("\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\"");
		}

		result.append("}");
		return result.toString();
	}
}
