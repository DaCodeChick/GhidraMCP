package com.lauriewired.handlers.structs;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.Msg;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.Map;
import javax.swing.SwingUtilities;

import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class GetFieldAccessContext extends Handler {
	/**
	 * Constructor for the GetFieldAccessContext handler.
	 * 
	 * @param tool The plugin tool instance.
	 */
	public GetFieldAccessContext(PluginTool tool) {
		super(tool, "/get_field_access_context");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, Object> params = parseJsonParams(exchange);
		String structAddress = (String) params.get("struct_address");
		int fieldOffset = parseIntOrDefault(String.valueOf(params.get("field_offset")), 0);
		int numExamples = parseIntOrDefault(String.valueOf(params.get("num_examples")), 5);

		String result = getFieldAccessContext(structAddress, fieldOffset, numExamples);
		sendResponse(exchange, result);
	}

	private String getFieldAccessContext(String structAddressStr, int fieldOffset, int numExamples) {
		// MAJOR FIX #7: Validate input parameters
		if (fieldOffset < 0 || fieldOffset > MAX_FIELD_OFFSET) {
			return "{\"error\": \"Field offset must be between 0 and " + MAX_FIELD_OFFSET + "\"}";
		}
		if (numExamples < 1 || numExamples > MAX_FIELD_EXAMPLES) {
			return "{\"error\": \"numExamples must be between 1 and " + MAX_FIELD_EXAMPLES + "\"}";
		}

		final AtomicReference<String> result = new AtomicReference<>();

		// CRITICAL FIX #1: Thread safety - wrap in SwingUtilities.invokeAndWait
		try {
			SwingUtilities.invokeAndWait(() -> {
				try {
					Program program = getCurrentProgram();
					if (program == null) {
						result.set("{\"error\": \"No program loaded\"}");
						return;
					}

					Address structAddr = program.getAddressFactory().getAddress(structAddressStr);
					if (structAddr == null) {
						result.set("{\"error\": \"Invalid address: " + structAddressStr + "\"}");
						return;
					}

					// Calculate field address with overflow protection
					Address fieldAddr;
					try {
						fieldAddr = structAddr.add(fieldOffset);
					} catch (Exception e) {
						result.set("{\"error\": \"Field offset overflow: " + fieldOffset + "\"}");
						return;
					}

					Msg.info(this, "Getting field access context for " + fieldAddr + " (offset " + fieldOffset + ")");

					// Get xrefs to the field address (or nearby addresses)
					ReferenceManager refMgr = program.getReferenceManager();
					ReferenceIterator refIter = refMgr.getReferencesTo(fieldAddr);

					StringBuilder json = new StringBuilder();
					json.append("{");
					json.append("\"struct_address\": \"").append(structAddressStr).append("\",");
					json.append("\"field_offset\": ").append(fieldOffset).append(",");
					json.append("\"field_address\": \"").append(fieldAddr.toString()).append("\",");
					json.append("\"examples\": [");

					int exampleCount = 0;
					boolean first = true;

					while (refIter.hasNext() && exampleCount < numExamples) {
						Reference ref = refIter.next();
						Address fromAddr = ref.getFromAddress();

						if (!first) json.append(",");
						first = false;

						json.append("{");
						json.append("\"access_address\": \"").append(fromAddr.toString()).append("\",");
						json.append("\"ref_type\": \"").append(ref.getReferenceType().getName()).append("\",");

						// Get assembly context with null check
						Listing listing = program.getListing();
						Instruction instr = listing.getInstructionAt(fromAddr);
						if (instr != null) {
							json.append("\"assembly\": \"").append(escapeJson(instr.toString())).append("\",");
						} else {
							json.append("\"assembly\": \"\",");
						}

						// Get function context with null check
						Function func = program.getFunctionManager().getFunctionContaining(fromAddr);
						if (func != null) {
							json.append("\"function_name\": \"").append(escapeJson(func.getName())).append("\",");
							json.append("\"function_address\": \"").append(func.getEntryPoint().toString()).append("\"");
						} else {
							json.append("\"function_name\": \"\",");
							json.append("\"function_address\": \"\"");
						}

						json.append("}");
						exampleCount++;
					}

					json.append("]");
					json.append("}");

					Msg.info(this, "Found " + exampleCount + " field access examples");
					result.set(json.toString());

				} catch (Exception e) {
					Msg.error(this, "Error in getFieldAccessContext", e);
					result.set("{\"error\": \"" + escapeJson(e.getMessage()) + "\"}");
				}
			});
		} catch (InvocationTargetException | InterruptedException e) {
			Msg.error(this, "Thread synchronization error in getFieldAccessContext", e);
			return "{\"error\": \"Thread synchronization error: " + escapeJson(e.getMessage()) + "\"}";
		}

		return result.get();
	}
}
