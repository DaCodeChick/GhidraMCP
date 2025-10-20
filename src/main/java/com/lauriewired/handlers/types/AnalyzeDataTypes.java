package com.lauriewired.handlers.types;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to analyze data types at a given address in the current program.
 */
public final class AnalyzeDataTypes extends Handler {
	/**
	 * Constructor for the AnalyzeDataTypes handler.
	 * 
	 * @param tool The PluginTool instance to use.
	 */
	public AnalyzeDataTypes(PluginTool tool) {
		super(tool, "/analyze_data_types");
	}

	/**
	 * Handles the HTTP exchange to analyze data types.
	 * Expects query parameters:
	 * - address: The address to analyze (required).
	 * - depth: The depth of analysis (optional, default is 1).
	 * 
	 * @param exchange The HttpExchange object.
	 * @throws IOException If an I/O error occurs.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String address = qparams.get("address");
		int depth = parseIntOrDefault(qparams.get("depth"), 1);
		sendResponse(exchange, analyzeDataTypes(address, depth));
	}

	/**
	 * Analyzes data types at the specified address in the current program.
	 * 
	 * @param addressStr The address to analyze.
	 * @param depth      The depth of analysis.
	 * @return A string representation of the data type analysis.
	 */
	private String analyzeDataTypes(String addressStr, int depth) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return "No program loaded";
		if (addressStr == null || addressStr.isEmpty())
			return "Address is required";

		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			StringBuilder result = new StringBuilder();

			result.append("Data type analysis at ").append(addressStr).append(" (depth: ").append(depth)
					.append("):\n\n");

			// Analyze the data at the given address
			analyzeDataAtAddress(program, addr, result, depth, 0);

			return result.toString();
		} catch (Exception e) {
			return "Error analyzing data types: " + e.getMessage();
		}
	}

	/**
	 * Recursively analyzes data at the given address and appends results to the
	 * StringBuilder.
	 * 
	 * @param program      The current program.
	 * @param addr         The address to analyze.
	 * @param result       The StringBuilder to append results to.
	 * @param maxDepth     The maximum depth of analysis.
	 * @param currentDepth The current depth of recursion.
	 */
	private void analyzeDataAtAddress(Program program, Address addr, StringBuilder result, int maxDepth,
			int currentDepth) {
		if (currentDepth >= maxDepth)
			return;

		String indent = "  ".repeat(currentDepth);
		Data data = program.getListing().getDefinedDataAt(addr);

		if (data != null) {
			DataType dataType = data.getDataType();
			result.append(indent).append("Address: ").append(addr)
					.append(" | Type: ").append(dataType.getName())
					.append(" | Size: ").append(dataType.getLength())
					.append(" | Value: ").append(data.getDefaultValueRepresentation()).append("\n");

			// If it's a composite type, analyze its components
			if (dataType instanceof Composite) {
				Composite composite = (Composite) dataType;
				for (DataTypeComponent component : composite.getDefinedComponents()) {
					result.append(indent).append("  Component: ").append(component.getFieldName())
							.append(" | Type: ").append(component.getDataType().getName())
							.append(" | Offset: ").append(component.getOffset()).append("\n");
				}
			}

			// If it's a pointer, analyze what it points to
			if (dataType instanceof Pointer && currentDepth < maxDepth - 1) {
				try {
					Address pointedAddr = (Address) data.getValue();
					if (pointedAddr != null) {
						result.append(indent).append("Points to:\n");
						analyzeDataAtAddress(program, pointedAddr, result, maxDepth, currentDepth + 1);
					}
				} catch (Exception e) {
					result.append(indent).append("Could not follow pointer: ").append(e.getMessage()).append("\n");
				}
			}
		} else {
			result.append(indent).append("Address: ").append(addr).append(" | No defined data\n");
		}
	}
}
