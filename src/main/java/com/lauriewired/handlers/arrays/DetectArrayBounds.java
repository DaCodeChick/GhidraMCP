package com.lauriewired.handlers.arrays;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;

import java.io.IOException;
import java.util.Map;

import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class DetectArrayBounds extends Handler {
	public DetectArrayBounds(PluginTool tool) {
		super(tool, "/detect_array_bounds");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, Object> params = parseJsonParams(exchange);
		String address = (String) params.get("address");
		boolean analyzeLoopBounds = parseBoolOrDefault(params.get("analyze_loop_bounds"), true);
		boolean analyzeIndexing = parseBoolOrDefault(params.get("analyze_indexing"), true);
		int maxScanRange = parseIntOrDefault(String.valueOf(params.get("max_scan_range")), 2048);

		String result = detectArrayBounds(address, analyzeLoopBounds, analyzeIndexing, maxScanRange);
		sendResponse(exchange, result);
	}

	/**
	 * Detect array bounds at the specified address using cross-reference analysis.
	 * @param addressStr The address as a string.
	 * @param analyzeLoopBounds Whether to analyze loop bounds (not implemented).
	 * @param analyzeIndexing Whether to analyze indexing (not implemented).
	 * @param maxScanRange The maximum scan range.
	 * @return A JSON string with the detection results.
	 */
	private String detectArrayBounds(String addressStr, boolean analyzeLoopBounds,
									  boolean analyzeIndexing, int maxScanRange) {
		Program program = getCurrentProgram(tool);
		if (program == null) return "{\"error\": \"No program loaded\"}";

		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			if (addr == null) {
				return "{\"error\": \"Invalid address: " + addressStr + "\"}";
			}

			ReferenceManager refMgr = program.getReferenceManager();

			// Scan for xrefs to detect array bounds
			int estimatedSize = 0;
			Address scanAddr = addr;

			for (int i = 0; i < maxScanRange; i++) {
				ReferenceIterator refIter = refMgr.getReferencesTo(scanAddr);
				if (refIter.hasNext()) {
					estimatedSize = i + 1;
				}

				// Check for boundary symbol
				Symbol[] symbols = program.getSymbolTable().getSymbols(scanAddr);
				if (symbols.length > 0 && i > 0) {
					for (Symbol sym : symbols) {
						if (!sym.getName().startsWith("DAT_")) {
							break;  // Found boundary
						}
					}
				}

				scanAddr = scanAddr.add(1);
			}

			StringBuilder result = new StringBuilder();
			result.append("{");
			result.append("\"address\": \"").append(addr.toString()).append("\",");
			result.append("\"estimated_size\": ").append(estimatedSize).append(",");
			result.append("\"stride\": 1,");
			result.append("\"element_count\": ").append(estimatedSize).append(",");
			result.append("\"confidence\": \"medium\",");
			result.append("\"detection_method\": \"xref_analysis\"");
			result.append("}");

			return result.toString();
		} catch (Exception e) {
			return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
		}
	}
}
