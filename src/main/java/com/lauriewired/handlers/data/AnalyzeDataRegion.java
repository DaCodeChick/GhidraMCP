package com.lauriewired.handlers.data;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.program.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class AnalyzeDataRegion extends Handler {
	public AnalyzeDataRegion(PluginTool tool) {
		super(tool, "/analyze_data_region");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, Object> params = parseJsonParams(exchange);
		String address = (String) params.get("address");
		int maxScanBytes = parseIntOrDefault(String.valueOf(params.get("max_scan_bytes")), 1024);
		boolean includeXrefMap = parseBoolOrDefault(params.get("include_xref_map"), true);
		boolean includeAssemblyPatterns = parseBoolOrDefault(params.get("include_assembly_patterns"), true);
		boolean includeBoundaryDetection = parseBoolOrDefault(params.get("include_boundary_detection"), true);

		String result = analyzeDataRegion(address, maxScanBytes, includeXrefMap,
											includeAssemblyPatterns, includeBoundaryDetection);
		sendResponse(exchange, result);
	}

	private String analyzeDataRegion(String startAddressStr, int maxScanBytes,
									  boolean includeXrefMap, boolean includeAssemblyPatterns,
									  boolean includeBoundaryDetection) {
		Program program = getCurrentProgram(tool);
		if (program == null) return "{\"error\": \"No program loaded\"}";

		try {
			Address startAddr = program.getAddressFactory().getAddress(startAddressStr);
			if (startAddr == null) {
				return "{\"error\": \"Invalid address: " + startAddressStr + "\"}";
			}

			ReferenceManager refMgr = program.getReferenceManager();
			Listing listing = program.getListing();

			// Scan byte-by-byte for xrefs and boundary detection
			Address currentAddr = startAddr;
			Address endAddr = startAddr;
			Set<String> uniqueXrefs = new HashSet<>();
			int byteCount = 0;
			StringBuilder xrefMapJson = new StringBuilder();
			xrefMapJson.append("\"xref_map\": {");
			boolean firstXrefEntry = true;

			for (int i = 0; i < maxScanBytes; i++) {
				Address scanAddr = startAddr.add(i);

				// Check for boundary: Named symbol that isn't DAT_
				Symbol[] symbols = program.getSymbolTable().getSymbols(scanAddr);
				if (includeBoundaryDetection && symbols.length > 0) {
					for (Symbol sym : symbols) {
						String name = sym.getName();
						if (!name.startsWith("DAT_") && !name.equals(startAddr.toString())) {
							// Found a named boundary
							endAddr = scanAddr.subtract(1);
							byteCount = i;
							break;
						}
					}
					if (byteCount > 0) break;
				}

				// Get xrefs for this byte
				ReferenceIterator refIter = refMgr.getReferencesTo(scanAddr);
				List<String> refsAtThisByte = new ArrayList<>();

				while (refIter.hasNext()) {
					Reference ref = refIter.next();
					String fromAddr = ref.getFromAddress().toString();
					refsAtThisByte.add(fromAddr);
					uniqueXrefs.add(fromAddr);
				}

				if (includeXrefMap && !refsAtThisByte.isEmpty()) {
					if (!firstXrefEntry) xrefMapJson.append(",");
					firstXrefEntry = false;

					xrefMapJson.append("\"").append(scanAddr.toString()).append("\": [");
					for (int j = 0; j < refsAtThisByte.size(); j++) {
						if (j > 0) xrefMapJson.append(",");
						xrefMapJson.append("\"").append(refsAtThisByte.get(j)).append("\"");
					}
					xrefMapJson.append("]");
				}

				endAddr = scanAddr;
				byteCount = i + 1;
			}
			xrefMapJson.append("}");

			// Get current name and type
			Data data = listing.getDataAt(startAddr);
			String currentName = (data != null && data.getLabel() != null) ?
								data.getLabel() : "DAT_" + startAddr.toString().replace(":", "");
			String currentType = (data != null) ?
								data.getDataType().getName() : "undefined";

			// STRING DETECTION: Read memory content to check for strings
			boolean isLikelyString = false;
			String detectedString = null;
			int suggestedStringLength = 0;

			try {
				Memory memory = program.getMemory();
				byte[] bytes = new byte[Math.min(byteCount, 256)]; // Read up to 256 bytes
				int bytesRead = memory.getBytes(startAddr, bytes);

				int printableCount = 0;
				int nullTerminatorIndex = -1;
				int consecutivePrintable = 0;
				int maxConsecutivePrintable = 0;

				for (int i = 0; i < bytesRead; i++) {
					char c = (char) (bytes[i] & 0xFF);

					if (c >= 0x20 && c <= 0x7E) {
						printableCount++;
						consecutivePrintable++;
						if (consecutivePrintable > maxConsecutivePrintable) {
							maxConsecutivePrintable = consecutivePrintable;
						}
					} else {
						consecutivePrintable = 0;
					}

					if (c == 0x00 && nullTerminatorIndex == -1) {
						nullTerminatorIndex = i;
					}
				}

				double printableRatio = (double) printableCount / bytesRead;

				// String detection criteria
				isLikelyString = (printableRatio >= 0.6) ||
								(maxConsecutivePrintable >= 4 && nullTerminatorIndex > 0);

				if (isLikelyString && nullTerminatorIndex > 0) {
					detectedString = new String(bytes, 0, nullTerminatorIndex, StandardCharsets.US_ASCII);
					suggestedStringLength = nullTerminatorIndex + 1;
				} else if (isLikelyString && printableRatio >= 0.8) {
					int endIdx = bytesRead;
					for (int i = bytesRead - 1; i >= 0; i--) {
						if ((bytes[i] & 0xFF) >= 0x20 && (bytes[i] & 0xFF) <= 0x7E) {
							endIdx = i + 1;
							break;
						}
					}
					detectedString = new String(bytes, 0, endIdx, StandardCharsets.US_ASCII);
					suggestedStringLength = endIdx;
				}
			} catch (Exception e) {
				// String detection failed, continue with normal classification
			}

			// Classify data type hint (enhanced with string detection)
			String classification = "PRIMITIVE";
			if (isLikelyString) {
				classification = "STRING";
			} else if (uniqueXrefs.size() > 3) {
				classification = "ARRAY";
			} else if (uniqueXrefs.size() > 1) {
				classification = "STRUCTURE";
			}

			// Build final JSON response
			StringBuilder result = new StringBuilder();
			result.append("{");
			result.append("\"start_address\": \"").append(startAddr.toString()).append("\",");
			result.append("\"end_address\": \"").append(endAddr.toString()).append("\",");
			result.append("\"byte_span\": ").append(byteCount).append(",");

			if (includeXrefMap) {
				result.append(xrefMapJson.toString()).append(",");
			}

			result.append("\"unique_xref_addresses\": [");
			int idx = 0;
			for (String xref : uniqueXrefs) {
				if (idx++ > 0) result.append(",");
				result.append("\"").append(xref).append("\"");
			}
			result.append("],");

			result.append("\"xref_count\": ").append(uniqueXrefs.size()).append(",");
			result.append("\"classification_hint\": \"").append(classification).append("\",");
			result.append("\"stride_detected\": 1,");
			result.append("\"current_name\": \"").append(currentName).append("\",");
			result.append("\"current_type\": \"").append(currentType).append("\",");

			// Add string detection results
			result.append("\"is_likely_string\": ").append(isLikelyString).append(",");
			if (detectedString != null) {
				result.append("\"detected_string\": \"").append(escapeJson(detectedString)).append("\",");
				result.append("\"suggested_string_type\": \"char[").append(suggestedStringLength).append("]\"");
			} else {
				result.append("\"detected_string\": null,");
				result.append("\"suggested_string_type\": null");
			}

			result.append("}");

			return result.toString();
		} catch (Exception e) {
			return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
		}
	}
}
