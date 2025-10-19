package com.lauriewired.handlers.data;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;

import java.io.IOException;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class InspectMemoryContent extends Handler {
	public InspectMemoryContent(PluginTool tool) {
		super(tool, "/inspect_memory_content");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String address = qparams.get("address");
		int length = parseIntOrDefault(qparams.get("length"), 64);
		boolean detectStrings = parseBoolOrDefault(qparams.get("detect_strings"), true);

		String result = inspectMemoryContent(address, length, detectStrings);
		sendResponse(exchange, result);
	}

	private String inspectMemoryContent(String addressStr, int length, boolean detectStrings) {
		Program program = getCurrentProgram(tool);
		if (program == null) return "{\"error\": \"No program loaded\"}";

		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			if (addr == null) {
				return "{\"error\": \"Invalid address: " + addressStr + "\"}";
			}

			Memory memory = program.getMemory();
			byte[] bytes = new byte[length];
			int bytesRead = memory.getBytes(addr, bytes);

			// Build hex dump
			StringBuilder hexDump = new StringBuilder();
			StringBuilder asciiRepr = new StringBuilder();

			for (int i = 0; i < bytesRead; i++) {
				if (i > 0 && i % 16 == 0) {
					hexDump.append("\\n");
					asciiRepr.append("\\n");
				}

				hexDump.append(String.format("%02X ", bytes[i] & 0xFF));

				// ASCII representation (printable chars only)
				char c = (char) (bytes[i] & 0xFF);
				if (c >= 0x20 && c <= 0x7E) {
					asciiRepr.append(c);
				} else if (c == 0x00) {
					asciiRepr.append("\\0");
				} else {
					asciiRepr.append(".");
				}
			}

			// String detection heuristics
			boolean likelyString = false;
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

			// String detection criteria:
			// - At least 60% printable characters OR
			// - At least 4 consecutive printable chars followed by null terminator
			if (detectStrings) {
				likelyString = (printableRatio >= 0.6) ||
							  (maxConsecutivePrintable >= 4 && nullTerminatorIndex > 0);
			}

			// Detect potential string content
			String detectedString = null;
			int stringLength = 0;
			if (likelyString && nullTerminatorIndex > 0) {
				detectedString = new String(bytes, 0, nullTerminatorIndex, StandardCharsets.US_ASCII);
				stringLength = nullTerminatorIndex + 1; // Include null terminator
			} else if (likelyString && printableRatio >= 0.8) {
				// String without null terminator (might be fixed-length string)
				int endIdx = bytesRead;
				for (int i = bytesRead - 1; i >= 0; i--) {
					if ((bytes[i] & 0xFF) >= 0x20 && (bytes[i] & 0xFF) <= 0x7E) {
						endIdx = i + 1;
						break;
					}
				}
				detectedString = new String(bytes, 0, endIdx, StandardCharsets.US_ASCII);
				stringLength = endIdx;
			}

			// Build JSON response
			StringBuilder result = new StringBuilder();
			result.append("{");
			result.append("\"address\": \"").append(addressStr).append("\",");
			result.append("\"bytes_read\": ").append(bytesRead).append(",");
			result.append("\"hex_dump\": \"").append(hexDump.toString().trim()).append("\",");
			result.append("\"ascii_repr\": \"").append(asciiRepr.toString().trim()).append("\",");
			result.append("\"printable_count\": ").append(printableCount).append(",");
			result.append("\"printable_ratio\": ").append(String.format("%.2f", printableRatio)).append(",");
			result.append("\"null_terminator_at\": ").append(nullTerminatorIndex).append(",");
			result.append("\"max_consecutive_printable\": ").append(maxConsecutivePrintable).append(",");
			result.append("\"is_likely_string\": ").append(likelyString).append(",");

			if (detectedString != null) {
				result.append("\"detected_string\": \"").append(escapeJson(detectedString)).append("\",");
				result.append("\"suggested_type\": \"char[").append(stringLength).append("]\",");
				result.append("\"string_length\": ").append(stringLength);
			} else {
				result.append("\"detected_string\": null,");
				result.append("\"suggested_type\": null,");
				result.append("\"string_length\": 0");
			}

			result.append("}");

			return result.toString();
		} catch (Exception e) {
			return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
		}
	}
}
