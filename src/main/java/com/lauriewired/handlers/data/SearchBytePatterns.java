package com.lauriewired.handlers.data;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class SearchBytePatterns extends Handler {
	/**
	 * Constructor for the SearchBytePatterns handler.
	 * 
	 * @param tool The PluginTool instance to use.
	 */
	public SearchBytePatterns(PluginTool tool) {
		super(tool, "/search_byte_patterns");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String pattern = qparams.get("pattern");
		String mask = qparams.get("mask");

		String result = searchBytePatterns(pattern, mask);
		sendResponse(exchange, result);
	}

	/**
	 * Searches the current program's memory for the specified byte pattern.
	 *
	 * @param pattern The byte pattern to search for (e.g., "E8 ?? ?? ?? ??").
	 * @param mask    The mask indicating which bytes to check (not used in this implementation).
	 * @return A JSON string containing the search results.
	 */
	private String searchBytePatterns(String pattern, String mask) {
        Program program = getCurrentProgram(tool);
        if (program == null) {
            return "Error: No program loaded";
        }

        if (pattern == null || pattern.trim().isEmpty()) {
            return "Error: Pattern is required";
        }

        try {
            final StringBuilder result = new StringBuilder();
            result.append("[\n");

            // Parse hex pattern (e.g., "E8 ?? ?? ?? ??" or "E8????????")
            String cleanPattern = pattern.trim().toUpperCase().replaceAll("\\s+", "");

            // Convert pattern to byte array and mask
            int patternLen = cleanPattern.replace("?", "").length() / 2 + cleanPattern.replace("?", "").length() % 2;
            if (cleanPattern.contains("?")) {
                patternLen = cleanPattern.length() / 2;
            }

            byte[] patternBytes = new byte[patternLen];
            byte[] maskBytes = new byte[patternLen];

            int byteIndex = 0;
            for (int i = 0; i < cleanPattern.length(); i += 2) {
                if (cleanPattern.charAt(i) == '?' || (i + 1 < cleanPattern.length() && cleanPattern.charAt(i + 1) == '?')) {
                    patternBytes[byteIndex] = 0;
                    maskBytes[byteIndex] = 0; // Don't check this byte
                } else {
                    String hexByte = cleanPattern.substring(i, Math.min(i + 2, cleanPattern.length()));
                    patternBytes[byteIndex] = (byte) Integer.parseInt(hexByte, 16);
                    maskBytes[byteIndex] = (byte) 0xFF; // Check this byte
                }
                byteIndex++;
            }

            // Search memory for pattern
            Memory memory = program.getMemory();
            int matchCount = 0;
            final int MAX_MATCHES = 1000; // Limit results

            for (MemoryBlock block : memory.getBlocks()) {
                if (!block.isInitialized()) continue;

                Address blockStart = block.getStart();
                long blockSize = block.getSize();

                // Read block data
                byte[] blockData = new byte[(int) Math.min(blockSize, Integer.MAX_VALUE)];
                try {
                    block.getBytes(blockStart, blockData);
                } catch (Exception e) {
                    continue; // Skip blocks we can't read
                }

                // Search for pattern in block
                for (int i = 0; i <= blockData.length - patternBytes.length; i++) {
                    boolean match = true;
                    for (int j = 0; j < patternBytes.length; j++) {
                        if (maskBytes[j] != 0 && blockData[i + j] != patternBytes[j]) {
                            match = false;
                            break;
                        }
                    }

                    if (match) {
                        if (matchCount > 0) result.append(",\n");
                        Address matchAddr = blockStart.add(i);
                        result.append("  {\"address\": \"").append(matchAddr).append("\"}");
                        matchCount++;

                        if (matchCount >= MAX_MATCHES) {
                            result.append(",\n  {\"note\": \"Limited to ").append(MAX_MATCHES).append(" matches\"}");
                            break;
                        }
                    }
                }

                if (matchCount >= MAX_MATCHES) break;
            }

            if (matchCount == 0) {
                result.append("  {\"note\": \"No matches found\"}");
            }

            result.append("\n]");
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}
