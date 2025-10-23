package com.lauriewired.handlers.security;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SymbolTable;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Set;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class ExtractIOCs extends Handler {
	/**
	 * Constructor for the ExtractIOCs handler.
	 * 
	 * @param tool The PluginTool instance to use.
	 */
	public ExtractIOCs(PluginTool tool) {
		super(tool, "/extract_iocs");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		String result = extractIOCs();
		sendResponse(exchange, result);
	}

	/**
	 * Extracts Indicators of Compromise (IOCs) from the current program.
	 * 
	 * @return A JSON string containing the extracted IOCs.
	 */
	private String extractIOCs() {
		Program program = getCurrentProgram();
		if (program == null) {
			return "Error: No program loaded";
		}

		try {
			StringBuilder result = new StringBuilder();
			result.append("{");

			// Extract strings from the program
			Set<String> ipv4Set = new HashSet<>();
			Set<String> urlSet = new HashSet<>();
			Set<String> filePathSet = new HashSet<>();
			Set<String> registryKeySet = new HashSet<>();

			// Regex patterns for IOCs
			Pattern ipv4Pattern = Pattern.compile(
				"\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b"
			);
			Pattern urlPattern = Pattern.compile(
				"https?://[a-zA-Z0-9\\-._~:/?#\\[\\]@!$&'()*+,;=%]+"
			);
			Pattern winPathPattern = Pattern.compile(
				"[A-Za-z]:\\\\[^\\x00-\\x1F\\x7F<>:\"|?*\\n\\r]+"
			);
			Pattern registryPattern = Pattern.compile(
				"(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\\\[^\\x00-\\x1F\\x7F\\n\\r]+"
			);

			// Iterate through all defined strings
			SymbolTable symbolTable = program.getSymbolTable();
			Listing listing = program.getListing();
			Memory memory = program.getMemory();

			// Search defined data
			DataIterator dataIter = listing.getDefinedData(true);
			int stringsChecked = 0;
			final int MAX_STRINGS = 10000; // Limit for performance

			while (dataIter.hasNext() && stringsChecked < MAX_STRINGS) {
				Data data = dataIter.next();
				if (data.hasStringValue()) {
					String str = data.getDefaultValueRepresentation();
					if (str == null || str.length() < 4) continue;

					stringsChecked++;

					// Check for IPv4
					Matcher ipMatcher = ipv4Pattern.matcher(str);
					while (ipMatcher.find()) {
						String ip = ipMatcher.group();
						// Basic validation: not 0.0.0.0, not all 255s
						if (!ip.equals("0.0.0.0") && !ip.equals("255.255.255.255")) {
							ipv4Set.add(ip);
						}
					}

					// Check for URLs
					Matcher urlMatcher = urlPattern.matcher(str);
					while (urlMatcher.find()) {
						urlSet.add(urlMatcher.group());
					}

					// Check for Windows paths
					Matcher pathMatcher = winPathPattern.matcher(str);
					while (pathMatcher.find()) {
						String path = pathMatcher.group();
						if (path.length() > 5) { // Reasonable minimum
							filePathSet.add(path);
						}
					}

					// Check for registry keys
					Matcher regMatcher = registryPattern.matcher(str);
					while (regMatcher.find()) {
						registryKeySet.add(regMatcher.group());
					}
				}
			}

			// Build JSON output
			result.append("\"ips\": [");
			int count = 0;
			for (String ip : ipv4Set) {
				if (count > 0) result.append(", ");
				result.append("\"").append(escapeJson(ip)).append("\"");
				count++;
				if (count >= 100) break; // Limit output
			}
			result.append("], ");

			result.append("\"urls\": [");
			count = 0;
			for (String url : urlSet) {
				if (count > 0) result.append(", ");
				result.append("\"").append(escapeJson(url)).append("\"");
				count++;
				if (count >= 100) break;
			}
			result.append("], ");

			result.append("\"file_paths\": [");
			count = 0;
			for (String path : filePathSet) {
				if (count > 0) result.append(", ");
				result.append("\"").append(escapeJson(path)).append("\"");
				count++;
				if (count >= 100) break;
			}
			result.append("], ");

			result.append("\"registry_keys\": [");
			count = 0;
			for (String reg : registryKeySet) {
				if (count > 0) result.append(", ");
				result.append("\"").append(escapeJson(reg)).append("\"");
				count++;
				if (count >= 100) break;
			}
			result.append("]");

			result.append("}");
			return result.toString();
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}
}
