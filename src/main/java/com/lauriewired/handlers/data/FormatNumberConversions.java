package com.lauriewired.handlers.data;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;

import java.io.IOException;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for converting and formatting numbers in various representations.
 */
public final class FormatNumberConversions extends Handler {
	/**
	 * Constructor for the FormatNumberConversions handler.
	 * 
	 * @param tool The plugin tool instance.
	 */
	public FormatNumberConversions(PluginTool tool) {
		super(tool, "/convert_number");
	}

	/**
	 * Handles the HTTP exchange for number conversion requests.
	 * 
	 * @param exchange The HTTP exchange object.
	 * @throws IOException If an I/O error occurs.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String text = qparams.get("text");
		int size = parseIntOrDefault(qparams.get("size"), 4);
		sendResponse(exchange, formatNumberConversion(text, size));
	}
	
	/**
	 * Formats the number conversions for the given text and size.
	 * 
	 * @param text The number in string format.
	 * @param size The size in bytes (1, 2, 4, or 8).
	 * @return A formatted string with conversions.
	 */
	private String formatNumberConversions(String text, int size) {
		if (text == null || text.isEmpty()) {
			return "Error: No number provided";
		}

		try {
			long value;
			String inputType;

			// Determine input format and parse
			if (text.startsWith("0x") || text.startsWith("0X")) {
				value = Long.parseUnsignedLong(text.substring(2), 16);
				inputType = "hexadecimal";
			} else if (text.startsWith("0b") || text.startsWith("0B")) {
				value = Long.parseUnsignedLong(text.substring(2), 2);
				inputType = "binary";
			} else if (text.startsWith("0") && text.length() > 1 && text.matches("0[0-7]+")) {
				value = Long.parseUnsignedLong(text, 8);
				inputType = "octal";
			} else {
				value = Long.parseUnsignedLong(text);
				inputType = "decimal";
			}

			StringBuilder result = new StringBuilder();
			result.append("Input: ").append(text).append(" (").append(inputType).append(")\n");
			result.append("Size: ").append(size).append(" bytes\n\n");

			// Handle different sizes with proper masking
			long mask = (size == 8) ? -1L : (1L << (size * 8)) - 1L;
			long maskedValue = value & mask;

			result.append("Decimal (unsigned): ").append(Long.toUnsignedString(maskedValue)).append("\n");

			// Signed representation for appropriate sizes
			if (size <= 8) {
				long signedValue = maskedValue;
				if (size < 8) {
					// Sign extend for smaller sizes
					long signBit = 1L << (size * 8 - 1);
					if ((maskedValue & signBit) != 0) {
						signedValue = maskedValue | (~mask);
					}
				}
				result.append("Decimal (signed): ").append(signedValue).append("\n");
			}

			result.append("Hexadecimal: 0x").append(Long.toHexString(maskedValue).toUpperCase()).append("\n");
			result.append("Binary: 0b").append(Long.toBinaryString(maskedValue)).append("\n");
			result.append("Octal: 0").append(Long.toOctalString(maskedValue)).append("\n");

			// Add size-specific hex representation
			String hexFormat = String.format("%%0%dX", size * 2);
			result.append("Hex (").append(size).append(" bytes): 0x").append(String.format(hexFormat, maskedValue))
					.append("\n");

			return result.toString();

		} catch (NumberFormatException e) {
			return "Error: Invalid number format: " + text;
		} catch (Exception e) {
			return "Error converting number: " + e.getMessage();
		}
	}
}
