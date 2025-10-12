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

/**
 * Handler to get bytes from a specified address in the current program.
 * Expects query parameters: address=<address> and size=<size>.
 */
public final class ReadMemory extends Handler {
	/**
	 * Constructor for the ReadMemory handler.
	 * 
	 * @param tool The PluginTool instance to use.
	 */
	public ReadMemory(PluginTool tool) {
		super(tool, "/get_bytes", "/read_bytes", "/readMemory");
	}

	/**
	 * Parses the query parameters from the HTTP exchange.
	 * 
	 * @param exchange The HTTP exchange containing the request.
	 * @return A map of query parameters.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String addrStr = qparams.get("address");
		int size = parseIntOrDefault(qparams.get("size"), 1);
		sendResponse(exchange, readMemory(addrStr, size));
	}

	/**
	 * Reads memory from the current program at the specified address and length.
	 * 
	 * @param addressStr The address to read from as a string.
	 * @param length     The number of bytes to read.
	 * @return A JSON string containing the address, length, data, and hex
	 *         representation.
	 */
	private String readMemory(String addressStr, int length) {
		try {
			Program program = getCurrentProgram(tool);
			if (program == null) {
				return "{\"error\":\"No program loaded\"}";
			}

			Address address = program.getAddressFactory().getAddress(addressStr);
			if (address == null) {
				return "{\"error\":\"Invalid address: " + addressStr + "\"}";
			}

			Memory memory = program.getMemory();
			byte[] bytes = new byte[length];

			int bytesRead = memory.getBytes(address, bytes);

			StringBuilder json = new StringBuilder();
			json.append("{");
			json.append("\"address\":\"").append(address.toString()).append("\",");
			json.append("\"length\":").append(bytesRead).append(",");
			json.append("\"data\":[");

			for (int i = 0; i < bytesRead; i++) {
				if (i > 0)
					json.append(",");
				json.append(bytes[i] & 0xFF);
			}

			json.append("],");
			json.append("\"hex\":\"");
			for (int i = 0; i < bytesRead; i++) {
				json.append(String.format("%02x", bytes[i] & 0xFF));
			}
			json.append("\"");
			json.append("}");

			return json.toString();

		} catch (Exception e) {
			return "{\"error\":\"Failed to read memory: " + e.getMessage() + "\"}";
		}
	}
}
