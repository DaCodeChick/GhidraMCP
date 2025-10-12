package com.lauriewired.handlers.misc;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

import java.io.IOException;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to retrieve metadata about the currently loaded program in Ghidra.
 * Responds to GET requests at the /get_metadata endpoint.
 * The metadata includes:
 * - Program Name
 * - Executable Path
 * - Architecture
 * - Compiler
 * - Language
 * - Endianness
 * - Address Size
 * - Base Address
 * - Memory Information (number of memory blocks, total size)
 * - Function Count
 * - Symbol Count
 */
public final class GetMetadata extends Handler {
	/**
	 * Constructor for the GetMetadata handler.
	 * 
	 * @param tool The PluginTool instance to use.
	 */
	public GetMetadata(PluginTool tool) {
		super(tool, "/get_metadata");
	}

	/**
	 * Handles the HTTP exchange by retrieving and sending the program metadata.
	 * @param exchange The HttpExchange object representing the HTTP request and response.
	 * @throws IOException If an I/O error occurs.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		sendResponse(exchange, getMetadata());
	}

	/**
	 * Retrieves metadata about the currently loaded program.
	 * @return A string containing the program metadata.
	 */
	private String getMetadata() {
		Program program = getCurrentProgram(tool);
		if (program == null) {
			return "No program loaded";
		}

		StringBuilder metadata = new StringBuilder();
		metadata.append("Program Name: ").append(program.getName()).append("\n");
		metadata.append("Executable Path: ").append(program.getExecutablePath()).append("\n");
		metadata.append("Architecture: ").append(program.getLanguage().getProcessor().toString()).append("\n");
		metadata.append("Compiler: ").append(program.getCompilerSpec().getCompilerSpecID()).append("\n");
		metadata.append("Language: ").append(program.getLanguage().getLanguageID()).append("\n");
		metadata.append("Endian: ").append(program.getLanguage().isBigEndian() ? "Big" : "Little").append("\n");
		metadata.append("Address Size: ").append(program.getAddressFactory().getDefaultAddressSpace().getSize())
				.append(" bits\n");
		metadata.append("Base Address: ").append(program.getImageBase()).append("\n");

		// Memory information
		long totalSize = 0;
		int blockCount = 0;
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			totalSize += block.getSize();
			blockCount++;
		}
		metadata.append("Memory Blocks: ").append(blockCount).append("\n");
		metadata.append("Total Memory Size: ").append(totalSize).append(" bytes\n");

		// Function count
		int functionCount = program.getFunctionManager().getFunctionCount();
		metadata.append("Function Count: ").append(functionCount).append("\n");

		// Symbol count
		int symbolCount = program.getSymbolTable().getNumSymbols();
		metadata.append("Symbol Count: ").append(symbolCount).append("\n");

		return metadata.toString();
	}
}
