package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to get entry points in the current program.
 */
public class GetEntryPoints extends Handler {
	/**
	 * Constructor for the GetEntryPoints handler.
	 * 
	 * @param tool The plugin tool
	 */
	public GetEntryPoints(PluginTool tool) {
		super(tool, "/get_entry_points");
	}

	/**
	 * Handles the HTTP exchange to retrieve entry points.
	 * 
	 * @param exchange The HTTP exchange
	 * @throws IOException If an I/O error occurs
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		sendResponse(exchange, getEntryPoints());
	}

	/**
	 * Retrieves entry points from the current program using multiple methods.
	 * 
	 * @return A formatted string of entry points or a message if none found
	 */
	private String getEntryPoints() {
		Program program = getCurrentProgram();
		if (program == null) {
			return "No program loaded";
		}

		List<String> entryPoints = new ArrayList<>();
		SymbolTable symbolTable = program.getSymbolTable();

		// Method 1: Get all external entry point symbols
		SymbolIterator allSymbols = symbolTable.getAllSymbols(true);
		while (allSymbols.hasNext()) {
			Symbol symbol = allSymbols.next();
			if (symbol.isExternalEntryPoint()) {
				String entryInfo = formatEntryPoint(symbol) + " [external entry]";
				entryPoints.add(entryInfo);
			}
		}

		// Method 2: Check for common entry point names
		String[] commonEntryNames = { "main", "_main", "start", "_start", "WinMain", "_WinMain",
				"DllMain", "_DllMain", "entry", "_entry" };

		for (String entryName : commonEntryNames) {
			SymbolIterator symbols = symbolTable.getSymbols(entryName);
			while (symbols.hasNext()) {
				Symbol symbol = symbols.next();
				if (symbol.getSymbolType() == SymbolType.FUNCTION || symbol.getSymbolType() == SymbolType.LABEL) {
					String entryInfo = formatEntryPoint(symbol) + " [common entry name]";
					if (!containsAddress(entryPoints, symbol.getAddress())) {
						entryPoints.add(entryInfo);
					}
				}
			}
		}

		// Method 4: Get the program's designated entry point
		Address programEntry = program.getImageBase();
		if (programEntry != null) {
			Symbol entrySymbol = symbolTable.getPrimarySymbol(programEntry);
			String entryInfo;
			if (entrySymbol != null) {
				entryInfo = formatEntryPoint(entrySymbol) + " [program entry]";
			} else {
				entryInfo = "entry @ " + programEntry + " [program entry] [FUNCTION]";
			}
			if (!containsAddress(entryPoints, programEntry)) {
				entryPoints.add(entryInfo);
			}
		}

		// If no entry points found, check for functions at common addresses
		if (entryPoints.isEmpty()) {
			// Check some common entry addresses
			String[] commonHexAddresses = { "0x401000", "0x400000", "0x1000", "0x10000" };
			for (String hexAddr : commonHexAddresses) {
				try {
					Address addr = program.getAddressFactory().getAddress(hexAddr);
					if (addr != null && program.getMemory().contains(addr)) {
						Function func = program.getFunctionManager().getFunctionAt(addr);
						if (func != null) {
							entryPoints
									.add("entry @ " + addr + " (" + func.getName() + ") [potential entry] [FUNCTION]");
						}
					}
				} catch (Exception e) {
					// Ignore invalid addresses
				}
			}
		}

		if (entryPoints.isEmpty()) {
			return "No entry points found in program";
		}

		return String.join("\n", entryPoints);
	}
}
