package com.lauriewired.handlers.functions;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompInterface;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.io.IOException;
import java.util.Map;

import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class BatchDecompileFunctions extends Handler {
	/**
	 * Constructor for the BatchDecompileFunctions handler.
	 * 
	 * @param tool The plugin tool instance.
	 */
	public BatchDecompileFunctions(PluginTool tool) {
		super(tool, "/batch_decompile");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String functions = qparams.get("functions");

		String result = batchDecompileFunctions(functions);
		sendResponse(exchange, result);
	}

	/**
	 * Decompiles a batch of functions specified by their names.
	 * 
	 * @param functionsParam Comma-separated function names to decompile.
	 * @return JSON string with function names as keys and decompiled code or error messages as values.
	 */
	private String batchDecompileFunctions(String functionsParam) {
		Program program = getCurrentProgram();
		if (program == null) {
			return "Error: No program loaded";
		}

		if (functionsParam == null || functionsParam.trim().isEmpty()) {
			return "Error: Functions parameter is required";
		}

		try {
			String[] functionNames = functionsParam.split(",");
			StringBuilder result = new StringBuilder();
			result.append("{");

			FunctionManager funcManager = program.getFunctionManager();
			final int MAX_FUNCTIONS = 20; // Limit to prevent overload

			for (int i = 0; i < functionNames.length && i < MAX_FUNCTIONS; i++) {
				String funcName = functionNames[i].trim();
				if (funcName.isEmpty()) continue;

				if (i > 0) result.append(", ");
				result.append("\"").append(escapeJson(funcName)).append("\": ");

				// Find function by name
				Function function = null;
				SymbolTable symbolTable = program.getSymbolTable();
				SymbolIterator symbols = symbolTable.getSymbols(funcName);

				while (symbols.hasNext()) {
					Symbol symbol = symbols.next();
					if (symbol.getSymbolType() == SymbolType.FUNCTION) {
						function = funcManager.getFunctionAt(symbol.getAddress());
						break;
					}
				}

				if (function == null) {
					result.append("\"Error: Function not found\"");
					continue;
				}

				// Decompile the function
				try {
					DecompInterface decompiler = new DecompInterface();
					decompiler.openProgram(program);
					DecompileResults decompResults = decompiler.decompileFunction(function, 30, null);

					if (decompResults != null && decompResults.decompileCompleted()) {
						String decompCode = decompResults.getDecompiledFunction().getC();
						result.append("\"").append(escapeJson(decompCode)).append("\"");
					} else {
						result.append("\"Error: Decompilation failed\"");
					}

					decompiler.dispose();
				} catch (Exception e) {
					result.append("\"Error: ").append(escapeJson(e.getMessage())).append("\"");
				}
			}

			result.append("}");
			return result.toString();
		} catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}
}
