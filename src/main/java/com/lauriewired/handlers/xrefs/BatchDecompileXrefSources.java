package com.lauriewired.handlers.xrefs;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompInterface;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class BatchDecompileXrefSources extends Handler {
	/**
	 * Constructs the handler with the specified plugin tool.
	 * 
	 * @param tool the plugin tool instance
	 */
	public BatchDecompileXrefSources(PluginTool tool) {
		super(tool, "/batch_decompile_xref_sources");
	}

	@Override
	public void handle(HttpExchange exchange) throws Exception {
		Map<String, Object> params = parseJsonParams(exchange);
		String targetAddress = (String) params.get("target_address");
		boolean includeFunctionNames = parseBoolOrDefault(params.get("include_function_names"), true);
		boolean includeUsageContext = parseBoolOrDefault(params.get("include_usage_context"), true);
		int limit = parseIntOrDefault(String.valueOf(params.get("limit")), 10);
		int offset = parseIntOrDefault(String.valueOf(params.get("offset")), 0);

		String result = batchDecompileXrefSources(targetAddress, includeFunctionNames, includeUsageContext, limit, offset);
		sendResponse(exchange, result);
	}

	/**
	 * Decompiles all functions that reference the specified target address.
	 * 
	 * @param targetAddressStr the target address as a string
	 * @param includeFunctionNames whether to include function names in the output
	 * @param includeUsageContext whether to include usage context in the output
	 * @param limit maximum number of functions to return
	 * @param offset number of functions to skip before starting to return results
	 * @return a JSON string containing decompiled code and metadata
	 */
	private String batchDecompileXrefSources(String targetAddressStr,
											 boolean includeFunctionNames,
											 boolean includeUsageContext,
											 int limit,
											 int offset) {
		Program program = getCurrentProgram(tool);
		if (program == null) return "{\"error\": \"No program loaded\"}";

		try {
			Address targetAddr = program.getAddressFactory().getAddress(targetAddressStr);
			if (targetAddr == null) {
				return "{\"error\": \"Invalid address: " + targetAddressStr + "\"}";
			}

			ReferenceManager refMgr = program.getReferenceManager();
			ReferenceIterator refIter = refMgr.getReferencesTo(targetAddr);

			Set<Function> functionsToDecompile = new HashSet<>();
			while (refIter.hasNext()) {
				Reference ref = refIter.next();
				Function func = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
				if (func != null) {
					functionsToDecompile.add(func);
				}
			}

			// Convert to list for pagination
			List<Function> functionList = new ArrayList<>(functionsToDecompile);
			int totalFunctions = functionList.size();

			// Apply pagination
			int startIndex = Math.min(offset, totalFunctions);
			int endIndex = Math.min(offset + limit, totalFunctions);
			List<Function> paginatedFunctions = functionList.subList(startIndex, endIndex);

			StringBuilder json = new StringBuilder();
			json.append("{");
			json.append("\"total_functions\": ").append(totalFunctions).append(",");
			json.append("\"offset\": ").append(offset).append(",");
			json.append("\"limit\": ").append(limit).append(",");
			json.append("\"returned\": ").append(paginatedFunctions.size()).append(",");
			json.append("\"functions\": [");

			boolean first = true;

			DecompInterface decomp = new DecompInterface();
			decomp.openProgram(program);

			for (Function func : paginatedFunctions) {
				if (!first) json.append(",");
				first = false;

				json.append("{");
				json.append("\"function_address\": \"").append(func.getEntryPoint().toString()).append("\",");
				json.append("\"function_name\": \"").append(func.getName()).append("\",");

				DecompileResults results = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
				if (results != null && results.decompileCompleted()) {
					String decompiledCode = results.getDecompiledFunction().getC();
					json.append("\"decompiled_code\": \"").append(escapeJson(decompiledCode)).append("\",");
				} else {
					json.append("\"decompiled_code\": \"Decompilation failed\",");
				}

				json.append("\"usage_line\": \"Placeholder: usage context\"");
				json.append("}");
			}

			decomp.dispose();
			json.append("]}");
			return json.toString();
		} catch (Exception e) {
			return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
		}
	}
}
