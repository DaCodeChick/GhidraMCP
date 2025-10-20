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

import java.util.Map;

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

		String result = batchDecompileXrefSources(targetAddress, includeFunctionNames, includeUsageContext);
		sendResponse(exchange, result);
	}

	/**
	 * Decompiles all functions that reference the specified target address.
	 * 
	 * @param targetAddressStr the target address as a string
	 * @param includeFunctionNames whether to include function names in the output
	 * @param includeUsageContext whether to include usage context in the output
	 * @return a JSON string containing decompiled code and metadata
	 */
	private String batchDecompileXrefSources(String targetAddressStr,
											 boolean includeFunctionNames,
											 boolean includeUsageContext) {
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

			StringBuilder json = new StringBuilder();
			json.append("{");
			boolean first = true;

			DecompInterface decomp = new DecompInterface();
			decomp.openProgram(program);

			for (Function func : functionsToDecompile) {
				if (!first) json.append(",");
				first = false;

				json.append("\"").append(func.getEntryPoint().toString()).append("\": {");
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
			json.append("}");
			return json.toString();
		} catch (Exception e) {
			return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
		}
	}
}
