package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to get callers of a specified function.
 * Expects query parameters:
 * - name: The name of the function to get callers for
 * - offset: The number of results to skip (for pagination)
 * - limit: The maximum number of results to return
 */
public class GetFunctionCallers extends Handler {
	/**
	 * Constructor
	 * 
	 * @param tool The plugin tool
	 */
	public GetFunctionCallers(PluginTool tool) {
		super(tool, "/function_callers");
	}

	/**
	 * Handle the HTTP exchange to get function callers.
	 * Expects query parameters:
	 * - name: The name of the function to get callers for
	 * - offset: The number of results to skip (for pagination)
	 * - limit: The maximum number of results to return
	 * 
	 * @param exchange The HTTP exchange
	 * @throws IOException If an I/O error occurs
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String name = qparams.get("name");
		int offset = parseIntOrDefault(qparams.get("offset"), 0);
		int limit = parseIntOrDefault(qparams.get("limit"), 100);
		sendResponse(exchange, getFunctionCallers(name, offset, limit));
	}

	/**
	 * Get callers of the specified function with pagination.
	 * 
	 * @param functionName The name of the function
	 * @param offset       The number of results to skip
	 * @param limit        The maximum number of results to return
	 * @return A string representation of the function callers
	 */
	private String getFunctionCallers(String functionName, int offset, int limit) {
		Program program = getCurrentProgram(tool);
		if (program == null) {
			return "No program loaded";
		}

		StringBuilder sb = new StringBuilder();
		FunctionManager functionManager = program.getFunctionManager();

		// Find the function by name
		Function targetFunction = null;
		for (Function f : functionManager.getFunctions(true)) {
			if (f.getName().equals(functionName)) {
				targetFunction = f;
				break;
			}
		}

		if (targetFunction == null) {
			return "Function not found: " + functionName;
		}

		Set<Function> callers = new HashSet<>();
		ReferenceManager refManager = program.getReferenceManager();

		// Get all references to this function's entry point
		ReferenceIterator refIter = refManager.getReferencesTo(targetFunction.getEntryPoint());
		while (refIter.hasNext()) {
			Reference ref = refIter.next();
			if (ref.getReferenceType().isCall()) {
				Address fromAddr = ref.getFromAddress();
				Function callerFunc = functionManager.getFunctionContaining(fromAddr);
				if (callerFunc != null) {
					callers.add(callerFunc);
				}
			}
		}

		// Convert to sorted list and apply pagination
		List<Function> sortedCallers = new ArrayList<>(callers);
		sortedCallers.sort((f1, f2) -> f1.getName().compareTo(f2.getName()));

		int count = 0;
		int skipped = 0;

		for (Function caller : sortedCallers) {
			if (count >= limit)
				break;

			if (skipped < offset) {
				skipped++;
				continue;
			}

			if (sb.length() > 0) {
				sb.append("\n");
			}

			sb.append(String.format("%s @ %s", caller.getName(), caller.getEntryPoint()));
			count++;
		}

		if (sb.length() == 0) {
			return "No callers found for function: " + functionName;
		}

		return sb.toString();
	}
}
