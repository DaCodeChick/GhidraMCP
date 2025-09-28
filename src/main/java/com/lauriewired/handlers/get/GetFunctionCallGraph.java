package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import java.io.IOException;
import java.util.*;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to get the function call graph for a specified function in the
 * current program.
 */
public class GetFunctionCallGraph extends Handler {
	/**
	 * Constructor
	 * 
	 * @param tool The plugin tool
	 */
	public GetFunctionCallGraph(PluginTool tool) {
		super(tool, "/function_call_graph");
	}

	/**
	 * Handle the HTTP exchange to get the function call graph.
	 * Query parameters:
	 * - name: The name of the function to analyze (required)
	 * - depth: The depth of the call graph (default: 2)
	 * - direction: "callees", "callers", or "both" (default: "both")
	 * 
	 * @param exchange The HTTP exchange
	 * @return The function call graph as a string
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String name = qparams.get("name");
		int depth = parseIntOrDefault(qparams.get("depth"), 2);
		String direction = qparams.getOrDefault("direction", "both");
		sendResponse(exchange, getFunctionCallGraph(name, depth, direction));
	}

	/**
	 * Get the function call graph for a specified function.
	 * 
	 * @param functionName The name of the function
	 * @param depth        The depth of the call graph
	 * @param direction    "callees", "callers", or "both"
	 * @return The function call graph as a string
	 */
	private String getFunctionCallGraph(String functionName, int depth, String direction) {
		Program program = getCurrentProgram();
		if (program == null) {
			return "No program loaded";
		}

		StringBuilder sb = new StringBuilder();
		FunctionManager functionManager = program.getFunctionManager();

		// Find the function by name
		Function rootFunction = null;
		for (Function f : functionManager.getFunctions(true)) {
			if (f.getName().equals(functionName)) {
				rootFunction = f;
				break;
			}
		}

		if (rootFunction == null) {
			return "Function not found: " + functionName;
		}

		Set<String> visited = new HashSet<>();
		Map<String, Set<String>> callGraph = new HashMap<>();

		// Build call graph based on direction
		if ("callees".equals(direction) || "both".equals(direction)) {
			buildCallGraphCallees(rootFunction, depth, visited, callGraph, functionManager);
		}

		if ("callers".equals(direction) || "both".equals(direction)) {
			visited.clear(); // Reset for callers traversal
			buildCallGraphCallers(rootFunction, depth, visited, callGraph, functionManager);
		}

		// Format output as edges
		for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
			String caller = entry.getKey();
			for (String callee : entry.getValue()) {
				if (sb.length() > 0) {
					sb.append("\n");
				}
				sb.append(caller).append(" -> ").append(callee);
			}
		}

		if (sb.length() == 0) {
			return "No call graph relationships found for function: " + functionName;
		}

		return sb.toString();
	}

	/**
	 * Recursively build the call graph for callees.
	 * 
	 * @param function        The current function
	 * @param depth           The remaining depth
	 * @param visited         Set of visited function names to avoid cycles
	 * @param callGraph       The call graph being built
	 * @param functionManager The function manager
	 */
	private void buildCallGraphCallees(Function function, int depth, Set<String> visited,
			Map<String, Set<String>> callGraph, FunctionManager functionManager) {
		if (depth <= 0 || visited.contains(function.getName())) {
			return;
		}

		visited.add(function.getName());
		Set<String> callees = new HashSet<>();

		// Find callees of this function
		AddressSetView functionBody = function.getBody();
		Listing listing = getCurrentProgram().getListing();
		ReferenceManager refManager = getCurrentProgram().getReferenceManager();

		InstructionIterator instructions = listing.getInstructions(functionBody, true);
		while (instructions.hasNext()) {
			Instruction instr = instructions.next();

			if (instr.getFlowType().isCall()) {
				Reference[] references = refManager.getReferencesFrom(instr.getAddress());
				for (Reference ref : references) {
					if (ref.getReferenceType().isCall()) {
						Address targetAddr = ref.getToAddress();
						Function targetFunc = functionManager.getFunctionAt(targetAddr);
						if (targetFunc != null) {
							callees.add(targetFunc.getName());
							// Recursively build graph for callees
							buildCallGraphCallees(targetFunc, depth - 1, visited, callGraph, functionManager);
						}
					}
				}
			}
		}

		if (!callees.isEmpty()) {
			callGraph.put(function.getName(), callees);
		}
	}

	/**
	 * Recursively build the call graph for callers.
	 * 
	 * @param function        The current function
	 * @param depth           The remaining depth
	 * @param visited         Set of visited function names to avoid cycles
	 * @param callGraph       The call graph being built
	 * @param functionManager The function manager
	 */
	private void buildCallGraphCallers(Function function, int depth, Set<String> visited,
			Map<String, Set<String>> callGraph, FunctionManager functionManager) {
		if (depth <= 0 || visited.contains(function.getName())) {
			return;
		}

		visited.add(function.getName());
		ReferenceManager refManager = getCurrentProgram().getReferenceManager();

		// Find callers of this function
		ReferenceIterator refIter = refManager.getReferencesTo(function.getEntryPoint());
		while (refIter.hasNext()) {
			Reference ref = refIter.next();
			if (ref.getReferenceType().isCall()) {
				Address fromAddr = ref.getFromAddress();
				Function callerFunc = functionManager.getFunctionContaining(fromAddr);
				if (callerFunc != null) {
					String callerName = callerFunc.getName();
					callGraph.computeIfAbsent(callerName, k -> new HashSet<>()).add(function.getName());
					// Recursively build graph for callers
					buildCallGraphCallers(callerFunc, depth - 1, visited, callGraph, functionManager);
				}
			}
		}
	}
}
