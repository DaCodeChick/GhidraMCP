package com.lauriewired.handlers.functions;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;

import java.io.IOException;
import java.util.*;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to get the full call graph of the current program in various formats.
 * Supports formats: edges (default), dot, mermaid, adjacency.
 */
public class GetFullCallGraph extends Handler {
	/**
	 * Constructor
	 * 
	 * @param tool The plugin tool
	 */
	public GetFullCallGraph(PluginTool tool) {
		super(tool, "/full_call_graph");
	}

	/**
	 * Handle the HTTP request to get the full call graph.
	 * 
	 * @param exchange The HTTP exchange object
	 * @throws IOException If an I/O error occurs
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String format = qparams.getOrDefault("format", "edges");
		int limit = parseIntOrDefault(qparams.get("limit"), 1000);
		sendResponse(exchange, getFullCallGraph(format, limit));
	}

	/**
	 * Generate the full call graph of the current program.
	 * 
	 * @param format The format of the call graph (e.g., "edges", "dot", "mermaid",
	 *               "adjacency")
	 * @param limit  The maximum number of relationships to include in the graph
	 * @return The generated call graph as a string
	 */
	private String getFullCallGraph(String format, int limit) {
		Program program = getCurrentProgram(tool);
		if (program == null) {
			return "No program loaded";
		}

		StringBuilder sb = new StringBuilder();
		FunctionManager functionManager = program.getFunctionManager();
		ReferenceManager refManager = program.getReferenceManager();
		Listing listing = program.getListing();

		Map<String, Set<String>> callGraph = new HashMap<>();
		int relationshipCount = 0;

		// Build complete call graph
		for (Function function : functionManager.getFunctions(true)) {
			if (relationshipCount >= limit) {
				break;
			}

			String functionName = function.getName();
			Set<String> callees = new HashSet<>();

			// Find all functions called by this function
			AddressSetView functionBody = function.getBody();
			InstructionIterator instructions = listing.getInstructions(functionBody, true);

			while (instructions.hasNext() && relationshipCount < limit) {
				Instruction instr = instructions.next();

				if (instr.getFlowType().isCall()) {
					Reference[] references = refManager.getReferencesFrom(instr.getAddress());
					for (Reference ref : references) {
						if (ref.getReferenceType().isCall()) {
							Address targetAddr = ref.getToAddress();
							Function targetFunc = functionManager.getFunctionAt(targetAddr);
							if (targetFunc != null) {
								callees.add(targetFunc.getName());
								relationshipCount++;
								if (relationshipCount >= limit) {
									break;
								}
							}
						}
					}
				}
			}

			if (!callees.isEmpty()) {
				callGraph.put(functionName, callees);
			}
		}

		// Format output based on requested format
		if ("dot".equals(format)) {
			sb.append("digraph CallGraph {\n");
			sb.append("  rankdir=TB;\n");
			sb.append("  node [shape=box];\n");
			for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
				String caller = entry.getKey().replace("\"", "\\\"");
				for (String callee : entry.getValue()) {
					callee = callee.replace("\"", "\\\"");
					sb.append("  \"").append(caller).append("\" -> \"").append(callee).append("\";\n");
				}
			}
			sb.append("}");
		} else if ("mermaid".equals(format)) {
			sb.append("graph TD\n");
			for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
				String caller = entry.getKey().replace(" ", "_");
				for (String callee : entry.getValue()) {
					callee = callee.replace(" ", "_");
					sb.append("  ").append(caller).append(" --> ").append(callee).append("\n");
				}
			}
		} else if ("adjacency".equals(format)) {
			for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
				if (sb.length() > 0) {
					sb.append("\n");
				}
				sb.append(entry.getKey()).append(": ");
				sb.append(String.join(", ", entry.getValue()));
			}
		} else { // Default "edges" format
			for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
				String caller = entry.getKey();
				for (String callee : entry.getValue()) {
					if (sb.length() > 0) {
						sb.append("\n");
					}
					sb.append(caller).append(" -> ").append(callee);
				}
			}
		}

		if (sb.length() == 0) {
			return "No call relationships found in the program";
		}

		return sb.toString();
	}
}
