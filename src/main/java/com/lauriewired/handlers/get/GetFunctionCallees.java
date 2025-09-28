package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.lauriewired.util.ParseUtils.parseQueryParams;
import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for GET requests to retrieve the callees of a function at a specific
 * address.
 */
public class GetFunctionCallees extends Handler {
	/**
	 * Constructor for GetFunctionCallees.
	 * 
	 * @param tool the plugin tool
	 */
	public GetFunctionCallees(PluginTool tool) {
		super(tool, "/function_callees");
	}

	/**
	 * Handles the HTTP exchange to retrieve callees.
	 * 
	 * @param exchange the HTTP exchange
	 * @throws IOException
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String name = qparams.get("name");
		int offset = parseIntOrDefault(qparams.get("offset"), 0);
		int limit = parseIntOrDefault(qparams.get("limit"), 100);
		sendResponse(exchange, getFunctionCallees(name, offset, limit));
	}

	/**
	 * Retrieves the callees of a function by its name.
	 * 
	 * @param functionName the name of the function
	 * @param offset       the offset for pagination
	 * @param limit        the maximum number of results to return
	 * @return a string representation of the callees
	 */
	private String getFunctionCallees(String functionName, int offset, int limit) {
		Program program = getCurrentProgram();
		if (program == null) {
			return "No program loaded";
		}

		StringBuilder sb = new StringBuilder();
		FunctionManager functionManager = program.getFunctionManager();

		// Find the function by name
		Function function = null;
		for (Function f : functionManager.getFunctions(true)) {
			if (f.getName().equals(functionName)) {
				function = f;
				break;
			}
		}

		if (function == null) {
			return "Function not found: " + functionName;
		}

		Set<Function> callees = new HashSet<>();
		AddressSetView functionBody = function.getBody();
		Listing listing = program.getListing();
		ReferenceManager refManager = program.getReferenceManager();

		// Iterate through all instructions in the function
		InstructionIterator instructions = listing.getInstructions(functionBody, true);
		while (instructions.hasNext()) {
			Instruction instr = instructions.next();

			// Check if this is a call instruction
			if (instr.getFlowType().isCall()) {
				// Get all reference addresses from this instruction
				Reference[] references = refManager.getReferencesFrom(instr.getAddress());
				for (Reference ref : references) {
					if (ref.getReferenceType().isCall()) {
						Address targetAddr = ref.getToAddress();
						Function targetFunc = functionManager.getFunctionAt(targetAddr);
						if (targetFunc != null) {
							callees.add(targetFunc);
						}
					}
				}
			}
		}

		// Convert to sorted list and apply pagination
		List<Function> sortedCallees = new ArrayList<>(callees);
		sortedCallees.sort((f1, f2) -> f1.getName().compareTo(f2.getName()));

		int count = 0;
		int skipped = 0;

		for (Function callee : sortedCallees) {
			if (count >= limit)
				break;

			if (skipped < offset) {
				skipped++;
				continue;
			}

			if (sb.length() > 0) {
				sb.append("\n");
			}

			sb.append(String.format("%s @ %s", callee.getName(), callee.getEntryPoint()));
			count++;
		}

		if (sb.length() == 0) {
			return "No callees found for function: " + functionName;
		}

		return sb.toString();
	}
}
