package com.lauriewired.handlers.addresses;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to get jump targets within a specified function, with pagination
 * support.
 */
public final class GetFunctionJumpTargets extends Handler {
	/**
	 * Constructor
	 *
	 * @param tool the plugin tool
	 */
	public GetFunctionJumpTargets(PluginTool tool) {
		super(tool, "/function_jump_target_addresses", "/function_jump_targets");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String name = qparams.get("name");
		int offset = parseIntOrDefault(qparams.get("offset"), 0);
		int limit = parseIntOrDefault(qparams.get("limit"), 100);
		sendResponse(exchange, getFunctionJumpTargets(name, offset, limit));
	}

	/**
	 * Get jump targets within a function, with pagination.
	 * 
	 * @param functionName the name of the function
	 * @param offset       the number of initial results to skip
	 * @param limit        the maximum number of results to return
	 * @return a string listing jump target addresses with context
	 */
	private String getFunctionJumpTargets(String functionName, int offset, int limit) {
		Program program = getCurrentProgram(tool);
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

		AddressSetView functionBody = function.getBody();
		Listing listing = program.getListing();
		Set<Address> jumpTargets = new HashSet<>();

		// Iterate through all instructions in the function
		InstructionIterator instructions = listing.getInstructions(functionBody, true);
		while (instructions.hasNext()) {
			Instruction instr = instructions.next();

			// Check if this is a jump instruction
			if (instr.getFlowType().isJump()) {
				// Get all reference addresses from this instruction
				Reference[] references = instr.getReferencesFrom();
				for (Reference ref : references) {
					Address targetAddr = ref.getToAddress();
					// Only include targets within the function or program space
					if (targetAddr != null && program.getMemory().contains(targetAddr)) {
						jumpTargets.add(targetAddr);
					}
				}

				// Also check for fall-through addresses for conditional jumps
				if (instr.getFlowType().isConditional()) {
					Address fallThroughAddr = instr.getFallThrough();
					if (fallThroughAddr != null) {
						jumpTargets.add(fallThroughAddr);
					}
				}
			}
		}

		// Convert to sorted list and apply pagination
		List<Address> sortedTargets = new ArrayList<>(jumpTargets);
		Collections.sort(sortedTargets);

		int count = 0;
		int skipped = 0;

		for (Address target : sortedTargets) {
			if (count >= limit)
				break;

			if (skipped < offset) {
				skipped++;
				continue;
			}

			if (sb.length() > 0) {
				sb.append("\n");
			}

			// Add context about what's at this address
			String context = "";
			Function targetFunc = functionManager.getFunctionContaining(target);
			if (targetFunc != null) {
				context = " (in " + targetFunc.getName() + ")";
			} else {
				// Check if there's a label at this address
				Symbol symbol = program.getSymbolTable().getPrimarySymbol(target);
				if (symbol != null) {
					context = " (" + symbol.getName() + ")";
				}
			}

			sb.append(target.toString()).append(context);
			count++;
		}

		if (sb.length() == 0) {
			return "No jump targets found in function: " + functionName;
		}

		return sb.toString();
	}
}
