package com.lauriewired.handlers.functions;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Function;
import ghidra.program.model.symbol.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.Map;
import java.util.Set;
import javax.swing.*;

import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class AnalyzeFunctionComplete extends Handler {
	/**
	 * Constructor for the AnalyzeFunctionComplete handler.
	 * 
	 * @param tool The plugin tool instance.
	 */
	public AnalyzeFunctionComplete(PluginTool tool) {
		super(tool, "/analyze_function_complete");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String name = qparams.get("name");
		boolean includeXrefs = Boolean.parseBoolean(qparams.getOrDefault("include_xrefs", "true"));
		boolean includeCallees = Boolean.parseBoolean(qparams.getOrDefault("include_callees", "true"));
		boolean includeCallers = Boolean.parseBoolean(qparams.getOrDefault("include_callers", "true"));
		boolean includeDisasm = Boolean.parseBoolean(qparams.getOrDefault("include_disasm", "true"));
		boolean includeVariables = Boolean.parseBoolean(qparams.getOrDefault("include_variables", "true"));

		String result = analyzeFunctionComplete(name, includeXrefs, includeCallees, includeCallers, includeDisasm, includeVariables);
		sendResponse(exchange, result);
	}

	/**
	 * Analyzes a function in detail and returns a JSON representation of its properties.
	 *
	 * @param name              The name of the function to analyze.
	 * @param includeXrefs      Whether to include cross-references.
	 * @param includeCallees    Whether to include called functions.
	 * @param includeCallers    Whether to include calling functions.
	 * @param includeDisasm     Whether to include disassembly instructions.
	 * @param includeVariables  Whether to include function parameters and local variables.
	 * @return A JSON string representing the analyzed function.
	 */
	private String analyzeFunctionComplete(String name, boolean includeXrefs, boolean includeCallees,
										  boolean includeCallers, boolean includeDisasm, boolean includeVariables) {
		Program program = getCurrentProgram(tool);
		if (program == null) {
			return "{\"error\": \"No program loaded\"}";
		}

		final StringBuilder result = new StringBuilder();
		final AtomicReference<String> errorMsg = new AtomicReference<>(null);

		try {
			SwingUtilities.invokeAndWait(() -> {
				try {
					Function func = null;
					FunctionManager funcMgr = program.getFunctionManager();

					// Find function by name
					for (Function f : funcMgr.getFunctions(true)) {
						if (f.getName().equals(name)) {
							func = f;
							break;
						}
					}

					if (func == null) {
						result.append("{\"error\": \"Function not found: ").append(name).append("\"}");
						return;
					}

					result.append("{");
					result.append("\"name\": \"").append(func.getName()).append("\", ");
					result.append("\"address\": \"").append(func.getEntryPoint().toString()).append("\", ");
					result.append("\"signature\": \"").append(func.getSignature().toString().replace("\"", "\\\"")).append("\"");

					// Include xrefs
					if (includeXrefs) {
						result.append(", \"xrefs\": [");
						ReferenceIterator refs = program.getReferenceManager().getReferencesTo(func.getEntryPoint());
						int refCount = 0;
						while (refs.hasNext() && refCount < 100) {
							Reference ref = refs.next();
							if (refCount > 0) result.append(", ");
							result.append("{\"from\": \"").append(ref.getFromAddress().toString()).append("\"}");
							refCount++;
						}
						result.append("], \"xref_count\": ").append(refCount);
					}

					// Include callees
					if (includeCallees) {
						result.append(", \"callees\": [");
						Set<Function> calledFuncs = func.getCalledFunctions(null);
						int calleeCount = 0;
						for (Function called : calledFuncs) {
							if (calleeCount > 0) result.append(", ");
							result.append("\"").append(called.getName()).append("\"");
							calleeCount++;
						}
						result.append("]");
					}

					// Include callers
					if (includeCallers) {
						result.append(", \"callers\": [");
						Set<Function> callingFuncs = func.getCallingFunctions(null);
						int callerCount = 0;
						for (Function caller : callingFuncs) {
							if (callerCount > 0) result.append(", ");
							result.append("\"").append(caller.getName()).append("\"");
							callerCount++;
						}
						result.append("]");
					}

					// Include disassembly
					if (includeDisasm) {
						result.append(", \"disassembly\": [");
						Listing listing = program.getListing();
						AddressSetView body = func.getBody();
						InstructionIterator instrIter = listing.getInstructions(body, true);
						int instrCount = 0;
						while (instrIter.hasNext() && instrCount < 100) {
							Instruction instr = instrIter.next();
							if (instrCount > 0) result.append(", ");
							result.append("{\"address\": \"").append(instr.getAddress().toString()).append("\", ");
							result.append("\"mnemonic\": \"").append(instr.getMnemonicString()).append("\"}");
							instrCount++;
						}
						result.append("]");
					}

					// Include variables
					if (includeVariables) {
						result.append(", \"parameters\": [");
						Parameter[] params = func.getParameters();
						for (int i = 0; i < params.length; i++) {
							if (i > 0) result.append(", ");
							result.append("{\"name\": \"").append(params[i].getName()).append("\", ");
							result.append("\"type\": \"").append(params[i].getDataType().getName()).append("\"}");
						}
						result.append("], \"locals\": [");
						Variable[] locals = func.getLocalVariables();
						for (int i = 0; i < locals.length; i++) {
							if (i > 0) result.append(", ");
							result.append("{\"name\": \"").append(locals[i].getName()).append("\", ");
							result.append("\"type\": \"").append(locals[i].getDataType().getName()).append("\"}");
						}
						result.append("]");
					}

					result.append("}");
				} catch (Exception e) {
					errorMsg.set(e.getMessage());
				}
			});

			if (errorMsg.get() != null) {
				return "{\"error\": \"" + errorMsg.get().replace("\"", "\\\"") + "\"}";
			}
		} catch (Exception e) {
			return "{\"error\": \"" + e.getMessage().replace("\"", "\\\"") + "\"}";
		}

		return result.toString();
	}
}
