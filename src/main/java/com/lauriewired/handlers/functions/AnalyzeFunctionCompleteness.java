package com.lauriewired.handlers.functions;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;

import java.io.IOException;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.List;
import java.util.Map;
import javax.swing.*;

import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class AnalyzeFunctionCompleteness extends Handler {
	/**
	 * Constructor for the AnalyzeFunctionCompleteness handler.
	 * 
	 * @param tool The plugin tool instance.
	 */
	public AnalyzeFunctionCompleteness(PluginTool tool) {
		super(tool, "/analyze_function_completeness");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String functionAddress = qparams.get("function_address");

		String result = analyzeFunctionCompleteness(functionAddress);
		sendResponse(exchange, result);
	}

	/**
	 * Analyzes the completeness of a function at the given address.
	 * 
	 * @param functionAddress The address of the function to analyze.
	 * @return A JSON string containing the analysis results.
	 */
	@SuppressWarnings("deprecation")
	private String analyzeFunctionCompleteness(String functionAddress) {
		Program program = getCurrentProgram(tool);
		if (program == null) {
			return "{\"error\": \"No program loaded\"}";
		}

		final StringBuilder result = new StringBuilder();
		final AtomicReference<String> errorMsg = new AtomicReference<>(null);

		try {
			SwingUtilities.invokeAndWait(() -> {
				try {
					Address addr = program.getAddressFactory().getAddress(functionAddress);
					if (addr == null) {
						errorMsg.set("Invalid address: " + functionAddress);
						return;
					}

					Function func = program.getFunctionManager().getFunctionAt(addr);
					if (func == null) {
						errorMsg.set("No function at address: " + functionAddress);
						return;
					}

					result.append("{");
					result.append("\"function_name\": \"").append(func.getName()).append("\", ");
					result.append("\"has_custom_name\": ").append(!func.getName().startsWith("FUN_")).append(", ");
					result.append("\"has_prototype\": ").append(func.getSignature() != null).append(", ");
					result.append("\"has_calling_convention\": ").append(func.getCallingConvention() != null).append(", ");
					result.append("\"has_plate_comment\": ").append(func.getComment() != null).append(", ");

					// Check for undefined variables
					List<String> undefinedVars = new ArrayList<>();
					for (Parameter param : func.getParameters()) {
						if (param.getName().startsWith("param_")) {
							undefinedVars.add(param.getName());
						}
					}
					for (Variable local : func.getLocalVariables()) {
						if (local.getName().startsWith("local_")) {
							undefinedVars.add(local.getName());
						}
					}

					result.append("\"undefined_variables\": [");
					for (int i = 0; i < undefinedVars.size(); i++) {
						if (i > 0) result.append(", ");
						result.append("\"").append(undefinedVars.get(i)).append("\"");
					}
					result.append("], ");

					result.append("\"completeness_score\": ").append(calculateCompletenessScore(func, undefinedVars.size()));
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

	/**
	 * Calculates a completeness score for the function based on various criteria.
	 * 
	 * @param func The function to analyze.
	 * @param undefinedCount The number of undefined variables in the function.
	 * @return A completeness score between 0 and 100.
	 */
	private double calculateCompletenessScore(Function func, int undefinedCount) {
		double score = 100.0;

		if (func.getName().startsWith("FUN_")) score -= 30;
		if (func.getSignature() == null) score -= 20;
		if (func.getCallingConvention() == null) score -= 10;
		if (func.getComment() == null) score -= 20;
		score -= (undefinedCount * 5);

		return Math.max(0, score);
	}
}
