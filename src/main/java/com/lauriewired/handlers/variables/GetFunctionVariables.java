package com.lauriewired.handlers.variables;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.util.Msg;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.Map;
import javax.swing.*;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class GetFunctionVariables extends Handler {
	/**
	 * Constructor for the GetFunctionVariables handler.
	 *
	 * @param tool the PluginTool instance
	 */
	public GetFunctionVariables(PluginTool tool) {
		super(tool, "/get_function_variables");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String functionName = qparams.get("function_name");

		String result = getFunctionVariables(functionName);
		sendResponse(exchange, result);
	}

	@SuppressWarnings("deprecation")
    private String getFunctionVariables(String functionName) {
        Program program = getCurrentProgram(tool);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        if (functionName == null || functionName.isEmpty()) {
            return "{\"error\": \"Function name is required\"}";
        }

        final StringBuilder result = new StringBuilder();
        final AtomicReference<String> errorMsg = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    // Find function by name
                    Function func = null;
                    for (Function f : program.getFunctionManager().getFunctions(true)) {
                        if (f.getName().equals(functionName)) {
                            func = f;
                            break;
                        }
                    }

                    if (func == null) {
                        errorMsg.set("Function not found: " + functionName);
                        return;
                    }

                    result.append("{");
                    result.append("\"function_name\": \"").append(func.getName()).append("\", ");
                    result.append("\"function_address\": \"").append(func.getEntryPoint().toString()).append("\", ");

                    // Get parameters
                    result.append("\"parameters\": [");
                    Parameter[] params = func.getParameters();
                    for (int i = 0; i < params.length; i++) {
                        if (i > 0) result.append(", ");
                        Parameter param = params[i];
                        result.append("{");
                        result.append("\"name\": \"").append(param.getName()).append("\", ");
                        result.append("\"type\": \"").append(param.getDataType().getName()).append("\", ");
                        result.append("\"ordinal\": ").append(param.getOrdinal()).append(", ");
                        result.append("\"storage\": \"").append(param.getVariableStorage().toString()).append("\"");
                        result.append("}");
                    }
                    result.append("], ");

                    // Get local variables
                    result.append("\"locals\": [");
                    Variable[] locals = func.getLocalVariables();
                    for (int i = 0; i < locals.length; i++) {
                        if (i > 0) result.append(", ");
                        Variable local = locals[i];
                        result.append("{");
                        result.append("\"name\": \"").append(local.getName()).append("\", ");
                        result.append("\"type\": \"").append(local.getDataType().getName()).append("\", ");
                        result.append("\"storage\": \"").append(local.getVariableStorage().toString()).append("\"");
                        result.append("}");
                    }
                    result.append("]");
                    result.append("}");
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                    Msg.error(this, "Error getting function variables", e);
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
