package com.lauriewired.handlers.functions;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.List;
import java.util.Map;
import javax.swing.*;

import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class ValidateFunctionPrototype extends Handler {
	/**
	 * Constructor for the ValidateFunctionPrototype handler.
	 * 
	 * @param tool The plugin tool instance.
	 */
	public ValidateFunctionPrototype(PluginTool tool) {
		super(tool, "/validate_function_prototype");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		String functionAddress = qparams.get("function_address");
		String prototype = qparams.get("prototype");
		String callingConvention = qparams.get("calling_convention");

		String result = validateFunctionPrototype(functionAddress, prototype, callingConvention);
		sendResponse(exchange, result);
	}

	/**
	 * Validates a function prototype for a given function address in the current program.
	 *
	 * @param functionAddress The address of the function to validate against.
	 * @param prototype The function prototype string to validate.
	 * @param callingConvention The calling convention to validate (optional).
	 * @return A JSON string indicating whether the prototype is valid, along with any errors or warnings.
	 */
	private String validateFunctionPrototype(String functionAddress, String prototype, String callingConvention) {
        Program program = getCurrentProgram(tool);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        final StringBuilder result = new StringBuilder();
        final AtomicReference<String> errorMsg = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    result.append("{\"valid\": ");

                    Address addr = program.getAddressFactory().getAddress(functionAddress);
                    if (addr == null) {
                        result.append("false, \"error\": \"Invalid address: ").append(functionAddress).append("\"");
                        return;
                    }

                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        result.append("false, \"error\": \"No function at address: ").append(functionAddress).append("\"");
                        return;
                    }

                    // Basic validation - check if prototype string is parseable
                    if (prototype == null || prototype.trim().isEmpty()) {
                        result.append("false, \"error\": \"Empty prototype\"");
                        return;
                    }

                    // Check for common issues
                    List<String> warnings = new ArrayList<>();

                    // Check for return type
                    if (!prototype.contains("(")) {
                        result.append("false, \"error\": \"Invalid prototype format - missing parentheses\"");
                        return;
                    }

                    // Validate calling convention if provided
                    if (callingConvention != null && !callingConvention.isEmpty()) {
                        String[] validConventions = {"__cdecl", "__stdcall", "__fastcall", "__thiscall", "default"};
                        boolean validConv = false;
                        for (String valid : validConventions) {
                            if (callingConvention.equalsIgnoreCase(valid)) {
                                validConv = true;
                                break;
                            }
                        }
                        if (!validConv) {
                            warnings.add("Unknown calling convention: " + callingConvention);
                        }
                    }

                    result.append("true");
                    if (!warnings.isEmpty()) {
                        result.append(", \"warnings\": [");
                        for (int i = 0; i < warnings.size(); i++) {
                            if (i > 0) result.append(", ");
                            result.append("\"").append(warnings.get(i).replace("\"", "\\\"")).append("\"");
                        }
                        result.append("]");
                    }
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                }
            });

            if (errorMsg.get() != null) {
                return "{\"valid\": false, \"error\": \"" + errorMsg.get().replace("\"", "\\\"") + "\"}";
            }
        } catch (Exception e) {
            return "{\"valid\": false, \"error\": \"" + e.getMessage().replace("\"", "\\\"") + "\"}";
        }

        result.append("}");
        return result.toString();
    }
}
