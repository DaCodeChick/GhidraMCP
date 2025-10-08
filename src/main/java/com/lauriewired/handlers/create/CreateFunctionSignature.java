package com.lauriewired.handlers.create;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.FunctionDefinitionDataType;
import ghidra.program.model.listing.ParameterDefinition;
import ghidra.program.model.listing.ParameterDefinitionImpl;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.Map;
import javax.swing.SwingUtilities;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to create a new function signature in the current program.
 * Expects JSON parameters: name (String), return_type (String), parameters (JSON Array of {name: String, type: String}).
 */
public final class CreateFunctionSignature extends Handler {
	/**
	 * Constructs a new CreateFunctionSignature handler.
	 *
	 * @param tool The PluginTool instance to interact with Ghidra.
	 */
	public CreateFunctionSignature(PluginTool tool) {
		super(tool, "/create_function_signature");
	}

	/**
	 * Handles the HTTP exchange to create a new function signature.
	 *
	 * @param exchange The HttpExchange object containing the request and response.
	 * @throws IOException If an I/O error occurs during handling.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, Object> params = parseJsonParams(exchange);
		String name = (String) params.get("name");
		String returnType = (String) params.get("return_type");
		Object parametersObj = params.get("parameters");
		String parametersJson = (parametersObj instanceof String) ? (String) parametersObj : 
								(parametersObj != null ? parametersObj.toString() : null);
		sendResponse(exchange, createFunctionSignature(name, returnType, parametersJson));
	}

	/**
	 * Creates a new function signature in the current program.
	 *
	 * @param name The name of the function.
	 * @param returnType The return type of the function.
	 * @param parametersJson JSON string representing an array of parameter objects.
	 * @return A message indicating success or failure.
	 */
	private String createFunctionSignature(String name, String returnType, String parametersJson) {
        Program program = getCurrentProgram(tool);
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "Function name is required";
        if (returnType == null || returnType.isEmpty()) return "Return type is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create function signature");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    
                    // Resolve return type
                    DataType returnDataType = resolveDataType(dtm, returnType);
                    if (returnDataType == null) {
                        result.append("Return type not found: ").append(returnType);
                        return;
                    }

                    // Create function definition
                    FunctionDefinitionDataType funcDef = new FunctionDefinitionDataType(name);
                    funcDef.setReturnType(returnDataType);

                    // Parse parameters if provided
                    if (parametersJson != null && !parametersJson.isEmpty()) {
                        try {
                            // Simple JSON parsing for parameters
                            String[] paramPairs = parametersJson.replace("[", "").replace("]", "")
                                                               .replace("{", "").replace("}", "")
                                                               .split(",");
                            
                            for (String paramPair : paramPairs) {
                                if (paramPair.trim().isEmpty()) continue;
                                
                                String[] parts = paramPair.split(":");
                                if (parts.length >= 2) {
                                    String paramType = parts[1].replace("\"", "").trim();
                                    DataType paramDataType = resolveDataType(dtm, paramType);
                                    if (paramDataType != null) {
                                        funcDef.setArguments(new ParameterDefinition[] {
                                            new ParameterDefinitionImpl(null, paramDataType, null)
                                        });
                                    }
                                }
                            }
                        } catch (Exception e) {
                            // If JSON parsing fails, continue without parameters
                            result.append("Warning: Could not parse parameters, continuing without them. ");
                        }
                    }

                    DataType addedFuncDef = dtm.addDataType(funcDef, DataTypeConflictHandler.REPLACE_HANDLER);
                    
                    result.append("Successfully created function signature: ").append(addedFuncDef.getName());
                    success.set(true);

                } catch (Exception e) {
                    result.append("Error creating function signature: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute function signature creation on Swing thread: ").append(e.getMessage());
        }

        return result.toString();
    }
}
