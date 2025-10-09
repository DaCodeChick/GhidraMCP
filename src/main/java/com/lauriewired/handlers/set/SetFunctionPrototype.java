package com.lauriewired.handlers.set;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import javax.swing.*;
import java.lang.reflect.InvocationTargetException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to set a function prototype in Ghidra
 * This handler processes HTTP requests to set a function prototype based on the
 * provided address and prototype string.
 */
public final class SetFunctionPrototype extends Handler {
	/**
	 * Constructor for the SetFunctionPrototype handler
	 *
	 * @param tool The Ghidra plugin tool instance
	 */
	public SetFunctionPrototype(PluginTool tool) {
		super(tool, "/set_function_prototype");
	}

	/**
	 * Result class to encapsulate success/failure and error messages
	 */
	private static class PrototypeResult {
		/** Indicates if the prototype was set successfully */
		private final boolean success;

		/** Detailed error message if the operation failed */
		private final String errorMessage;

		/**
		 * Constructor for PrototypeResult
		 *
		 * @param success      Indicates if the operation was successful
		 * @param errorMessage Detailed error message if applicable
		 */
		public PrototypeResult(boolean success, String errorMessage) {
			this.success = success;
			this.errorMessage = errorMessage;
		}

		/**
		 * Getters for success status and error message
		 */
		public boolean isSuccess() {
			return success;
		}

		/**
		 * Get the error message if the operation failed
		 *
		 * @return Error message or empty string if successful
		 */
		public String getErrorMessage() {
			return errorMessage;
		}
	}

	/**
	 * Handle the HTTP request to set a function prototype
	 *
	 * @param exchange The HTTP exchange containing the request and response
	 * @throws Exception If an error occurs during processing
	 */
	@Override
	public void handle(HttpExchange exchange) throws Exception {
		Map<String, Object> params = parseJsonParams(exchange);
            String functionAddress = (String) params.get("function_address");
            String prototype = (String) params.get("prototype");
            String callingConvention = (String) params.get("calling_convention");

		// Call the set prototype function and get detailed result
		PrototypeResult result = setFunctionPrototype(functionAddress, prototype, callingConvention);

		if (result.isSuccess()) {
			// Even with successful operations, include any warning messages for debugging
			String successMsg = "Function prototype set successfully";
			if (!result.getErrorMessage().isEmpty()) {
				successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
			}
			sendResponse(exchange, successMsg);
		} else {
			// Return the detailed error message to the client
			sendResponse(exchange, "Failed to set function prototype: " + result.getErrorMessage());
		}
	}

	/**
	 * Set the function prototype for a given function address without calling convention
	 * @param functionAddrStr The address of the function as a string
	 * @param prototype       The prototype string to set
	 * @return PrototypeResult indicating success or failure with error message
	 */
	private PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        return setFunctionPrototype(functionAddrStr, prototype, null);
    }

	/**
	 * Set the function prototype for a given function address
	 *
	 * @param functionAddrStr The address of the function as a string
	 * @param prototype       The prototype string to set
	 * @param callingConvention The calling convention to set (optional)
	 * @return PrototypeResult indicating success or failure with error message
	 */
	private PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype, String callingConvention) {
		// Input validation
		Program program = getCurrentProgram(tool);
		if (program == null)
			return new PrototypeResult(false, "No program loaded");
		if (functionAddrStr == null || functionAddrStr.isEmpty()) {
			return new PrototypeResult(false, "Function address is required");
		}
		if (prototype == null || prototype.isEmpty()) {
			return new PrototypeResult(false, "Function prototype is required");
		}

		final StringBuilder errorMessage = new StringBuilder();
		final AtomicBoolean success = new AtomicBoolean(false);

		try {
			SwingUtilities.invokeAndWait(
					() -> applyFunctionPrototype(program, functionAddrStr, prototype, callingConvention, success, errorMessage));
		} catch (InterruptedException | InvocationTargetException e) {
			String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
			errorMessage.append(msg);
			Msg.error(this, msg, e);
		}

		return new PrototypeResult(success.get(), errorMessage.toString());
	}

	/**
	 * Apply the function prototype in a Swing thread to avoid blocking the UI
	 *
	 * @param program         The current program
	 * @param functionAddrStr The address of the function as a string
	 * @param prototype       The prototype string to set
	 * @param callingConvention The calling convention to set (optional)
	 * @param success         Atomic boolean to indicate success
	 * @param errorMessage    StringBuilder to collect error messages
	 */
	private void applyFunctionPrototype(Program program, String functionAddrStr, String prototype,
			String callingConvention, AtomicBoolean success, StringBuilder errorMessage) {
		try {
			// Get the address and function
			Address addr = program.getAddressFactory().getAddress(functionAddrStr);
			Function func = program.getListing().getFunctionContaining(addr);

			if (func == null) {
				String msg = "Could not find function at address: " + functionAddrStr;
				errorMessage.append(msg);
				Msg.error(this, msg);
				return;
			}

			Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);

			// Store original prototype as a comment for reference
			addPrototypeComment(program, func, prototype);

			// Use ApplyFunctionSignatureCmd to parse and apply the signature
			parseFunctionSignatureAndApply(program, addr, prototype, callingConvention, success, errorMessage);

		} catch (Exception e) {
			String msg = "Error setting function prototype: " + e.getMessage();
			errorMessage.append(msg);
			Msg.error(this, msg, e);
		}
	}

	/**
	 * Add a comment to the function indicating the prototype being set
	 *
	 * @param program   The current program
	 * @param func      The function to add the comment to
	 * @param prototype The prototype string being set
	 */
	private void addPrototypeComment(Program program, Function func, String prototype) {
		int txComment = program.startTransaction("Add prototype comment");
		try {
			program.getListing().setComment(
					func.getEntryPoint(),
					CommentType.PLATE,
					"Setting prototype: " + prototype);
		} finally {
			program.endTransaction(txComment, true);
		}
	}

	/**
	 * Parse the function signature from the prototype string and apply it to the
	 * function
	 *
	 * @param program      The current program
	 * @param addr         The address of the function
	 * @param prototype    The prototype string to set
	 * @param callingConvention The calling convention to set (optional)
	 * @param success      Atomic boolean to indicate success
	 * @param errorMessage StringBuilder to collect error messages
	 */
	private void parseFunctionSignatureAndApply(Program program, Address addr, String prototype,
			String callingConvention, AtomicBoolean success, StringBuilder errorMessage) {
		// Use ApplyFunctionSignatureCmd to parse and apply the signature
		int txProto = program.startTransaction("Set function prototype");
		try {
			// Get data type manager
			DataTypeManager dtm = program.getDataTypeManager();

			// Get data type manager service
			DataTypeManagerService dtms = tool
					.getService(DataTypeManagerService.class);

			// Create function signature parser
			FunctionSignatureParser parser = new FunctionSignatureParser(
					dtm, dtms);

			// Parse the prototype into a function signature
			FunctionDefinitionDataType sig = parser.parse(null, prototype);

			if (sig == null) {
				String msg = "Failed to parse function prototype";
				errorMessage.append(msg);
				Msg.error(this, msg);
				return;
			}

			// Create and apply the command
			ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
					addr, sig, SourceType.USER_DEFINED);

			// Apply the command to the program
			boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

			if (cmdResult) {
				// Apply calling convention if specified
                if (callingConvention != null && !callingConvention.isEmpty()) {
                    applyCallingConvention(program, addr, callingConvention, errorMessage);
                }
				success.set(true);
				Msg.info(this, "Successfully applied function signature");
			} else {
				String msg = "Command failed: " + cmd.getStatusMsg();
				errorMessage.append(msg);
				Msg.error(this, msg);
			}
		} catch (Exception e) {
			String msg = "Error applying function signature: " + e.getMessage();
			errorMessage.append(msg);
			Msg.error(this, msg, e);
		} finally {
			program.endTransaction(txProto, success.get());
		}
	}

	/**
	 * Apply the specified calling convention to the function at the given address
	 *
	 * @param program         The current program
	 * @param addr            The address of the function
	 * @param callingConvention The calling convention to set
	 * @param errorMessage    StringBuilder to collect error messages
	 */
	private void applyCallingConvention(Program program, Address addr, String callingConvention, StringBuilder errorMessage) {
        try {
            Function func = getFunctionForAddress(program, addr);
            if (func == null) {
                errorMessage.append("Could not find function to set calling convention");
                return;
            }

            // Get the program's calling convention manager
            ghidra.program.model.lang.CompilerSpec compilerSpec = program.getCompilerSpec();
            ghidra.program.model.lang.PrototypeModel callingConv = null;
            
            // Get all available calling conventions
            ghidra.program.model.lang.PrototypeModel[] available = compilerSpec.getCallingConventions();
            
            // Try to find matching calling convention by name
            String targetName = callingConvention.toLowerCase();
            for (ghidra.program.model.lang.PrototypeModel model : available) {
                String modelName = model.getName().toLowerCase();
                if (modelName.equals(targetName) || 
                    modelName.equals("__" + targetName) ||
                    modelName.replace("__", "").equals(targetName.replace("__", ""))) {
                    callingConv = model;
                    break;
                }
            }
            
            if (callingConv != null) {
                func.setCallingConvention(callingConv.getName());
                Msg.info(this, "Set calling convention to: " + callingConv.getName());
            } else {
                String msg = "Unknown calling convention: " + callingConvention;
                errorMessage.append(msg);
                Msg.warn(this, msg);
                
                // List available calling conventions for debugging
                StringBuilder availList = new StringBuilder("Available: ");
                for (ghidra.program.model.lang.PrototypeModel model : available) {
                    availList.append(model.getName()).append(", ");
                }
                Msg.info(this, availList.toString());
            }
            
        } catch (Exception e) {
            String msg = "Error setting calling convention: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }
}
