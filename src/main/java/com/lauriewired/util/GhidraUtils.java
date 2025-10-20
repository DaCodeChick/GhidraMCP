package com.lauriewired.util;

import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import javax.swing.*;
import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Utility class for Ghidra-related operations.
 * Provides methods to interact with the current program, resolve data types,
 * and set comments at specific addresses.
 */
public final class GhidraUtils {
	/**
	 * Creates a label at the specified address in the current program.
	 *
	 * @param tool      The plugin tool to get the current program
	 * @param addressStr The address as a string where the label should be created
	 * @param labelName  The name of the label to create
	 * @return A message indicating success or failure
	 */
	public static String createLabel(PluginTool tool, String addressStr, String labelName) {
		Program program = getCurrentProgram(tool);
		if (program == null) {
			return "No program loaded";
		}

		if (addressStr == null || addressStr.isEmpty()) {
			return "Address is required";
		}

		if (labelName == null || labelName.isEmpty()) {
			return "Label name is required";
		}

		try {
			Address address = program.getAddressFactory().getAddress(addressStr);
			if (address == null) {
				return "Invalid address: " + addressStr;
			}

			SymbolTable symbolTable = program.getSymbolTable();

			// Check if a label with this name already exists at this address
			Symbol[] existingSymbols = symbolTable.getSymbols(address);
			for (Symbol symbol : existingSymbols) {
				if (symbol.getName().equals(labelName) && symbol.getSymbolType() == SymbolType.LABEL) {
					return "Label '" + labelName + "' already exists at address " + addressStr;
				}
			}

			// Check if the label name is already used elsewhere (optional warning)
			SymbolIterator existingLabels = symbolTable.getSymbolIterator(labelName, true);
			if (existingLabels.hasNext()) {
				Symbol existingSymbol = existingLabels.next();
				if (existingSymbol.getSymbolType() == SymbolType.LABEL) {
					// Allow creation but warn about duplicate name
					Msg.warn(this, "Label name '" + labelName + "' already exists at address " +
							existingSymbol.getAddress() + ". Creating duplicate at " + addressStr);
				}
			}

			// Create the label
			int transactionId = program.startTransaction("Create Label");
			try {
				Symbol newSymbol = symbolTable.createLabel(address, labelName, SourceType.USER_DEFINED);
				if (newSymbol != null) {
					return "Successfully created label '" + labelName + "' at address " + addressStr;
				} else {
					return "Failed to create label '" + labelName + "' at address " + addressStr;
				}
			} catch (Exception e) {
				return "Error creating label: " + e.getMessage();
			} finally {
				program.endTransaction(transactionId, true);
			}

		} catch (Exception e) {
			return "Error processing request: " + e.getMessage();
		}
	}

	/**
	 * Decompiles the given function in the specified program and returns the C code as a string.
	 *
	 * @param func    The function to decompile
	 * @param program The program containing the function
	 * @return The decompiled C code as a string, or null if decompilation fails
	 */
	public static String decompileFunctionInProgram(Function func, Program program) {
		try {
			DecompInterface decomp = new DecompInterface();
			decomp.openProgram(program);
			DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());

			if (result != null && result.decompileCompleted()) {
				return result.getDecompiledFunction().getC();
			}
		} catch (Exception e) {
			Msg.error(GhidraUtils.class, "Error decompiling function in external program", e);
		}
		return null;
	}

	/**
	 * Searches for a data type by name in all categories of the given DataTypeManager.
	 *
	 * @param dtm      The DataTypeManager to search in
	 * @param typeName The name of the data type to search for
	 * @return The found DataType, or null if not found
	 */
	public static DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
		// Try exact match first
		DataType result = searchByNameInAllCategories(dtm, typeName);
		if (result != null) {
			return result;
		}

		// Try lowercase
		return searchByNameInAllCategories(dtm, typeName.toLowerCase());
	}

	/**
	 * Gets the category name of a data type.
	 * If the data type is in the root category, returns "builtin".
	 * Otherwise, returns the last part of the category path in lowercase.
	 * 
	 * @param dt the data type
	 * @return the category name
	 */
	public static String getCategoryName(DataType dt) {
		if (dt.getCategoryPath() == null) {
			return "builtin";
		}
		String categoryPath = dt.getCategoryPath().getPath();
		if (categoryPath.isEmpty() || categoryPath.equals("/")) {
			return "builtin";
		}

		// Extract the last part of the category path
		String[] parts = categoryPath.split("/");
		return parts[parts.length - 1].toLowerCase();
	}

	/**
	 * Gets the current program from the specified plugin tool.
	 *
	 * @param tool the plugin tool
	 * @return the current program, or null if not available
	 */
	public static Program getCurrentProgram(PluginTool tool) {
		ProgramManager pm = tool.getService(ProgramManager.class);
		return pm != null ? pm.getCurrentProgram() : null;
	}

	/**
	 * Gets the function at or containing the specified address in the given program.
	 *
	 * @param program the program to search in
	 * @param addr    the address to look for
	 * @return the function at or containing the address, or null if none found
	 */
	public static Function getFunctionForAddress(Program program, Address addr) {
		Function func = program.getFunctionManager().getFunctionAt(addr);
		if (func == null) {
			func = program.getFunctionManager().getFunctionContaining(addr);
		}
		return func;
	}

	/**
	 * Renames the data at the specified address in the current program.
	 * If the data exists, it updates its name; otherwise, it creates a new label.
	 *
	 * @param tool       the plugin tool
	 * @param addressStr the address of the data as a string
	 * @param newName    the new name for the data
	 */
	public static void renameDataAtAddress(PluginTool tool, String addressStr, String newName) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return;

		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Rename data");
				try {
					Address addr = program.getAddressFactory().getAddress(addressStr);
					Listing listing = program.getListing();
					Data data = listing.getDefinedDataAt(addr);
					if (data != null) {
						SymbolTable symTable = program.getSymbolTable();
						Symbol symbol = symTable.getPrimarySymbol(addr);
						if (symbol != null) {
							symbol.setName(newName, SourceType.USER_DEFINED);
						} else {
							symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
						}
					}
				} catch (Exception e) {
					Msg.error(this, "Rename data error", e);
				} finally {
					program.endTransaction(tx, true);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			Msg.error(this, "Failed to execute rename data on Swing thread", e);
		}
	}

	/**
	 * Resolves a data type by name, handling common types and pointer types
	 *
	 * @param tool     The plugin tool to use for services
	 * @param dtm      The data type manager
	 * @param typeName The type name to resolve
	 * @return The resolved DataType, or null if not found
	 */
	public static DataType resolveDataType(PluginTool tool, DataTypeManager dtm, String typeName) {
		DataTypeManagerService dtms = tool.getService(DataTypeManagerService.class);
		DataTypeManager[] managers = dtms.getDataTypeManagers();
		DataType dt = null;

		List<DataTypeManager> managerList = new ArrayList<>();
		for (DataTypeManager manager : managers) {
			if (manager != dtm)
				managerList.add(manager);
		}
		managerList.addFirst(dtm);

		DataTypeParser parser = null;

		for (DataTypeManager manager : managerList) {
			try {
				parser = new DataTypeParser(manager, null, null, AllowedDataTypes.ALL);
				dt = parser.parse(typeName);
				if (dt != null) {
					return dt; // Found a successful parse, return
				}
			} catch (Exception e) {
				// Continue to next manager if this one fails
			}
		}

		// Fallback to int if we couldn't find it
		Msg.warn(GhidraUtils.class, "Unknown type: " + typeName + ", defaulting to int");
		return dtm.getDataType("/int");
	}

	/**
	 * Helper method to search for a data type by name in all categories of the given DataTypeManager.
	 * This method performs a case-sensitive search first, then a case-insensitive search.
	 *
	 * @param dtm  The DataTypeManager to search in
	 * @param name The name of the data type to search for
	 * @return The found DataType, or null if not found
	 */
	public static DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
		// Get all data types from the manager
		Iterator<DataType> allTypes = dtm.getAllDataTypes();
		DataType fuzzyCandidate = null;
		while (allTypes.hasNext()) {
			DataType dt = allTypes.next();
			// Check if the name matches exactly (case-sensitive) 
			if (dt.getName().equals(name)) {
				return dt;
			// For case-insensitive, we want an exact match except for case
			} else if (fuzzyCandidate == null && dt.getName().equalsIgnoreCase(name)) {
				// For case-insensitive, we want an exact match except for case
				// We want to check ALL types for exact matches, not just the first one
				// We want to stop on the very first match for fuzzy matching
				fuzzyCandidate = dt;
			}
		}
		return fuzzyCandidate;
	}

	/**
	 * Sets a comment at the specified address in the current program.
	 *
	 * @param tool            the plugin tool
	 * @param addressStr      the address as a string
	 * @param comment         the comment to set
	 * @param commentType     the type of comment (e.g., CodeUnit.PLATE_COMMENT)
	 * @param transactionName the name of the transaction for logging
	 * @return true if successful, false otherwise
	 */
	public static boolean setCommentAtAddress(PluginTool tool,
			String addressStr, String comment, CommentType commentType, String transactionName) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return false;
		if (addressStr == null || addressStr.isEmpty() || comment == null)
			return false;

		AtomicBoolean success = new AtomicBoolean(false);

		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction(transactionName);
				try {
					Address addr = program.getAddressFactory().getAddress(addressStr);
					program.getListing().setComment(addr, commentType, comment);
					success.set(true);
				} catch (Exception e) {
					Msg.error(GhidraUtils.class, "Error setting " + transactionName.toLowerCase(), e);
				} finally {
					program.endTransaction(tx, success.get());
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			Msg.error(GhidraUtils.class,
					"Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
		}

		return success.get();
	}
}
