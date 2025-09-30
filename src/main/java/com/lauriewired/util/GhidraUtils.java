package com.lauriewired.util;

import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.CommentType;
import ghidra.util.Msg;

import javax.swing.*;
import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

import ghidra.app.services.DataTypeManagerService;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;

/**
 * Utility class for Ghidra-related operations.
 * Provides methods to interact with the current program, resolve data types,
 * and set comments at specific addresses.
 */
public final class GhidraUtils {
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
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            // Check if the name matches exactly (case-sensitive) 
            if (dt.getName().equals(name)) {
                return dt;
            }
            // For case-insensitive, we want an exact match except for case
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
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
