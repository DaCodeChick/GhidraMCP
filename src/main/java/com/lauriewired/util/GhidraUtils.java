package com.lauriewired.util;

import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import javax.swing.*;
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicBoolean;

import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/** Utility class for Ghidra-related functions */
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
	 * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT)
	 */
	public static boolean setCommentAtAddress(PluginTool tool,
			String addressStr, String comment, int commentType, String transactionName) {
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
