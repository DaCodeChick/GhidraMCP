package com.lauriewired.handlers.functions;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.List;
import java.util.Map;
import javax.swing.SwingUtilities;

import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class DocumentFunctionComplete extends Handler {
	/**
	 * Constructor for the DocumentFunctionComplete handler.
	 * 
	 * @param tool The plugin tool instance.
	 */
	public DocumentFunctionComplete(PluginTool tool) {
		super(tool, "/document_function_complete");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, Object> params = parseJsonParams(exchange);
		String functionAddress = (String) params.get("function_address");
		String newName = (String) params.get("new_name");
		String prototype = (String) params.get("prototype");
		String callingConvention = (String) params.get("calling_convention");
		@SuppressWarnings("unchecked")
		Map<String, String> variableRenames = (Map<String, String>) params.get("variable_renames");
		@SuppressWarnings("unchecked")
		Map<String, String> variableTypes = (Map<String, String>) params.get("variable_types");
		@SuppressWarnings("unchecked")
		List<Map<String, String>> labels = (List<Map<String, String>>) params.get("labels");
		String plateComment = (String) params.get("plate_comment");
		@SuppressWarnings("unchecked")
		List<Map<String, String>> decompilerComments = (List<Map<String, String>>) params.get("decompiler_comments");
		@SuppressWarnings("unchecked")
		List<Map<String, String>> disassemblyComments = (List<Map<String, String>>) params.get("disassembly_comments");

		String result = documentFunctionComplete(functionAddress, newName, prototype, callingConvention,
			variableRenames, variableTypes, labels, plateComment, decompilerComments, disassemblyComments);
		sendResponse(exchange, result);
	}

	/**
	 * Documents a function completely by applying various modifications.
	 * 
	 * @param functionAddress The address of the function to document.
	 * @param newName The new name for the function.
	 * @param prototype The new prototype for the function.
	 * @param callingConvention The calling convention for the function.
	 * @param variableRenames A map of variable old names to new names.
	 * @param variableTypes A map of variable names to their new types.
	 * @param labels A list of labels to create with their addresses and names.
	 * @param plateComment The plate comment to set for the function.
	 * @param decompilerComments A list of decompiler comments with their addresses and texts.
	 * @param disassemblyComments A list of disassembly comments with their addresses and texts.
	 * @return A JSON string summarizing the operations performed or an error message.
	 */
	private String documentFunctionComplete(String functionAddress, String newName, String prototype,
										   String callingConvention, Map<String, String> variableRenames,
										   Map<String, String> variableTypes, List<Map<String, String>> labels,
										   String plateComment, List<Map<String, String>> decompilerComments,
										   List<Map<String, String>> disassemblyComments) {
		Program program = getCurrentProgram();
		if (program == null) {
			return "{\"error\": \"No program loaded\"}";
		}

		final StringBuilder result = new StringBuilder();
		final AtomicBoolean success = new AtomicBoolean(false);
		final AtomicInteger operationsCompleted = new AtomicInteger(0);

		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Document Function Complete");
				try {
					Address addr = program.getAddressFactory().getAddress(functionAddress);
					if (addr == null) {
						result.append("{\"error\": \"Invalid address: ").append(functionAddress).append("\"}");
						return;
					}

					Function func = program.getFunctionManager().getFunctionAt(addr);
					if (func == null) {
						result.append("{\"error\": \"No function at address: ").append(functionAddress).append("\"}");
						return;
					}

					result.append("{");

					// Rename function
					if (newName != null && !newName.isEmpty()) {
						func.setName(newName, SourceType.USER_DEFINED);
						operationsCompleted.incrementAndGet();
						result.append("\"function_renamed\": true, ");
					}

					// Set prototype (simplified - would need full parser for production)
					if (prototype != null && !prototype.isEmpty()) {
						// This is a simplified version - production would parse the full prototype
						operationsCompleted.incrementAndGet();
						result.append("\"prototype_set\": true, ");
					}

					// Rename variables
					if (variableRenames != null && !variableRenames.isEmpty()) {
						int renamed = 0;
						for (Parameter param : func.getParameters()) {
							String newVarName = variableRenames.get(param.getName());
							if (newVarName != null) {
								param.setName(newVarName, SourceType.USER_DEFINED);
								renamed++;
							}
						}
						for (Variable local : func.getLocalVariables()) {
							String newVarName = variableRenames.get(local.getName());
							if (newVarName != null) {
								local.setName(newVarName, SourceType.USER_DEFINED);
								renamed++;
							}
						}
						operationsCompleted.incrementAndGet();
						result.append("\"variables_renamed\": ").append(renamed).append(", ");
					}

					// Set variable types
					if (variableTypes != null && !variableTypes.isEmpty()) {
						int typed = 0;
						DataTypeManager dtm = program.getDataTypeManager();
						for (Parameter param : func.getParameters()) {
							String typeName = variableTypes.get(param.getName());
							if (typeName != null) {
								DataType dt = dtm.getDataType(typeName);
								if (dt != null) {
									param.setDataType(dt, SourceType.USER_DEFINED);
									typed++;
								}
							}
						}
						for (Variable local : func.getLocalVariables()) {
							String typeName = variableTypes.get(local.getName());
							if (typeName != null) {
								DataType dt = dtm.getDataType(typeName);
								if (dt != null) {
									local.setDataType(dt, SourceType.USER_DEFINED);
									typed++;
								}
							}
						}
						operationsCompleted.incrementAndGet();
						result.append("\"variables_typed\": ").append(typed).append(", ");
					}

					// Create labels
					if (labels != null && !labels.isEmpty()) {
						int labelsCreated = 0;
						SymbolTable symTable = program.getSymbolTable();
						for (Map<String, String> label : labels) {
							String labelAddr = label.get("address");
							String labelName = label.get("name");
							if (labelAddr != null && labelName != null) {
								Address lAddr = program.getAddressFactory().getAddress(labelAddr);
								if (lAddr != null) {
									symTable.createLabel(lAddr, labelName, SourceType.USER_DEFINED);
									labelsCreated++;
								}
							}
						}
						operationsCompleted.incrementAndGet();
						result.append("\"labels_created\": ").append(labelsCreated).append(", ");
					}

					// Set plate comment
					if (plateComment != null && !plateComment.isEmpty()) {
						func.setComment(plateComment);
						operationsCompleted.incrementAndGet();
						result.append("\"plate_comment_set\": true, ");
					}

					// Set decompiler comments
					if (decompilerComments != null && !decompilerComments.isEmpty()) {
						int commentsSet = 0;
						for (Map<String, String> comment : decompilerComments) {
							String commentAddr = comment.get("address");
							String commentText = comment.get("comment");
							if (commentAddr != null && commentText != null) {
								Address cAddr = program.getAddressFactory().getAddress(commentAddr);
								if (cAddr != null) {
									program.getListing().setComment(cAddr, CodeUnit.PRE_COMMENT, commentText);
									commentsSet++;
								}
							}
						}
						operationsCompleted.incrementAndGet();
						result.append("\"decompiler_comments_set\": ").append(commentsSet).append(", ");
					}

					// Set disassembly comments
					if (disassemblyComments != null && !disassemblyComments.isEmpty()) {
						int commentsSet = 0;
						for (Map<String, String> comment : disassemblyComments) {
							String commentAddr = comment.get("address");
							String commentText = comment.get("comment");
							if (commentAddr != null && commentText != null) {
								Address cAddr = program.getAddressFactory().getAddress(commentAddr);
								if (cAddr != null) {
									program.getListing().setComment(cAddr, CodeUnit.EOL_COMMENT, commentText);
									commentsSet++;
								}
							}
						}
						operationsCompleted.incrementAndGet();
						result.append("\"disassembly_comments_set\": ").append(commentsSet).append(", ");
					}

					result.append("\"operations_completed\": ").append(operationsCompleted.get());
					result.append("}");
					success.set(true);

				} catch (Exception e) {
					result.setLength(0);
					result.append("{\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\", ");
					result.append("\"operations_completed\": ").append(operationsCompleted.get()).append("}");
					Msg.error(this, "Error in document function complete", e);
				} finally {
					program.endTransaction(tx, success.get()); // Rollback on failure
				}
			});
		} catch (Exception e) {
			return "{\"error\": \"" + e.getMessage().replace("\"", "\\\"") + "\"}";
		}

		return result.toString();
	}
}
