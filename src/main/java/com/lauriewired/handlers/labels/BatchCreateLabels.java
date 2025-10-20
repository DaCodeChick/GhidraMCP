package com.lauriewired.handlers.labels;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;

import java.io.IOException;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.List;
import java.util.Map;
import javax.swing.SwingUtilities;

import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;

public final class BatchCreateLabels extends Handler {
	/**
	 * Constructs a new BatchCreateLabels handler.
	 *
	 * @param tool The PluginTool instance to interact with Ghidra.
	 */
	public BatchCreateLabels(PluginTool tool) {
		super(tool, "/batch_create_labels");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, Object> params = parseJsonParams(exchange);
		List<Map<String, String>> labels = convertToMapList(params.get("labels"));
		String result = batchCreateLabels(labels);
		sendResponse(exchange, result);
	}

	/**
	 * Batch creates labels in the current program.
	 *
	 * @param labels A list of maps, each containing "address" and "name" keys for the label.
	 * @return A JSON string summarizing the results of the operation.
	 */
	private String batchCreateLabels(List<Map<String, String>> labels) {
		Program program = getCurrentProgram(tool);
		if (program == null) {
			return "{\"error\": \"No program loaded\"}";
		}

		if (labels == null || labels.isEmpty()) {
			return "{\"error\": \"No labels provided\"}";
		}

		final StringBuilder result = new StringBuilder();
		result.append("{");
		final AtomicInteger successCount = new AtomicInteger(0);
		final AtomicInteger skipCount = new AtomicInteger(0);
		final AtomicInteger errorCount = new AtomicInteger(0);
		final List<String> errors = new ArrayList<>();

		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Batch Create Labels");
				try {
					SymbolTable symbolTable = program.getSymbolTable();

					for (Map<String, String> labelEntry : labels) {
						String addressStr = labelEntry.get("address");
						String labelName = labelEntry.get("name");

						if (addressStr == null || addressStr.isEmpty()) {
							errors.add("Missing address in label entry");
							errorCount.incrementAndGet();
							continue;
						}

						if (labelName == null || labelName.isEmpty()) {
							errors.add("Missing name for address " + addressStr);
							errorCount.incrementAndGet();
							continue;
						}

						try {
							Address address = program.getAddressFactory().getAddress(addressStr);
							if (address == null) {
								errors.add("Invalid address: " + addressStr);
								errorCount.incrementAndGet();
								continue;
							}

							// Check if label already exists
							Symbol[] existingSymbols = symbolTable.getSymbols(address);
							boolean labelExists = false;
							for (Symbol symbol : existingSymbols) {
								if (symbol.getName().equals(labelName) && symbol.getSymbolType() == SymbolType.LABEL) {
									labelExists = true;
									break;
								}
							}

							if (labelExists) {
								skipCount.incrementAndGet();
								continue;
							}

							// Create the label
							Symbol newSymbol = symbolTable.createLabel(address, labelName, SourceType.USER_DEFINED);
							if (newSymbol != null) {
								successCount.incrementAndGet();
							} else {
								errors.add("Failed to create label '" + labelName + "' at " + addressStr);
								errorCount.incrementAndGet();
							}

						} catch (Exception e) {
							errors.add("Error at " + addressStr + ": " + e.getMessage());
							errorCount.incrementAndGet();
							Msg.error(this, "Error creating label at " + addressStr, e);
						}
					}

				} catch (Exception e) {
					errors.add("Transaction error: " + e.getMessage());
					Msg.error(this, "Error in batch create labels transaction", e);
				} finally {
					program.endTransaction(tx, successCount.get() > 0);
				}
			});

			result.append("\"success\": true, ");
			result.append("\"labels_created\": ").append(successCount.get()).append(", ");
			result.append("\"labels_skipped\": ").append(skipCount.get()).append(", ");
			result.append("\"labels_failed\": ").append(errorCount.get());

			if (!errors.isEmpty()) {
				result.append(", \"errors\": [");
				for (int i = 0; i < errors.size(); i++) {
					if (i > 0) result.append(", ");
					result.append("\"").append(errors.get(i).replace("\"", "\\\"")).append("\"");
				}
				result.append("]");
			}

		} catch (Exception e) {
			result.append("\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\"");
		}

		result.append("}");
		return result.toString();
	}
}
