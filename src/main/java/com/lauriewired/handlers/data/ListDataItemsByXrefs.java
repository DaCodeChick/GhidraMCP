package com.lauriewired.handlers.data;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.ref.ReferenceManager;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class ListDataItemsByXrefs extends Handler {
	/**
	 * Data structure to hold information about a data item.
	 */
	private static class DataItemInfo {
		/** The address of the data item. */
		final String address;

		/** The label of the data item. */
		final String label;

		/** The type name of the data item. */
		final String typeName;

		/** The length of the data item. */
		final int length;

		/** The number of cross-references to the data item. */
		final int xrefCount;

		/**
		 * Constructs a new DataItemInfo instance.
		 * @param address The address of the data item.
		 * @param label The label of the data item.
		 * @param typeName The type name of the data item.
		 * @param length The length of the data item.
		 * @param xrefCount The number of cross-references to the data item.
		 */
		DataItemInfo(String address, String label, String typeName, int length, int xrefCount) {
			this.address = address;
			this.label = label;
			this.typeName = typeName;
			this.length = length;
			this.xrefCount = xrefCount;
		}
	}
	
	/**
	 * Constructs a new ListDataItemsByXrefs handler.
	 * 
	 * @param tool The PluginTool instance to use for accessing the current program.
	 */
	public ListDataItemsByXrefs(PluginTool tool) {
		super(tool, "/list_data_items_by_xrefs");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> qparams = parseQueryParams(exchange);
		int offset = parseIntOrDefault(qparams.get("offset"), 0);
		int limit  = parseIntOrDefault(qparams.get("limit"),  100);
		String format = qparams.getOrDefault("format", "text");
		sendResponse(exchange, listDataItemsByXrefs(offset, limit, format));
	}

	/**
	 * Formats the list of data items as JSON.
	 *
	 * @param dataItems The list of data items to format.
	 * @param offset    The offset for pagination.
	 * @param limit     The limit for pagination.
	 * @return A JSON representation of the data items.
	 */
	private String formatDataItemsAsJson(List<DataItemInfo> dataItems, int offset, int limit) {
		StringBuilder json = new StringBuilder();
		json.append("[");

		int start = Math.min(offset, dataItems.size());
		int end = Math.min(start + limit, dataItems.size());

		for (int i = start; i < end; i++) {
			if (i > start) json.append(",");

			DataItemInfo item = dataItems.get(i);

			json.append("\n  {");
			json.append("\n    \"address\": \"").append(item.address).append("\",");
			json.append("\n    \"name\": \"").append(escapeJson(item.label)).append("\",");
			json.append("\n    \"type\": \"").append(escapeJson(item.typeName)).append("\",");

			String sizeStr = (item.length == 1) ? "1 byte" : item.length + " bytes";
			json.append("\n    \"size\": \"").append(sizeStr).append("\",");
			json.append("\n    \"xref_count\": ").append(item.xrefCount);
			json.append("\n  }");
		}

		json.append("\n]");
		return json.toString();
	}

	/**
	 * Formats the list of data items as plain text.
	 *
	 * @param dataItems The list of data items to format.
	 * @param offset    The offset for pagination.
	 * @param limit     The limit for pagination.
	 * @return A plain text representation of the data items.
	 */
	private String formatDataItemsAsText(List<DataItemInfo> dataItems, int offset, int limit) {
		List<String> lines = new ArrayList<>();

		int start = Math.min(offset, dataItems.size());
		int end = Math.min(start + limit, dataItems.size());

		for (int i = start; i < end; i++) {
			DataItemInfo item = dataItems.get(i);

			StringBuilder line = new StringBuilder();
			line.append(item.label);
			line.append(" @ ").append(item.address);
			line.append(" [").append(item.typeName).append("]");

			String sizeStr = (item.length == 1) ? "1 byte" : item.length + " bytes";
			line.append(" (").append(sizeStr).append(")");
			line.append(" - ").append(item.xrefCount).append(" xrefs");

			lines.add(line.toString());
		}

		return String.join("\n", lines);
	}

	/**
	 * Lists data items by their cross-references.
	 *
	 * @param offset The offset for pagination.
	 * @param limit  The limit for pagination.
	 * @param format The response format (text or json).
	 * @return A string representation of the data items.
	 */
	private String listDataItemsByXrefs(int offset, int limit, String format) {
		Program program = getCurrentProgram(tool);
		if (program == null) return "No program loaded";

		// Collect all data items with their xref counts
		List<DataItemInfo> dataItems = new ArrayList<>();
		ReferenceManager refMgr = program.getReferenceManager();

		for (MemoryBlock block : program.getMemory().getBlocks()) {
			DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
			while (it.hasNext()) {
				Data data = it.next();
				if (block.contains(data.getAddress())) {
					// Count xrefs to this data item
					Address addr = data.getAddress();
					int xrefCount = refMgr.getReferenceCountTo(addr);

					String label = data.getLabel() != null ? data.getLabel() :
								   "DAT_" + addr.toString().replace(":", "");

					DataType dt = data.getDataType();
					String typeName = (dt != null) ? dt.getName() : "undefined";
					int length = data.getLength();

					dataItems.add(new DataItemInfo(addr.toString().replace(":", ""), label, typeName, length, xrefCount));
				}
			}
		}

		// Sort by xref count (descending)
		dataItems.sort((a, b) -> Integer.compare(b.xrefCount, a.xrefCount));

		// Format output based on requested format
		if ("json".equalsIgnoreCase(format)) {
			return formatDataItemsAsJson(dataItems, offset, limit);
		} else {
			return formatDataItemsAsText(dataItems, offset, limit);
		}
	}
}
