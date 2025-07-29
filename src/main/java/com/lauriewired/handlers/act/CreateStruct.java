package com.lauriewired.handlers.act;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StructureDataType;

import java.lang.reflect.InvocationTargetException;
import java.io.IOException;
import java.util.*;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class CreateStruct extends Handler {
	public CreateStruct(PluginTool tool) {
		super("/create_struct");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOExcep
		, String> params = parsePostParam
		e = params.get("name");
		egory = params.get("category");
		= parseIntOrDefault(params.get("size"), 0);

		
			ll || name.isEmpty()) {
			exchang
		
		 
		sendResponse(exchange, createStruct(name, category, (int) size, membersJson));
	}

	private String createStruct(String name, String category, int size, String membersJson) {
		Program program = getCurrentProgram();
		if (program == null)
			return "No program loaded";

		final AtomicReference<String> result = new AtomicReference<>();
		try {
			SwingUtilities.invokeAndWait(() -> {
				int txId = program.startTransaction("Create Struct");
				boolean success = false;
				try {
					DataTypeManager dtm = program.getDataTypeManager();
					CategoryPath path = new CategoryPath(category == null ? "/" : category);

					if (dtm.getDataType(path, name) != null) {
						result.set("Error: Struct " + name + " already exists in category " + path);
						return;
					}
					StructureDataType newStruct = new StructureDataType(path, name, size, dtm);

					StringBuilder responseBuilder = new StringBuilder(
							"Struct " + name + " created successfully in category " + path);

					if (membersJson != null && !membersJson.isEmpty()) {
						Gson gson = new Gson();
						StructMember[] members = gson.fromJson(membersJson, StructMember[].class);

						int membersAdded = 0;
						for (StructMember member : members) {
							DataType memberDt = resolveDataType(dtm, member.type);
							if (memberDt == null) {
								responseBuilder.append("\nError: Could not resolve data type '").append(member.type)
										.append("' for member '").append(member.name)
										.append("'. Aborting further member creation.");
								break;
							}

							if (member.offset != -1) {
								newStruct.insertAtOffset((int) member.offset, memberDt, -1, member.name,
										member.comment);
							} else {
								newStruct.add(memberDt, member.name, member.comment);
							}
							membersAdded++;
						}
						responseBuilder.append("\nAdded ").append(membersAdded).append(" members.");
					}
					dtm.addDataType(newStruct, DataTypeConflictHandler.DEFAULT_HANDLER);
					result.set(responseBuilder.toString());
					success = true;
				} catch (Exception e) {
					result.set("Error: Failed to create struct: " + e.getMessage());
				} finally {
					program.endTransaction(txId, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			return "Error: Failed to execute create struct on Swing thread: " + e.getMessage();
		}
		return result.get();
	}
}
