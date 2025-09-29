package com.lauriewired.handlers.create;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

import java.io.IOException;

import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler to auto-create a structure at a specified address in the current
 * program.
 * The structure is inferred based on the data patterns found in memory.
 * Parameters:
 * - address: The starting address to analyze (required).
 * - size: The number of bytes to analyze (optional, default is 64).
 * - name: The name of the structure to create (required).
 * Example usage:
 * /auto_create_struct?address=0x00400000&size=128&name=MyStruct
 * This will analyze 128 bytes starting from address 0x00400000 and create a
 * structure named "MyStruct".
 */
public final class AutoCreateStruct extends Handler {
	/**
	 * Constructs a new AutoCreateStruct handler.
	 *
	 * @param tool The PluginTool instance to interact with Ghidra.
	 */
	public AutoCreateStruct(PluginTool tool) {
		super(tool, "/auto_create_struct");
	}

	/**
	 * Handles the HTTP exchange to auto-create a structure.
	 * Expects POST parameters:
	 * - address: The starting address to analyze (required).
	 * - size: The number of bytes to analyze (optional, default is 64).
	 * - name: The name of the structure to create (required).
	 * 
	 * @param exchange The HttpExchange object representing the HTTP request and
	 *                 response.
	 * @throws IOException If an I/O error occurs.
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> params = parsePostParams(exchange);
		String address = params.get("address");
		int size = parseIntOrDefault(params.get("size"), 0);
		String name = params.get("name");
		sendResponse(exchange, autoCreateStruct(address, size, name));
	}

	/**
	 * Auto-creates a structure at the specified address by analyzing memory
	 * patterns.
	 *
	 * @param addressStr The starting address to analyze.
	 * @param size       The number of bytes to analyze.
	 * @param name       The name of the structure to create.
	 * @return A message indicating success or failure.
	 */
	private String autoCreateStruct(String addressStr, int size, String name) {
		Program program = getCurrentProgram();
		if (program == null)
			return "No program loaded";
		if (addressStr == null || addressStr.isEmpty())
			return "Address is required";
		if (name == null || name.isEmpty())
			return "Structure name is required";

		AtomicBoolean success = new AtomicBoolean(false);
		StringBuilder result = new StringBuilder();

		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Auto-create structure");
				try {
					Address addr = program.getAddressFactory().getAddress(addressStr);
					DataTypeManager dtm = program.getDataTypeManager();
					StructureDataType struct = new StructureDataType(name, 0);

					// Analyze memory at the address to infer structure
					Memory memory = program.getMemory();
					int actualSize = (size > 0) ? size : 64; // Default to 64 bytes if size not specified

					// Simple field inference based on data patterns
					for (int i = 0; i < actualSize; i += 4) { // Assume 4-byte fields for simplicity
						if (i + 4 <= actualSize) {
							try {
								int value = memory.getInt(addr.add(i));
								String fieldName = "field_" + (i / 4);

								// Try to infer type based on value patterns
								DataType fieldType;
								if (value == 0 || (value > 0 && value < 1000000)) {
									fieldType = new IntegerDataType();
								} else {
									// Could be a pointer
									fieldType = new PointerDataType();
								}

								struct.add(fieldType, fieldName, null);
								result.append("Added field: ").append(fieldName)
										.append(" at offset ").append(i)
										.append(" (").append(fieldType.getName()).append(")\n");
							} catch (Exception e) {
								// Memory might not be readable, add undefined byte
								struct.add(new ByteDataType(), "undefined_" + i, null);
							}
						}
					}

					dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
					result.append("Structure '").append(name).append("' created with ")
							.append(struct.getNumComponents()).append(" fields");
					success.set(true);
				} catch (Exception e) {
					result.append("Error auto-creating structure: ").append(e.getMessage());
				} finally {
					program.endTransaction(tx, success.get());
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			result.append("Failed to execute auto-create structure on Swing thread: ").append(e.getMessage());
		}

		return result.toString();
	}
}
