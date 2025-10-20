package com.lauriewired.handlers.structs;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.Set;
import javax.swing.SwingUtilities;

import static com.lauriewired.GhidraMCPPlugin.*;
import static com.lauriewired.util.GhidraUtils.*;
import static com.lauriewired.util.ParseUtils.*;

/**
 * Handler to analyze struct field usage in decompiled code.
 * Expects JSON parameters:
 * {
 *   "address": "0x00400000",
 *   "struct_name": "MyStruct",
 *   "max_functions": 10
 * }
 * Returns JSON with field usage statistics.
 */
public final class AnalyzeStructFieldUsage extends Handler {
	/**
	 * Constructor for AnalyzeStructFieldUsage.
	 * @param tool the plugin tool
	 */
	public AnalyzeStructFieldUsage(PluginTool tool) {
		super(tool, "/analyze_struct_field_usage");
	}

	/**
	 * Handles the HTTP exchange for struct field usage analysis.
	 * @param exchange the HTTP exchange
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, Object> params = parseJsonParams(exchange);
		String address = (String) params.get("address");
		String structName = (String) params.get("struct_name");
		int maxFunctionsToAnalyze = parseIntOrDefault(String.valueOf(params.get("max_functions")), 10);

		String result = analyzeStructFieldUsage(address, structName, maxFunctionsToAnalyze);
		sendResponse(exchange, result);
	}

	/** Class to hold field usage information. */
	private static class FieldUsageInfo {
		/** Number of times the field was accessed. */
        int accessCount = 0;

        /** Set of suggested names for the field. */
        Set<String> suggestedNames = new HashSet<>();

		/** Set of usage patterns detected for the field. */
        Set<String> usagePatterns = new HashSet<>();

		/**
		 * Get suggested names as JSON array.
		 * @return JSON array string of suggested names
		 */
        String getSuggestedNamesJson() {
            StringBuilder json = new StringBuilder("[");
            boolean first = true;
            for (String name : suggestedNames) {
                if (!first) json.append(",");
                first = false;
                json.append("\"").append(name).append("\"");
            }
            json.append("]");
            return json.toString();
        }

		/**
		 * Get usage patterns as JSON array.
		 * @return JSON array string of usage patterns
		 */
        String getUsagePatternsJson() {
            StringBuilder json = new StringBuilder("[");
            boolean first = true;
            for (String pattern : usagePatterns) {
                if (!first) json.append(",");
                first = false;
                json.append("\"").append(pattern).append("\"");
            }
            json.append("]");
            return json.toString();
        }
    }

	/**
	 * Analyze field usage in decompiled code.
	 * @param code the decompiled code
	 * @param struct the structure being analyzed
	 * @param fieldUsageMap the map to store field usage information
	 * @param baseAddr the base address of the structure
	 */
	private void analyzeFieldUsageInCode(String code, Structure struct, Map<Integer, FieldUsageInfo> fieldUsageMap, String baseAddr) {
        String[] lines = code.split("\\n");

        for (String line : lines) {
            // Skip empty lines and comments
            String trimmedLine = line.trim();
            if (trimmedLine.isEmpty() || trimmedLine.startsWith("//") || trimmedLine.startsWith("/*")) {
                continue;
            }

            // Look for field access patterns
            for (DataTypeComponent component : struct.getComponents()) {
                String fieldName = component.getFieldName();
                int offset = component.getOffset();
                boolean fieldMatched = false;

                // IMPROVED: Use word boundary matching for field names
                Pattern fieldPattern = Pattern.compile("\\b" + Pattern.quote(fieldName) + "\\b");
                if (fieldPattern.matcher(line).find()) {
                    fieldMatched = true;
                }

                // IMPROVED: Use word boundary for offset matching (e.g., "+4" but not "+40")
                Pattern offsetPattern = Pattern.compile("\\+\\s*" + offset + "\\b");
                if (offsetPattern.matcher(line).find()) {
                    fieldMatched = true;
                }

                if (fieldMatched) {
                    FieldUsageInfo info = fieldUsageMap.computeIfAbsent(offset, k -> new FieldUsageInfo());
                    info.accessCount++;

                    // IMPROVED: Detect usage patterns with better regex
                    // Conditional check: if (field == ...) or if (field != ...)
                    if (line.matches(".*\\bif\\s*\\(.*\\b" + Pattern.quote(fieldName) + "\\b.*(==|!=|<|>|<=|>=).*")) {
                        info.usagePatterns.add("conditional_check");
                    }

                    // Increment/decrement: field++ or field--
                    if (line.matches(".*\\b" + Pattern.quote(fieldName) + "\\s*(\\+\\+|--).*") ||
                        line.matches(".*(\\+\\+|--)\\s*\\b" + Pattern.quote(fieldName) + "\\b.*")) {
                        info.usagePatterns.add("increment_decrement");
                    }

                    // Assignment: variable = field or field = value
                    if (line.matches(".*\\b\\w+\\s*=\\s*.*\\b" + Pattern.quote(fieldName) + "\\b.*") ||
                        line.matches(".*\\b" + Pattern.quote(fieldName) + "\\s*=.*")) {
                        info.usagePatterns.add("assignment");
                    }

                    // Array access: field[index]
                    if (line.matches(".*\\b" + Pattern.quote(fieldName) + "\\s*\\[.*\\].*")) {
                        info.usagePatterns.add("array_access");
                    }

                    // Pointer dereference: ptr->field or struct.field
                    if (line.matches(".*->\\s*\\b" + Pattern.quote(fieldName) + "\\b.*") ||
                        line.matches(".*\\.\\s*\\b" + Pattern.quote(fieldName) + "\\b.*")) {
                        info.usagePatterns.add("pointer_dereference");
                    }

                    // IMPROVED: Extract variable names with C keyword filtering
                    String[] tokens = line.split("\\W+");
                    for (String token : tokens) {
                        if (token.length() >= MIN_TOKEN_LENGTH &&
                            !token.equals(fieldName) &&
                            !C_KEYWORDS.contains(token.toLowerCase()) &&
                            Character.isLetter(token.charAt(0)) &&
                            !token.matches("\\d+")) {  // Filter out numbers
                            info.suggestedNames.add(token);
                        }
                    }
                }
            }
        }
    }

	/**
	 * Analyze struct field usage at the given address.
	 * @param addressStr the address as a string
	 * @param structName the name of the structure (optional)
	 * @param maxFunctionsToAnalyze maximum number of functions to analyze
	 * @return JSON string with analysis results
	 */
	private String analyzeStructFieldUsage(String addressStr, String structName, int maxFunctionsToAnalyze) {
        // CRITICAL FIX #3: Validate input parameters
        if (maxFunctionsToAnalyze < MIN_FUNCTIONS_TO_ANALYZE || maxFunctionsToAnalyze > MAX_FUNCTIONS_TO_ANALYZE) {
            return "{\"error\": \"maxFunctionsToAnalyze must be between " + MIN_FUNCTIONS_TO_ANALYZE +
                   " and " + MAX_FUNCTIONS_TO_ANALYZE + "\"}";
        }

        final AtomicReference<String> result = new AtomicReference<>();

		// CRITICAL FIX #1: Thread safety - wrap in SwingUtilities.invokeAndWait
		try {
			SwingUtilities.invokeAndWait(() -> {
                try {
                    Program program = getCurrentProgram(tool);
                    if (program == null) {
                        result.set("{\"error\": \"No program loaded\"}");
                        return;
                    }

					Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        result.set("{\"error\": \"Invalid address: " + addressStr + "\"}");
                        return;
                    }

					// Get data at address to determine structure
                    Data data = program.getListing().getDataAt(addr);
                    DataType dataType = (data != null) ? data.getDataType() : null;

					if (dataType == null || !(dataType instanceof Structure)) {
                        result.set("{\"error\": \"No structure data type found at " + addressStr + "\"}");
                        return;
                    }

					Structure struct = (Structure) dataType;

				// MAJOR FIX #5: Validate structure size
                    DataTypeComponent[] components = struct.getComponents();
                    if (components.length > MAX_STRUCT_FIELDS) {
                        result.set("{\"error\": \"Structure too large (" + components.length +
                                   " fields). Maximum " + MAX_STRUCT_FIELDS + " fields supported.\"}");
                        return;
                    }

                    String actualStructName = (structName != null && !structName.isEmpty()) ? structName : struct.getName();

                    // Get all xrefs to this address
                    ReferenceManager refMgr = program.getReferenceManager();
                    ReferenceIterator refIter = refMgr.getReferencesTo(addr);

                    Set<Function> functionsToAnalyze = new HashSet<>();
                    while (refIter.hasNext() && functionsToAnalyze.size() < maxFunctionsToAnalyze) {
                        Reference ref = refIter.next();
                        Function func = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                        if (func != null) {
                            functionsToAnalyze.add(func);
                        }
                    }

                    // Decompile all functions and analyze field usage
                    Map<Integer, FieldUsageInfo> fieldUsageMap = new HashMap<>();
                    DecompInterface decomp = null;

                    // CRITICAL FIX #2: Resource management with try-finally
                    try {
                        decomp = new DecompInterface();
                        decomp.openProgram(program);

                        long analysisStart = System.currentTimeMillis();
                        Msg.info(this, "Analyzing struct at " + addressStr + " with " + functionsToAnalyze.size() + " functions");

                        for (Function func : functionsToAnalyze) {
                            try {
                                DecompileResults results = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS,
                                                                                   new ConsoleTaskMonitor());
                                if (results != null && results.decompileCompleted()) {
                                    String decompiledCode = results.getDecompiledFunction().getC();
                                    analyzeFieldUsageInCode(decompiledCode, struct, fieldUsageMap, addr.toString());
                                } else {
                                    Msg.warn(this, "Failed to decompile function: " + func.getName());
                                }
                            } catch (Exception e) {
                                // Continue with other functions if one fails
                                Msg.error(this, "Error decompiling function " + func.getName() + ": " + e.getMessage());
                            }
                        }

                        long analysisTime = System.currentTimeMillis() - analysisStart;
                        Msg.info(this, "Field analysis completed in " + analysisTime + "ms, found " +
                                 fieldUsageMap.size() + " fields with usage data");

                    } finally {
                        // CRITICAL FIX #2: Always dispose of DecompInterface
                        if (decomp != null) {
                            decomp.dispose();
                        }
                    }

                    // Build JSON response with field analysis
                    StringBuilder json = new StringBuilder();
                    json.append("{");
                    json.append("\"struct_address\": \"").append(addressStr).append("\",");
                    json.append("\"struct_name\": \"").append(escapeJson(actualStructName)).append("\",");
                    json.append("\"struct_size\": ").append(struct.getLength()).append(",");
                    json.append("\"functions_analyzed\": ").append(functionsToAnalyze.size()).append(",");
                    json.append("\"field_usage\": {");

                    boolean first = true;
                    for (int i = 0; i < components.length; i++) {
                        DataTypeComponent component = components[i];
                        int offset = component.getOffset();

                        if (!first) json.append(",");
                        first = false;

                        json.append("\"").append(offset).append("\": {");
                        json.append("\"field_name\": \"").append(escapeJson(component.getFieldName())).append("\",");
                        json.append("\"field_type\": \"").append(escapeJson(component.getDataType().getName())).append("\",");
                        json.append("\"offset\": ").append(offset).append(",");
                        json.append("\"size\": ").append(component.getLength()).append(",");

                        FieldUsageInfo usageInfo = fieldUsageMap.get(offset);
                        if (usageInfo != null) {
                            json.append("\"access_count\": ").append(usageInfo.accessCount).append(",");
                            json.append("\"suggested_names\": ").append(usageInfo.getSuggestedNamesJson()).append(",");
                            json.append("\"usage_patterns\": ").append(usageInfo.getUsagePatternsJson());
                        } else {
                            json.append("\"access_count\": 0,");
                            json.append("\"suggested_names\": [],");
                            json.append("\"usage_patterns\": []");
                        }

                        json.append("}");
                    }

                    json.append("}");
                    json.append("}");

                    result.set(json.toString());
                } catch (Exception e) {
                    result.set("{\"error\": \"" + escapeJson(e.getMessage()) + "\"}");
                }
            });
        } catch (InvocationTargetException | InterruptedException e) {
            Msg.error(this, "Thread synchronization error in analyzeStructFieldUsage", e);
            return "{\"error\": \"Thread synchronization error: " + escapeJson(e.getMessage()) + "\"}";
        }

        return result.get();
    }
}
