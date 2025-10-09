package com.lauriewired.handlers.bsim;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.features.bsim.gensig.GenSignatures;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.QueryNearest;
import ghidra.features.bsim.query.ResponseNearest;
import ghidra.features.bsim.util.DescriptionManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.util.Map;

import static com.lauriewired.util.BSimUtils.*;
import static com.lauriewired.util.ParseUtils.*;

/**
 * Handler for querying similar functions from a BSim database
 */
public final class QueryBSimFunction extends Handler {
	/**
	 * Constructor for the QueryBSimFunction handler
	 * 
	 * @param tool The Ghidra PluginTool instance
	 */
	public QueryBSimFunction(PluginTool tool) {
		super(tool, "/bsim/query_function");
	}

	/**
	 * Handles the HTTP request for querying similar functions
	 * @param exchange The HttpExchange object representing the HTTP request/response
	 */
	@Override
	public void handle(HttpExchange exchange) throws Exception {
		Map<String, String> params = parsePostParams(exchange);
		String functionAddress = params.get("function_address");
		int maxMatches = parseIntOrDefault(params.get("max_matches"), 10);
		double similarityThreshold = parseDoubleOrDefault(params.get("similarity_threshold"), "0.7");
		double confidenceThreshold = parseDoubleOrDefault(params.get("confidence_threshold"), "0.0");
		double maxSimilarity = parseDoubleOrDefault(params.get("max_similarity"), String.valueOf(Double.POSITIVE_INFINITY));
		double maxConfidence = parseDoubleOrDefault(params.get("max_confidence"), String.valueOf(Double.POSITIVE_INFINITY));
		int offset = parseIntOrDefault(params.get("offset"), 0);
		int limit = parseIntOrDefault(params.get("limit"), 100);
		sendResponse(exchange, queryBSimFunction(functionAddress, maxMatches, similarityThreshold, confidenceThreshold, maxSimilarity, maxConfidence, offset, limit));
	}

	/**
	 * Queries the BSim database for functions similar to the one at the given address
	 * @param functionAddress The address of the function to query
	 * @param maxMatches The maximum number of matches to return
	 * @param similarityThreshold The minimum similarity threshold for matches
	 * @param confidenceThreshold The minimum confidence threshold for matches
	 * @param maxSimilarity The maximum similarity value for filtering results
	 * @param maxConfidence The maximum confidence value for filtering results
	 * @param offset The offset for pagination
	 * @param limit The limit for pagination
	 * @return A formatted string of the query results or an error message
	 */
	private String queryBSimFunction(String functionAddress, int maxMatches, 
                                     double similarityThreshold, double confidenceThreshold,
                                     double maxSimilarity, double maxConfidence,
                                     int offset, int limit) {
        if (bsimDatabase == null) {
            return "Error: Not connected to a BSim database. Use bsim_select_database first.";
        }

        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        try {
            Address addr = program.getAddressFactory().getAddress(functionAddress);
            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) {
                func = program.getFunctionManager().getFunctionContaining(addr);
            }
            if (func == null) {
                return "Error: No function found at address " + functionAddress;
            }

            // Generate signature for this function
            GenSignatures gensig = new GenSignatures(false);
            gensig.setVectorFactory(bsimDatabase.getLSHVectorFactory());

            // Set up the executable record for the current program
            String exeName = program.getName();
            String exePath = program.getExecutablePath();
            gensig.openProgram(program, exeName, exePath, null, null, null);

            DescriptionManager descManager = gensig.getDescriptionManager();
            gensig.scanFunction(func);

            if (descManager.numFunctions() == 0) {
                return "Error: Failed to generate signature for function";
            }

            // Create and execute query
            // Note: We don't set query.max here because we need to filter by max similarity/confidence first,
            // then limit to maxMatches. Setting query.max too early might exclude valid matches.
            QueryNearest query = new QueryNearest();
            query.manage = descManager;
            query.max = Integer.MAX_VALUE; // Get all potential matches
            query.thresh = similarityThreshold;
            query.signifthresh = confidenceThreshold;

            // Execute query
            ResponseNearest response = query.execute(bsimDatabase);

            if (response == null) {
                return "Error: Query returned no response";
            }

            // Debug info
            Msg.info(this, String.format("Query completed for %s: threshold=%.2f, results=%d", 
                func.getName(), similarityThreshold,
                response.result != null ? response.result.size() : 0));

            // Filter results by max similarity and max confidence, and limit to maxMatches
            filterBSimResults(response, maxSimilarity, maxConfidence, maxMatches);

            // Format results with pagination
            return formatBSimResults(response, func.getName(), offset, limit);

        } catch (Exception e) {
            return "Error querying BSim database: " + e.getMessage();
        }
    }
}
