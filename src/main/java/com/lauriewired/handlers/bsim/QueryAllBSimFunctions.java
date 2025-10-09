package com.lauriewired.handlers.bsim;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.features.bsim.query.QueryNearest;
import ghidra.features.bsim.query.ResponseNearest;
import ghidra.features.bsim.query.description.DescriptionManager;
import ghidra.features.bsim.query.protocol.SimilarityNote;
import ghidra.features.bsim.query.protocol.SimilarityResult;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;

import java.util.Iterator;
import java.util.Map;

import static com.lauriewired.util.BSimUtils.*;
import static com.lauriewired.util.ParseUtils.*;

/**
 * Handler for querying all functions in the current program against the BSim database.
 * This handler processes HTTP requests to retrieve similarity results for all functions
 * based on specified thresholds and limits.
 */
public final class QueryAllBSimFunctions extends Handler {
	/**
	 * Constructor for the QueryAllBSimFunctions handler
	 * 
	 * @param tool The Ghidra PluginTool instance
	 */
	public QueryAllBSimFunctions(PluginTool tool) {
		super(tool, "/bsim/query_all_functions");
	}

	/**
	 * Handles the HTTP request to query all functions against the BSim database.
	 * 
	 * @param exchange The HTTP exchange containing the request and response
	 * @throws Exception If an error occurs during processing
	 */
	@Override
	public void handle(HttpExchange exchange) throws Exception {
		Map<String, String> params = parsePostParams(exchange);
		int maxMatchesPerFunction = parseIntOrDefault(params.get("max_matches_per_function"), 5);
		double similarityThreshold = parseDoubleOrDefault(params.get("similarity_threshold"), "0.7");
		double confidenceThreshold = parseDoubleOrDefault(params.get("confidence_threshold"), "0.0");
		double maxSimilarity = parseDoubleOrDefault(params.get("max_similarity"), String.valueOf(Double.POSITIVE_INFINITY));
		double maxConfidence = parseDoubleOrDefault(params.get("max_confidence"), String.valueOf(Double.POSITIVE_INFINITY));
		int offset = parseIntOrDefault(params.get("offset"), 0);
		int limit = parseIntOrDefault(params.get("limit"), 100);
		sendResponse(exchange, queryAllBSimFunctions(maxMatchesPerFunction, similarityThreshold, confidenceThreshold, maxSimilarity, maxConfidence, offset, limit));
	}

	/**
	 * Queries all functions in the current program against the BSim database.
	 * 
	 * @param maxMatchesPerFunction The maximum number of matches to return per function
	 * @param similarityThreshold The minimum similarity threshold for matches
	 * @param confidenceThreshold The minimum confidence threshold for matches
	 * @param maxSimilarity The maximum similarity to filter results (exclusive)
	 * @param maxConfidence The maximum confidence to filter results (exclusive)
	 * @param offset The offset for pagination
	 * @param limit The maximum number of results to return
	 * @return A string containing the formatted results or an error message
	 */
	private String queryAllBSimFunctions(int maxMatchesPerFunction, 
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
            StringBuilder results = new StringBuilder();
            FunctionManager funcManager = program.getFunctionManager();
            int totalFunctions = funcManager.getFunctionCount();
            int queriedFunctions = 0;

            results.append("Querying ").append(totalFunctions).append(" functions against BSim database...\n\n");

            // Generate signatures for all functions
            GenSignatures gensig = new GenSignatures(false);
            gensig.setVectorFactory(bsimDatabase.getLSHVectorFactory());

            // Set up the executable record for the current program
            String exeName = program.getName();
            String exePath = program.getExecutablePath();
            gensig.openProgram(program, exeName, exePath, null, null, null);

            DescriptionManager descManager = gensig.getDescriptionManager();

            // Use built-in scanFunctions to scan all at once
            try {
                gensig.scanFunctions(funcManager.getFunctions(true), 30, new ConsoleTaskMonitor());
                queriedFunctions = descManager.numFunctions();
            } catch (Exception e) {
                return "Error: Failed to generate signatures: " + e.getMessage();
            }

            if (queriedFunctions == 0) {
                return "Error: No function signatures were generated";
            }

            // Create query
            // Note: We don't set query.max here because we need to filter by max similarity/confidence first,
            // then limit to maxMatchesPerFunction. Setting query.max too early might exclude valid matches.
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

            // Filter results by max similarity and max confidence, and limit to maxMatchesPerFunction
            filterBSimResults(response, maxSimilarity, maxConfidence, maxMatchesPerFunction);

            results.append("Successfully queried ").append(queriedFunctions).append(" functions\n");

            // Format detailed results with pagination
            results.append(formatBSimResults(response, null, offset, limit));

            return results.toString();

        } catch (Exception e) {
            return "Error querying all functions: " + e.getMessage();
        }
    }
	
	/**
	 * Filters the BSim query results to remove matches that exceed the specified maximum similarity
	 * or confidence thresholds, and limits the number of matches per function.
	 *
	 * @param response The BSim query response containing similarity results
	 * @param maxSimilarity The maximum similarity threshold (exclusive)
	 * @param maxConfidence The maximum confidence threshold (exclusive)
	 * @param maxMatches The maximum number of matches to retain per function
	 */
	private void filterBSimResults(ResponseNearest response, double maxSimilarity, double maxConfidence, int maxMatches) {
        if (response == null || response.result == null) {
            return;
        }

        Iterator<SimilarityResult> iter = response.result.iterator();
        while (iter.hasNext()) {
            SimilarityResult simResult = iter.next();
            Iterator<SimilarityNote> noteIter = simResult.iterator();

            int validMatchCount = 0;

            while (noteIter.hasNext()) {
                SimilarityNote note = noteIter.next();

                // Remove matches that meet or exceed max similarity or max confidence (exclusive)
                if (note.getSimilarity() >= maxSimilarity || note.getSignificance() >= maxConfidence) {
                    noteIter.remove();
                } else {
                    // This is a valid match
                    validMatchCount++;

                    // Early stopping: if we've reached maxMatches valid matches, remove all remaining
                    if (validMatchCount > maxMatches) {
                        noteIter.remove();
                    }
                }
            }
        }
    }
}
