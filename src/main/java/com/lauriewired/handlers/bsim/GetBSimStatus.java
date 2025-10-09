package com.lauriewired.handlers.bsim;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import generic.lsh.vector.LSHVectorFactory;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.protocol.QueryInfo;
import ghidra.features.bsim.query.protocol.ResponseInfo;
import ghidra.framework.plugintool.PluginTool;

import static com.lauriewired.util.ParseUtils.*;

/**
 * Handler to get the status of the current BSim database connection
 */
public final class GetBSimStatus extends Handler {
	/**
	 * Constructor for the GetBSimStatus handler
	 * 
	 * @param tool The Ghidra PluginTool instance
	 */
	public GetBSimStatus(PluginTool tool) {
		super(tool, "/bsim/status");
	}

	/**
	 * Handles the HTTP request to get the BSim status
	 *
	 * @param exchange The HTTP exchange object
	 * @throws Exception If an error occurs while handling the request
	 */
	@Override
	public void handle(HttpExchange exchange) throws Exception {
		sendResponse(exchange, getBSimStatus());
	}

	/**
	 * Retrieves the current status of the BSim database connection
	 *
	 * @return A string describing the current BSim database status
	 */
	private String getBSimStatus() {
        if (bsimDatabase != null && currentBSimDatabasePath != null) {
            try {
                StringBuilder status = new StringBuilder();
                status.append("Connected to: ").append(currentBSimDatabasePath).append("\n");
                status.append("Database info:\n");

                LSHVectorFactory vectorFactory = bsimDatabase.getLSHVectorFactory();
                if (vectorFactory != null) {
                    status.append("  Vector Factory: ").append(vectorFactory.getClass().getSimpleName()).append("\n");
                } else {
                    status.append("  Vector Factory: null (ERROR)\n");
                }

                // Try to get database info
                QueryInfo infoQuery = new QueryInfo();
                ResponseInfo infoResponse = infoQuery.execute(bsimDatabase);
                if (infoResponse != null && infoResponse.info != null) {
                    status.append("  Database name: ").append(infoResponse.info.databasename).append("\n");
                }

                return status.toString();
            } catch (Exception e) {
                return "Connected to: " + currentBSimDatabasePath + " (Error getting details: " + e.getMessage() + ")";
            }
        }
        return "Not connected to any BSim database";
    }
}
