package com.lauriewired.handlers.bsim;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.framework.plugintool.PluginTool;

import java.net.URL;
import java.util.Map;

import static com.lauriewired.util.BSimUtils.*;
import static com.lauriewired.util.ParseUtils.*;

/**
 * Handler to select and connect to a BSim database given a path or URL.
 * Expects a POST request with parameter "database_path".
 * Responds with success or error message.
 */
public final class SelectBSimDatabase extends Handler {
	/**
	 * Constructor for the SelectBSimDatabase handler
	 * 
	 * @param tool The Ghidra PluginTool instance
	 */
	public SelectBSimDatabase(PluginTool tool) {
		super(tool, "/bsim/select_database");
	}

	/** Handle the HTTP exchange to select a BSim database
	 * 
	 * @param exchange The HttpExchange object
	 * @throws Exception if an error occurs during handling
	 */
	@Override
	public void handle(HttpExchange exchange) throws Exception {
		Map<String, String> params = parsePostParams(exchange);
		String dbPath = params.get("database_path");
		sendResponse(exchange, selectBSimDatabase(dbPath));
	}

	/** Select and connect to a BSim database given its path or URL
	 * 
	 * @param databasePath The path or URL of the BSim database
	 * @return A success message or error message
	 */
	private String selectBSimDatabase(String databasePath) {
        if (databasePath == null || databasePath.isEmpty()) {
            return "Error: Database path is required";
        }

        try {
            // Disconnect from any existing database first
            if (bsimDatabase != null) {
                disconnectBSimDatabase();
            }

            // Create BSimServerInfo from the path/URL
            // Use URL constructor for URLs (postgresql://, file://, etc.)
            // Use String constructor only for file paths
            BSimServerInfo serverInfo;
            if (databasePath.contains("://")) {
                // It's a URL - use URL constructor
                serverInfo = new BSimServerInfo(new URL(databasePath));
            } else {
                // It's a file path - use String constructor
                serverInfo = new BSimServerInfo(databasePath);
            }

            // Initialize the database connection
            bsimDatabase = BSimClientFactory.buildClient(serverInfo, false);

            if (bsimDatabase == null) {
                return "Error: Failed to create BSim database client";
            }

            // Try to initialize the connection
            if (!bsimDatabase.initialize()) {
                bsimDatabase = null;
                return "Error: Failed to initialize BSim database connection";
            }

            currentBSimDatabasePath = databasePath;
            return "Successfully connected to BSim database: " + databasePath;

        } catch (Exception e) {
            bsimDatabase = null;
            currentBSimDatabasePath = null;
            return "Error connecting to BSim database: " + e.getMessage();
        }
    }
}
