package com.lauriewired;

import com.lauriewired.handlers.Handler;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

import com.sun.net.httpserver.HttpServer;
import org.reflections.Reflections;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.net.BindException;
import java.net.InetSocketAddress;
import java.util.*;

/**
 * A Ghidra plugin that starts an embedded HTTP server to expose program data
 * via a RESTful API.
 * The server's port and address can be configured via the Tool Options.
 */
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = ghidra.app.DeveloperPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "GhidraMCP - HTTP server plugin",
	description = "GhidraMCP - Starts an embedded HTTP server to expose program data via REST API and MCP bridge. " +
				  "Provides endpoints for reverse engineering automation. Port configurable via Tool Options. "
)
public class GhidraMCPPlugin extends Plugin {
	/** The embedded HTTP server instance that handles all API requests */
	private HttpServer server;

	/** Configuration category name for tool options */
	private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";

	/** Configuration option name for the server address setting */
	private static final String ADDRESS_OPTION_NAME = "Server Address";

	/** Default address for the HTTP server */
	private static final String DEFAULT_ADDRESS = "127.0.0.1";

	/** Configuration option name for the server port setting */
	private static final String PORT_OPTION_NAME = "Server Port";

	/** Configuration option name for the decompile timeout setting */
	private static final String DECOMPILE_TIMEOUT_OPTION_NAME = "Decompile Timeout";

	/** Default port number for the HTTP server (8089) */
	private static final int DEFAULT_PORT = 8089;
	
	/** HashMap to store all registered API routes */
	private static final HashMap<String, Handler> routes = new HashMap<>();

	/** Maximum number of functions to analyze in batch operations */
	public static final int MAX_FUNCTIONS_TO_ANALYZE = 100;

	/** Minimum number of functions to analyze in batch operations */
	public static final int MIN_FUNCTIONS_TO_ANALYZE = 1;

	/** Maximum number of structure fields to analyze */
	private static final int MAX_STRUCT_FIELDS = 256;

	/** Maximum number of field examples to return */
	private static final int MAX_FIELD_EXAMPLES = 50;
	
	/** Decompilation timeout in seconds */
	public static final int DECOMPILE_TIMEOUT_SECONDS = 60;
	
	/** Minimum token length for searches */
	private static final int MIN_TOKEN_LENGTH = 3;
	
	/** Maximum field offset for structure analysis */
	private static final int MAX_FIELD_OFFSET = 65536;

	/** Set of C language keywords to filter from field name suggestions */
	private static final Set<String> C_KEYWORDS = Set.of(
		"if", "else", "for", "while", "do", "switch", "case", "default",
		"break", "continue", "return", "goto", "int", "void", "char",
		"float", "double", "long", "short", "struct", "union", "enum",
		"typedef", "sizeof", "const", "static", "extern", "auto", "register",
		"signed", "unsigned", "volatile", "inline", "restrict"
	);

	/** HTTP connection timeout in seconds */
	private static final int HTTP_CONNECTION_TIMEOUT_SECONDS = 180;

	/** HTTP idle timeout in seconds */
    private static final int HTTP_IDLE_TIMEOUT_SECONDS = 300;

	/** Batch operation chunk size */
    private static final int BATCH_OPERATION_CHUNK_SIZE = 20;

	/** The timeout for decompilation requests in seconds */
	private int decompileTimeout;

	/**
	 * Constructor called by Ghidra to initialize the plugin.
	 * Sets up configuration options and starts the HTTP server.
	 *
	 * @param tool The plugin tool that manages this plugin.
	 */
	public GhidraMCPPlugin(PluginTool tool) {
		super(tool);
		Msg.info(this, "GhidraMCPPlugin loading...");

		// Register the configuration option
		Options options = tool.getOptions(OPTION_CATEGORY_NAME);
		options.registerOption(ADDRESS_OPTION_NAME, DEFAULT_ADDRESS,
				null, // No help location for now
				"The network address the embedded HTTP server will listen on. " +
						"Requires Ghidra restart or plugin reload to take effect after changing.");
		options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
				null, // No help location for now
				"The network port number the embedded HTTP server will listen on. " +
						"Requires Ghidra restart or plugin reload to take effect after changing.");
		options.registerOption(DECOMPILE_TIMEOUT_OPTION_NAME, DECOMPILE_TIMEOUT_SECONDS,
				null,
				"Decompilation timeout. " +
						"Requires Ghidra restart or plugin reload to take effect after changing.");

		try {
			startServer();
			Msg.info(this, "GhidraMCPPlugin loaded successfully with HTTP server on port " +
				options.getInt(PORT_OPTION_NAME, DEFAULT_PORT));
		} catch (IOException e) {
			Msg.error(this, "Failed to start HTTP server: " + e.getMessage(), e);
			Msg.showError(this, null, "GhidraMCP Server Error",
				"Failed to start MCP server on port " + options.getInt(PORT_OPTION_NAME, DEFAULT_PORT) +
				".\n\nThe port may already be in use. Try:\n" +
				"1. Restarting Ghidra\n" +
				"2. Changing the port in Edit > Tool Options > GhidraMCP\n" +
				"3. Checking if another Ghidra instance is running\n\n" +
				"Error: " + e.getMessage());
		}
	}

	/**
	 * Starts the embedded HTTP server on the configured port and address.
	 * Registers all API route handlers found in the classpath.
	 *
	 * @throws IOException If the server fails to start (e.g., port in use).
	 */
	private void startServer() throws IOException {
		// Read the configured port
		Options options = tool.getOptions(OPTION_CATEGORY_NAME);
		String listenAddress = options.getString(ADDRESS_OPTION_NAME, DEFAULT_ADDRESS);
		int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

		// Stop existing server if running (e.g., if plugin is reloaded)
		if (server != null) {
			Msg.info(this, "Stopping existing HTTP server before starting new one.");
			try {
				server.stop(0);
				// Give the server time to fully stop and release all resources
				Thread.sleep(500);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				Msg.warn(this, "Interrupted while waiting for server to stop");
			}
			server = null;
		}

		// Create new server - if port is in use, try to handle gracefully
		try {
			server = HttpServer.create(new InetSocketAddress(port), 0);
			Msg.info(this, "HTTP server created successfully on port " + port);
		} catch (BindException e) {
			Msg.error(this, "Port " + port + " is already in use. " +
				"Another instance may be running or port is not released yet. " +
				"Please wait a few seconds and restart Ghidra, or change the port in Tool Options.");
			throw e;
		} catch (IllegalArgumentException e) {
			Msg.error(this, "Cannot create HTTP server contexts - they may already exist. " +
				"Please restart Ghidra completely. Error: " + e.getMessage());
			throw new IOException("Server context creation failed", e);
		}

		Reflections reflections = new Reflections("com.lauriewired.handlers");
		Set<Class<? extends Handler>> subclasses = reflections.getSubTypesOf(Handler.class);
		for (Class<?> clazz : subclasses) {
			System.out.println(clazz.getName());
			try {
				Constructor<?> constructor = clazz.getConstructor(PluginTool.class);
				Handler handler = (Handler) constructor.newInstance(tool);
				String[] paths = handler.getPaths();
				for (String path : paths) {
					if (routes.containsKey(path)) {
						Msg.error(this, "Handler class " + clazz.getName() + " already registered for path " + path
								+ ", skipped.");
						continue;
					}
					routes.put(path, handler);

					server.createContext(path, exchange -> {
						try {
							handler.handle(exchange);
						} catch (Exception e) {
							throw new RuntimeException(e);
						}
					});
				}
			} catch (NoSuchMethodException e) {
				Msg.error(this, "Handler class " + clazz.getName() +
						" doesn't have constructor xxx(PluginTool tool), skipped.");
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		server.setExecutor(null);
		new Thread(() -> {
			try {
				server.start();
				Msg.info(this, "GhidraMCP HTTP server started on port " + options.getInt(PORT_OPTION_NAME, DEFAULT_PORT));
			} catch (Exception e) {
				Msg.error(this, "Failed to start HTTP server: " + e.getMessage(), e);
				Msg.showError(this, null, "GhidraMCP Server Error",
					"Failed to start MCP server on port " + options.getInt(PORT_OPTION_NAME, DEFAULT_PORT) +
					".\n\nThe port may already be in use. Try:\n" +
					"1. Restarting Ghidra\n" +
					"2. Changing the port in Edit > Tool Options > GhidraMCP\n" +
					"3. Checking if another Ghidra instance is running\n\n" +
					"Error: " + e.getMessage());
					server = null; // Ensure server isn't considered running
			}
		}, "GhidraMCP-HTTP-Server").start();
	}

	/**
	 * Stops the embedded HTTP server if it is running.
	 * Called when the plugin is disposed or Ghidra is shutting down.
	 */
	@Override
	public void dispose() {
		if (server != null) {
			Msg.info(this, "Stopping GhidraMCP HTTP server...");
			try {
				server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
				// Give the server time to fully release the port
				Thread.sleep(100);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
			server = null; // Nullify the reference
			Msg.info(this, "GhidraMCP HTTP server stopped.");
		}
		super.dispose();
	}
}
