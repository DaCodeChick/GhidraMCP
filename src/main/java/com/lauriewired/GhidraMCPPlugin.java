package com.lauriewired;

import com.lauriewired.handlers.Handler;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import ghidra.framework.options.Options;

import com.sun.net.httpserver.HttpServer;
import org.reflections.Reflections;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.net.InetSocketAddress;
import java.util.*;

/**
 * A Ghidra plugin that starts an embedded HTTP server to expose program data
 * via a RESTful API.
 * The server's port and address can be configured via the Tool Options.
 */
@PluginInfo(status = PluginStatus.RELEASED, packageName = ghidra.app.DeveloperPluginPackage.NAME, category = PluginCategoryNames.ANALYSIS, shortDescription = "HTTP server plugin", description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options.")
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

	/** Default decompile timeout in seconds */
	private static final int DEFAULT_DECOMPILE_TIMEOUT = 30;

	/** HashMap to store all registered API routes */
	private static final HashMap<String, Handler> routes = new HashMap<>();

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
		options.registerOption(DECOMPILE_TIMEOUT_OPTION_NAME, DEFAULT_DECOMPILE_TIMEOUT,
				null,
				"Decompilation timeout. " +
						"Requires Ghidra restart or plugin reload to take effect after changing.");

		try {
			startServer();
		} catch (IOException e) {
			Msg.error(this, "Failed to start HTTP server", e);
		}
		Msg.info(this, "GhidraMCPPlugin loaded!");
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
			server.stop(0);
			server = null;
		}

		InetSocketAddress inetAddress = new InetSocketAddress(listenAddress, port);

		if (inetAddress.isUnresolved()) {
			Msg.error(this, "Failed to resolve listen address.");
			return;
		}

		server = HttpServer.create(inetAddress, 0);

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
				}
				server.createContext(handler.getPath(), exchange -> {
					try {
						handler.handle(exchange);
					} catch (Exception e) {
						throw new RuntimeException(e);
					}
				});
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
				Msg.info(this, "GhidraMCP HTTP server started on port " + port);
			} catch (Exception e) {
				Msg.error(this, "Failed to start HTTP server on port " + port + ". Port might be in use.", e);
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
			server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
			server = null; // Nullify the reference
			Msg.info(this, "GhidraMCP HTTP server stopped.");
		}
		super.dispose();
	}
}
