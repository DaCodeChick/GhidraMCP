package com.lauriewired.util;

import com.sun.net.httpserver.HttpExchange;
import ghidra.util.Msg;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Utility methods for parsing HTTP requests and responses.
 * 
 * This class provides methods to parse query parameters, post body parameters,
 * paginate lists, parse integers with defaults, escape non-ASCII characters,
 * and send HTTP responses.
 */
public final class ParseUtils {
	/**
	 * Parse query parameters from the request URI.
	 * 
	 * @param exchange The HttpExchange object containing the request.
	 * @return A map of query parameters where the key is the parameter name
	 *         and the value is the parameter value.
	 *         For example, for a query string "offset=10&limit=100",
	 *         the map will contain {"offset": "10", "limit": "100"}
	 */
	public static Map<String, String> parseQueryParams(HttpExchange exchange) {
		Map<String, String> result = new HashMap<>();
		String query = exchange.getRequestURI().getQuery(); // e.g. offset=10&limit=100
		if (query != null) {
			String[] pairs = query.split("&");
			for (String p : pairs) {
				String[] kv = p.split("=");
				if (kv.length == 2) {
					// URL decode parameter values
					try {
						String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
						String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
						result.put(key, value);
					} catch (Exception e) {
						Msg.error(ParseUtils.class, "Error decoding URL parameter", e);
					}
				}
			}
		}
		return result;
	}

	/**
	 * Parse POST parameters from the request body.
	 * 
	 * @param exchange The HttpExchange object containing the request.
	 * @return A map of POST parameters where the key is the parameter name
	 *         and the value is the parameter value.
	 *         For example, for a body "offset=10&limit=100",
	 *         the map will contain {"offset": "10", "limit": "100"}
	 */
	public static Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
		byte[] body = exchange.getRequestBody().readAllBytes();
		String bodyStr = new String(body, StandardCharsets.UTF_8);
		Map<String, String> params = new HashMap<>();
		for (String pair : bodyStr.split("&")) {
			String[] kv = pair.split("=");
			if (kv.length == 2) {
				// URL decode parameter values
				try {
					String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
					String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
					params.put(key, value);
				} catch (Exception e) {
					Msg.error(ParseUtils.class, "Error decoding URL parameter", e);
				}
			}
		}
		return params;
	}

	/**
	 * Paginate a list of items based on offset and limit.
	 * 
	 * @param items  The list of items to paginate.
	 * @param offset The starting index for pagination.
	 * @param limit  The maximum number of items to return.
	 * @return A string containing the paginated items, each on a new line.
	 *         If the offset is beyond the list size, returns an empty string.
	 */
	public static String paginateList(List<String> items, int offset, int limit) {
		int start = Math.max(0, offset);
		int end = Math.min(items.size(), offset + limit);

		if (start >= items.size()) {
			return ""; // no items in range
		}
		List<String> sub = items.subList(start, end);
		return String.join("\n", sub);
	}

	/**
	 * Parse an integer from a string, returning a default value if parsing fails.
	 * 
	 * @param val          The string to parse.
	 * @param defaultValue The default value to return if parsing fails.
	 * @return The parsed integer or the default value if parsing fails.
	 */
	public static int parseIntOrDefault(String val, int defaultValue) {
		if (val == null)
			return defaultValue;
		try {
			return Integer.parseInt(val);
		} catch (NumberFormatException e) {
			return defaultValue;
		}
	}

	/**
	 * Escape non-ASCII characters in a string.
	 * 
	 * @param input The input string to escape.
	 * @return A string where non-ASCII characters are replaced with their
	 *         hexadecimal representation, e.g. "\xFF" for 255.
	 */
	public static String escapeNonAscii(String input) {
		if (input == null)
			return "";
		StringBuilder sb = new StringBuilder();
		for (char c : input.toCharArray()) {
			if (c >= 32 && c < 127) {
				sb.append(c);
			} else {
				sb.append("\\x");
				sb.append(Integer.toHexString(c & 0xFF));
			}
		}
		return sb.toString();
	}

	/**
	 * Send a plain text response to the HTTP exchange.
	 * 
	 * @param exchange The HttpExchange object to send the response to.
	 * @param response The response string to send.
	 * @throws IOException If an I/O error occurs while sending the response.
	 */
	public static void sendResponse(HttpExchange exchange, String response) throws IOException {
		byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
		exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
		exchange.sendResponseHeaders(200, bytes.length);
		try (OutputStream os = exchange.getResponseBody()) {
			os.write(bytes);
		}
	}
}
