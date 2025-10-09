package com.lauriewired.util;

import com.sun.net.httpserver.HttpExchange;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
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
	 * Definition of a field in a structure.
	 */
	public static class FieldDefinition {
		/** Field name */
		public String name;
		
		/** Field type */
		public String type;

		/** Field offset */
		public int offset;

		/**
		 * Constructor
		 * 
		 * @param name   The name of the field.
		 * @param type   The type of the field.
		 * @param offset The offset of the field.
		 */
		public FieldDefinition(String name, String type, int offset) {
			this.name = name;
			this.type = type;
			this.offset = offset;
		}
	}

	/**
	 * Decode a hexadecimal string into a byte array.
	 * 
	 * @param hex The hexadecimal string to decode.
	 * @return A byte array representing the decoded hexadecimal string.
	 * @throws IllegalArgumentException If the input string is not a valid hex
	 *                                  string.
	 */
	public static byte[] decodeHex(String hex) {
		hex = hex.replaceAll("\\s+", "");
		if (hex.length() % 2 != 0)
			throw new IllegalArgumentException();
		byte[] out = new byte[hex.length() / 2];
		for (int i = 0; i < out.length; i++) {
			out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
		}
		return out;
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
	 * Escape special characters in a string for safe display
	 * 
	 * @param input the string to escape
	 * @return the escaped string
	 */
	public static String escapeString(String input) {
		if (input == null)
			return "";

		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < input.length(); i++) {
			char c = input.charAt(i);
			if (c >= 32 && c < 127) {
				sb.append(c);
			} else if (c == '\n') {
				sb.append("\\n");
			} else if (c == '\r') {
				sb.append("\\r");
			} else if (c == '\t') {
				sb.append("\\t");
			} else {
				sb.append(String.format("\\x%02x", (int) c & 0xFF));
			}
		}
		return sb.toString();
	}

	/**
	 * Generate a hexdump of a byte array starting from a given base address.
	 * 
	 * @param base The base address to start the hexdump from.
	 * @param buf  The byte array to generate the hexdump for.
	 * @param len  The number of bytes to include in the hexdump.
	 * @return A string representation of the hexdump.
	 */
	public static String hexdump(Address base, byte[] buf, int len) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < len; i += 16) {
			sb.append(String.format("%s  ", base.add(i)));
			for (int j = 0; j < 16 && (i + j) < len; j++) {
				sb.append(String.format("%02X ", buf[i + j]));
			}
			sb.append('\n');
		}
		return sb.toString();
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
	 * Parse a double from a string, returning a default value if parsing fails.
	 * 
	 * @param val          The string to parse.
	 * @param defaultValue The default value to return if parsing fails.
	 * @return The parsed double or the default value if parsing fails.
	 */
	public static double parseDoubleOrDefault(String val, String defaultValue) {
        if (val == null) val = defaultValue;
        try {
            return Double.parseDouble(val);
        }
        catch (NumberFormatException e) {
            try {
                return Double.parseDouble(defaultValue);
            }
            catch (NumberFormatException e2) {
                return 0.0;
            }
        }
    }

	/**
	 * Parse a JSON-like string of field definitions into a list of FieldDefinition objects.
	 * 
	 * The input string should be in the format:
	 * [{"name": "field1", "type": "int", "offset": 0}, {"name": "field2", "type": "char", "offset": 4}, ...]
	 * 
	 * @param fieldsJson The JSON-like string to parse.
	 * @return A list of FieldDefinition objects parsed from the input string.
	 *         If parsing fails, returns an empty list.
	 */
	public static List<FieldDefinition> parseFieldsJson(String fieldsJson) {
		List<FieldDefinition> fields = new ArrayList<>();

		try {
			// Remove outer brackets and whitespace
			String content = fieldsJson.trim();
			if (content.startsWith("[")) {
				content = content.substring(1);
			}
			if (content.endsWith("]")) {
				content = content.substring(0, content.length() - 1);
			}

			// Split by field objects (simple parsing)
			String[] fieldStrings = content.split("\\},\\s*\\{");

			for (String fieldStr : fieldStrings) {
				// Clean up braces
				fieldStr = fieldStr.replace("{", "").replace("}", "").trim();

				String name = null;
				String type = null;
				int offset = -1;

				// Parse key-value pairs
				String[] pairs = fieldStr.split(",");
				for (String pair : pairs) {
					String[] keyValue = pair.split(":");
					if (keyValue.length == 2) {
						String key = keyValue[0].trim().replace("\"", "");
						String value = keyValue[1].trim().replace("\"", "");

						switch (key) {
							case "name":
								name = value;
								break;
							case "type":
								type = value;
								break;
							case "offset":
								try {
									offset = Integer.parseInt(value);
								} catch (NumberFormatException e) {
									// Ignore invalid offset
								}
								break;
						}
					}
				}

				if (name != null && type != null) {
					fields.add(new FieldDefinition(name, type, offset));
				}
			}
		} catch (Exception e) {
			// Return empty list on parse error
		}

		return fields;
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
	 * Parse JSON parameters from the request body.
	 * 
	 * @param exchange The HttpExchange object containing the request.
	 * @return A map of JSON parameters where the key is the parameter name
	 *         and the value is the parameter value (as Object).
	 *         For example, for a body '{"key1": "value1", "key2": 123}',
	 *         the map will contain {"key1": "value1", "key2": 123}
	 * @throws IOException If an I/O error occurs while reading the request body.
	 */
	public static Map<String, Object> parseJsonParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        
        // Simple JSON parsing - this is a basic implementation
        // In a production environment, you'd want to use a proper JSON library
        Map<String, Object> result = new HashMap<>();
        
        if (bodyStr.trim().isEmpty()) {
            return result;
        }
        
        try {
            // Remove outer braces and parse key-value pairs
            String content = bodyStr.trim();
            if (content.startsWith("{") && content.endsWith("}")) {
                content = content.substring(1, content.length() - 1).trim();
                
                // Simple parsing - split by commas but handle nested objects/arrays
                String[] parts = splitJsonPairs(content);
                
                for (String part : parts) {
                    String[] kv = part.split(":", 2);
                    if (kv.length == 2) {
                        String key = kv[0].trim().replaceAll("^\"|\"$", "");
                        String value = kv[1].trim();
                        
                        // Handle different value types
                        if (value.startsWith("\"") && value.endsWith("\"")) {
                            // String value
                            result.put(key, value.substring(1, value.length() - 1));
                        } else if (value.startsWith("[") && value.endsWith("]")) {
                            // Array value - keep as string for now
                            result.put(key, value);
                        } else if (value.startsWith("{") && value.endsWith("}")) {
                            // Object value - keep as string for now
                            result.put(key, value);
                        } else if (value.matches("\\d+")) {
                            // Integer value
                            result.put(key, Integer.parseInt(value));
                        } else {
                            // Default to string
                            result.put(key, value);
                        }
                    }
                }
            }
        } catch (Exception e) {
            Msg.error(ParseUtils.class, "Error parsing JSON: " + e.getMessage(), e);
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
	 * Parse a JSON-like string of key-value pairs into a map.
	 * 
	 * The input string should be in the format:
	 * {"key1": value1, "key2": value2, ...}
	 * where keys are strings and values are integers.
	 * 
	 * @param valuesJson The JSON-like string to parse.
	 * @return A map of key-value pairs parsed from the input string.
	 *         If parsing fails, returns an empty map.
	 */
	public static Map<String, Long> parseValuesJson(String valuesJson) {
		Map<String, Long> values = new LinkedHashMap<>();

		try {
			// Remove outer braces and whitespace
			String content = valuesJson.trim();
			if (content.startsWith("{")) {
				content = content.substring(1);
			}
			if (content.endsWith("}")) {
				content = content.substring(0, content.length() - 1);
			}

			// Split by commas (simple parsing)
			String[] pairs = content.split(",");

			for (String pair : pairs) {
				String[] keyValue = pair.split(":");
				if (keyValue.length == 2) {
					String key = keyValue[0].trim().replace("\"", "");
					String valueStr = keyValue[1].trim();

					try {
						Long value = Long.parseLong(valueStr);
						values.put(key, value);
					} catch (NumberFormatException e) {
						// Skip invalid values
					}
				}
			}
		} catch (Exception e) {
			// Return empty map on parse error
		}

		return values;
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

	/**
	 * Split a JSON string into key-value pairs, handling nested objects and arrays.
	 * 
	 * @param content The JSON string content (without outer braces).
	 * @return An array of key-value pair strings.
	 */
	public static String[] splitJsonPairs(String content) {
        List<String> parts = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        int braceDepth = 0;
        int bracketDepth = 0;
        boolean inString = false;
        boolean escaped = false;
        
        for (char c : content.toCharArray()) {
            if (escaped) {
                escaped = false;
                current.append(c);
                continue;
            }
            
            if (c == '\\' && inString) {
                escaped = true;
                current.append(c);
                continue;
            }
            
            if (c == '"') {
                inString = !inString;
                current.append(c);
                continue;
            }
            
            if (!inString) {
                if (c == '{') braceDepth++;
                else if (c == '}') braceDepth--;
                else if (c == '[') bracketDepth++;
                else if (c == ']') bracketDepth--;
                else if (c == ',' && braceDepth == 0 && bracketDepth == 0) {
                    parts.add(current.toString().trim());
                    current = new StringBuilder();
                    continue;
                }
            }
            
            current.append(c);
        }
        
        if (current.length() > 0) {
            parts.add(current.toString().trim());
        }
        
        return parts.toArray(new String[0]);
    }
}
