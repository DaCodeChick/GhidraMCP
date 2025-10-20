from functools import wraps
import hashlib
import json
import logging
import os
from typing import Callable, TypeVar, Any
import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import RequestException, Timeout
import time
from urllib.parse import urljoin, urlparse
from urllib3.util.retry import Retry

# Cache size (256 entries ≈ 1MB memory footprint for typical requests)
CACHE_SIZE = 256

ENABLE_CACHING = True

# Per-endpoint timeout configuration for expensive operations
ENDPOINT_TIMEOUTS = {
	'document_function_complete': 180,     # 3 minutes - comprehensive atomic documentation
	'batch_rename_variables': 120,         # 2 minutes - variable renames trigger re-analysis (increased from 90s)
	'batch_set_comments': 120,             # 2 minutes - multiple comment operations (increased from 90s)
	'analyze_function_complete': 120,      # 2 minutes - comprehensive analysis with decompilation (increased from 90s)
	'batch_decompile_functions': 120,      # 2 minutes - multiple decompilations
	'batch_rename_function_components': 120, # 2 minutes - multiple rename operations (increased from 90s)
	'batch_set_variable_types': 90,        # 1.5 minutes - DataType lookups can be slow
	'analyze_data_region': 90,             # 1.5 minutes - complex data analysis
	'batch_decompile_xref_sources': 120,   # 2 minutes - multiple decompilations
	'create_and_apply_data_type': 60,      # 1 minute - struct creation + application
	'batch_create_labels': 60,             # 1 minute - creating multiple labels in transaction
	'set_plate_comment': 45,               # 45 seconds - plate comments can be lengthy
	'set_function_prototype': 45,          # 45 seconds - prototype changes trigger re-analysis
	'rename_function_by_address': 45,      # 45 seconds - function renames update xrefs
	'rename_variable': 30,                 # 30 seconds - single variable rename
	'rename_function': 45,                 # 45 seconds - function renames update xrefs
	'decompile_function': 45,              # 45 seconds - decompilation can be slow for large functions
	'default': 30                          # 30 seconds for all other operations
}

# Make log level configurable via environment variable (DEBUG, INFO, WARNING, ERROR, CRITICAL)
# Default to INFO for production use
LOG_LEVEL = os.getenv("GHIDRA_MCP_LOG_LEVEL", "INFO")

# Maximum retry attempts for transient failures (3 attempts with exponential backoff)
MAX_RETRIES = 3

# HTTP request timeout (30s chosen for slow decompilation operations)
REQUEST_TIMEOUT = 30

# Exponential backoff factor (0.5s, 1s, 2s, 4s sequence)
RETRY_BACKOFF_FACTOR = 0.5

class GhidraConnectionError(Exception):
	"""Raised when connection to Ghidra server fails"""
	pass

class GhidraHTTPClient:
	T = TypeVar('T')
	
	def __init__(self, server_url: str, timeout: int):
		self.adapter = HTTPAdapter(max_retries=self.retry_strategy, pool_connections=20, pool_maxsize=20)
		self.logger = logging.getLogger('GhidraHTTPClient')
		self.retry_strategy = Retry(
			total=MAX_RETRIES,
			backoff_factor=RETRY_BACKOFF_FACTOR,
			status_forcelist=[429, 500, 502, 503, 504],
		)
		self.server_url = server_url
		self.session = requests.Session()
		self.timeout = timeout
		
		self.session.mount("http://", self.adapter)
		self.session.mount("https://", self.adapter)
		logging.basicConfig(
			level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
			format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
		)

	def cached_request(self, cache_duration: int = 300) -> Callable[[Callable[..., T]], Callable[..., T]]:
		"""
		Decorator to cache HTTP requests for specified duration.

		Args:
			cache_duration: Cache time-to-live in seconds (default: 300 = 5 minutes)

		Returns:
			Decorated function with caching capability
		"""
		def decorator(self, func: Callable[..., GhidraHTTPClient.T]) -> Callable[..., GhidraHTTPClient.T]:
			cache: dict[str, tuple[GhidraHTTPClient.T, float]] = {}
			
			@wraps(func)
			def wrapper(*args: Any, **kwargs: Any) -> GhidraHTTPClient.T:
				if not ENABLE_CACHING:
					return func(*args, **kwargs)
					
				key = cache_key(*args, **kwargs)
				now = time.time()
				
				# Check cache
				if key in cache:
					result, timestamp = cache[key]
					if now - timestamp < cache_duration:
						self.logger.debug(f"Cache hit for {func.__name__}")
						return result
					else:
						del cache[key]  # Expired
				
				# Execute and cache
				result = func(*args, **kwargs)
				cache[key] = (result, now)
				
				# Simple cache cleanup (keep only most recent items)
				if len(cache) > CACHE_SIZE:
					oldest_key = min(cache.keys(), key=lambda k: cache[k][1])
					del cache[oldest_key]
					
				return result
			return wrapper
		return decorator
	
	@cached_request(cache_duration=180)  # 3-minute cache for GET requests
	def safe_get(self, endpoint: str, params: dict = None, retries: int = 3) -> list:
		"""
		Perform a GET request with enhanced error handling and retry logic.
		
		Args:
			endpoint: The API endpoint to call
			params: Optional query parameters
			retries: Number of retry attempts for server errors
		
		Returns:
			List of strings representing the response
		"""
		
		if params is None:
			params = {}
			
		# Validate server URL for security
		if not validate_server_url(self.server_url):
			self.logger.error(f"Invalid or unsafe server URL: {self.server_url}")
			return ["Error: Invalid server URL - only local addresses allowed"]

		url = urljoin(self.server_url, endpoint)

		# Get endpoint-specific timeout
		self.timeout = get_timeout_for_endpoint(endpoint)
		self.logger.debug(f"Using timeout of {self.timeout}s for endpoint {endpoint}")

		for attempt in range(retries):
			try:
				start_time = time.time()
				response = self.session.get(url, params=params, timeout=self.timeout)
				response.encoding = 'utf-8'
				duration = time.time() - start_time

				self.logger.info(f"Request to {endpoint} took {duration:.2f}s (attempt {attempt + 1}/{retries})")

				if response.ok:
					return response.text.splitlines()
				elif response.status_code == 404:
					self.logger.warning(f"Endpoint not found: {endpoint}")
					return [f"Endpoint not found: {endpoint}"]
				elif response.status_code >= 500:
					# Server error - retry with exponential backoff
					if attempt < retries - 1:
						wait_time = 2 ** attempt
						self.logger.warning(f"Server error {response.status_code}, retrying in {wait_time}s...")
						time.sleep(wait_time)
						continue
					else:
						self.logger.error(f"Server error after {retries} attempts: {response.status_code}")
						raise GhidraConnectionError(f"Server error: {response.status_code}")
				else:
					self.logger.error(f"HTTP {response.status_code}: {response.text.strip()}")
					return [f"Error {response.status_code}: {response.text.strip()}"]

			except Timeout:
				self.logger.warning(f"Request timeout on attempt {attempt + 1}/{retries}")
				if attempt < retries - 1:
					continue
				return [f"Timeout connecting to Ghidra server after {retries} attempts"]
			except RequestException as e:
				self.logger.error(f"Request failed: {str(e)}")
				return [f"Request failed: {str(e)}"]
			except Exception as e:
				self.logger.error(f"Unexpected error: {str(e)}")
				return [f"Unexpected error: {str(e)}"]

		return ["Unexpected error in safe_get"]
	
	def safe_get_uncached(self, endpoint: str, params: dict = None, retries: int = 3) -> list:
		"""
		Perform a GET request WITHOUT caching (for stateful queries like get_current_address).

		Args:
			endpoint: The API endpoint to call
			params: Optional query parameters
			retries: Number of retry attempts for server errors

		Returns:
			List of strings representing the response
		"""
		if params is None:
			params = {}

		# Validate server URL for security
		if not validate_server_url(self.server_url):
			self.logger.error(f"Invalid or unsafe server URL: {self.server_url}")
			return ["Error: Invalid server URL - only local addresses allowed"]

		url = urljoin(self.server_url, endpoint)

		# Get endpoint-specific timeout
		self.timeout = get_timeout_for_endpoint(endpoint)
		self.logger.debug(f"Using timeout of {self.timeout}s for endpoint {endpoint}")

		for attempt in range(retries):
			try:
				start_time = time.time()
				response = self.session.get(url, params=params, timeout=self.timeout)
				response.encoding = 'utf-8'
				duration = time.time() - start_time

				self.logger.info(f"Request to {endpoint} took {duration:.2f}s (attempt {attempt + 1}/{retries})")

				if response.ok:
					return response.text.splitlines()
				elif response.status_code == 404:
					self.logger.warning(f"Endpoint not found: {endpoint}")
					return [f"Endpoint not found: {endpoint}"]
				elif response.status_code >= 500:
					# Server error - retry with exponential backoff
					if attempt < retries - 1:
						wait_time = 2 ** attempt
						self.logger.warning(f"Server error {response.status_code}, retrying in {wait_time}s...")
						time.sleep(wait_time)
						continue
					else:
						self.logger.error(f"Server error after {retries} attempts: {response.status_code}")
						raise GhidraConnectionError(f"Server error: {response.status_code}")
				else:
					self.logger.error(f"HTTP {response.status_code}: {response.text.strip()}")
					return [f"Error {response.status_code}: {response.text.strip()}"]

			except Timeout:
				self.logger.warning(f"Request timeout on attempt {attempt + 1}/{retries}")
				if attempt < retries - 1:
					continue
				return [f"Timeout connecting to Ghidra server after {retries} attempts"]
			except RequestException as e:
				self.logger.error(f"Request failed: {str(e)}")
				return [f"Request failed: {str(e)}"]
			except Exception as e:
				self.logger.error(f"Unexpected error: {str(e)}")
				return [f"Unexpected error: {str(e)}"]

		return ["Unexpected error in safe_get_uncached"]

	def safe_post(self, endpoint: str, data: dict | str, retries: int = 3) -> str:
		"""
		Perform a POST request with enhanced error handling and retry logic.
		
		Args:
			endpoint: The API endpoint to call
			data: Data to send (dict or string)
			retries: Number of retry attempts for server errors
		
		Returns:
			String response from the server
		"""
		# Validate server URL for security  
		if not self.validate_server_url(self.server_url):
			self.logger.error(f"Invalid or unsafe server URL: {self.server_url}")
			return "Error: Invalid server URL - only local addresses allowed"

		url = urljoin(self.server_url, endpoint)

		for attempt in range(retries):
			try:
				start_time = time.time()
				
				if isinstance(data, dict):
					self.logger.info(f"Sending POST to {url} with form data: {data}")
					response = self.session.post(url, data=data, timeout=REQUEST_TIMEOUT)
				else:
					self.logger.info(f"Sending POST to {url} with raw data: {data}")
					response = self.session.post(url, data=data.encode("utf-8"), timeout=REQUEST_TIMEOUT)

				response.encoding = 'utf-8'
				duration = time.time() - start_time

				self.logger.info(f"POST to {endpoint} took {duration:.2f}s (attempt {attempt + 1}/{retries}), status: {response.status_code}")

				if response.ok:
					return response.text.strip()
				elif response.status_code == 404:
					self.logger.warning(f"Endpoint not found: {endpoint}")
					return f"Endpoint not found: {endpoint}"
				elif response.status_code >= 500:
					# Server error - retry with exponential backoff
					if attempt < retries - 1:
						wait_time = 2 ** attempt
						self.logger.warning(f"Server error {response.status_code}, retrying in {wait_time}s...")
						time.sleep(wait_time)
						continue
					else:
						self.logger.error(f"Server error after {retries} attempts: {response.status_code}")
						raise GhidraConnectionError(f"Server error: {response.status_code}")
				else:
					self.logger.error(f"HTTP {response.status_code}: {response.text.strip()}")
					return f"Error {response.status_code}: {response.text.strip()}"
					
			except Timeout:
				self.logger.warning(f"POST timeout on attempt {attempt + 1}/{retries}")
				if attempt < retries - 1:
					continue
				return f"Timeout connecting to Ghidra server after {retries} attempts"
			except RequestException as e:
				self.logger.error(f"POST request failed: {str(e)}")
				return f"Request failed: {str(e)}"
			except Exception as e:
				self.logger.error(f"Unexpected error in POST: {str(e)}")
				return f"Unexpected error: {str(e)}"
		
		return "Unexpected error in safe_post"
	
	def safe_post_json(self, endpoint: str, data: dict, retries: int = 3) -> str:
		"""
		Perform a JSON POST request with enhanced error handling and retry logic.
		
		Args:
			endpoint: The API endpoint to call
			data: Data to send as JSON
			retries: Number of retry attempts for server errors
		
		Returns:
			String response from the server
		"""
		# Validate server URL for security  
		if not validate_server_url(self.server_url):
			self.logger.error(f"Invalid or unsafe server URL: {self.server_url}")
			return "Error: Invalid server URL - only local addresses allowed"

		url = urljoin(self.server_url, endpoint)

		# Get endpoint-specific timeout
		self.timeout = get_timeout_for_endpoint(endpoint)
		self.logger.debug(f"Using timeout of {self.timeout}s for endpoint {endpoint}")

		for attempt in range(retries):
			try:
				start_time = time.time()
				
				self.logger.info(f"Sending JSON POST to {url} with data: {data}")
				response = self.session.post(url, json=data, timeout=self.timeout)
				
				response.encoding = 'utf-8'
				duration = time.time() - start_time

				self.logger.info(f"JSON POST to {endpoint} took {duration:.2f}s (attempt {attempt + 1}/{retries}), status: {response.status_code}")
				
				if response.ok:
					return response.text.strip()
				elif response.status_code == 404:
					return f"Error: Endpoint {endpoint} not found"
				elif response.status_code >= 500:
					if attempt < retries - 1:  # Only log retry attempts for server errors
						self.logger.warning(f"Server error {response.status_code} on attempt {attempt + 1}, retrying...")
						time.sleep(1)  # Brief delay before retry
						continue
					else:
						return f"Error: Server error {response.status_code} after {retries} attempts"
				else:
					return f"Error: HTTP {response.status_code} - {response.text}"
					
			except requests.RequestException as e:
				if attempt < retries - 1:
					self.logger.warning(f"Request failed on attempt {attempt + 1}, retrying: {e}")
					time.sleep(1)
					continue
				else:
					self.logger.error(f"Request failed after {retries} attempts: {e}")
					return f"Error: Request failed - {str(e)}"

		return "Error: Maximum retries exceeded"

def cache_key(*args: Any, **kwargs: Any) -> str:
	"""
	Generate a cache key from function arguments.

	Returns:
		MD5 hash of serialized arguments
	"""

	key_data = {"args": args, "kwargs": kwargs}
	return hashlib.md5(json.dumps(key_data, sort_keys=True, default=str).encode()).hexdigest()

def get_timeout_for_endpoint(endpoint: str) -> int:
	"""Get the appropriate timeout for a specific endpoint"""

	# Extract endpoint name from URL path
	endpoint_name = endpoint.strip('/').split('/')[-1]
	return ENDPOINT_TIMEOUTS.get(endpoint_name, ENDPOINT_TIMEOUTS['default'])

def validate_server_url(url: str) -> bool:
	"""Validate that the server URL is safe to use"""

	try:
		parsed = urlparse(url)
		# Only allow HTTP/HTTPS protocols
		if parsed.scheme not in ['http', 'https']:
			return False
		# Only allow local addresses for security
		if parsed.hostname in ['localhost', '127.0.0.1', '::1']:
			return True
		# Allow private network ranges
		if parsed.hostname and (
			parsed.hostname.startswith('192.168.') or
			parsed.hostname.startswith('10.') or
			parsed.hostname.startswith('172.')
		):
			return True
		return False
	except Exception:
		return False
