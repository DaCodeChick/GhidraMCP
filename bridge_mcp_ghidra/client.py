from functools import wraps
import hashlib
import json
import logging
import requests
from requests.adapters import HTTPAdapter
import time
from urllib.parse import urljoin, urlparse
from urllib3.util.retry import Retry

CACHE_SIZE = 256
ENABLE_CACHING = True
MAX_RETRIES = 3
REQUEST_TIMEOUT = 30
RETRY_BACKOFF_FACTOR = 0.5

class GhidraConnectionError(Exception):
    """Raised when connection to Ghidra server fails"""
    pass

class GhidraHTTPClient:
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
            level=logging.DEBUG,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

    @staticmethod
    def cache_key(*args, **kwargs) -> str:
        """Generate a cache key from function arguments."""
        key_data = {"args": args, "kwargs": kwargs}
        return hashlib.md5(json.dumps(key_data, sort_keys=True, default=str).encode()).hexdigest()


    def cached_request(cache_duration=300):  # 5 minutes default
        """Decorator to cache HTTP requests."""
        def decorator(func):
            cache = {}
            
            @wraps(func)
            def wrapper(*args, **kwargs):
                if not ENABLE_CACHING:
                    return func(*args, **kwargs)
                    
                key = GhidraHTTPClient.cache_key(*args, **kwargs)
                now = time.time()
                
                # Check cache
                if key in cache:
                    result, timestamp = cache[key]
                    if now - timestamp < cache_duration:
                        logging.getLogger('GhidraHTTPClient').debug(f"Cache hit for {func.__name__}")
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
        if not self.validate_server_url(self.server_url):
            self.logger.error(f"Invalid or unsafe server URL: {self.server_url}")
            return ["Error: Invalid server URL - only local addresses allowed"]

        url = urljoin(self.server_url, endpoint)

        for attempt in range(retries):
            try:
                start_time = time.time()
                response = self.session.get(url, params=params, timeout=REQUEST_TIMEOUT)
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

            except requests.exceptions.Timeout:
                self.logger.warning(f"Request timeout on attempt {attempt + 1}/{retries}")
                if attempt < retries - 1:
                    continue
                return [f"Timeout connecting to Ghidra server after {retries} attempts"]
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Request failed: {str(e)}")
                return [f"Request failed: {str(e)}"]
            except Exception as e:
                self.logger.error(f"Unexpected error: {str(e)}")
                return [f"Unexpected error: {str(e)}"]

        return ["Unexpected error in safe_get"]

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
        if not self.validate_server_url(self.server_url):
            self.logger.error(f"Invalid or unsafe server URL: {self.server_url}")
            return "Error: Invalid server URL - only local addresses allowed"

        url = urljoin(self.server_url, endpoint)

        for attempt in range(retries):
            try:
                start_time = time.time()
                
                self.logger.info(f"Sending JSON POST to {url} with data: {data}")
                response = self.session.post(url, json=data, timeout=REQUEST_TIMEOUT)
                
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
                    
            except requests.exceptions.Timeout:
                self.logger.warning(f"POST timeout on attempt {attempt + 1}/{retries}")
                if attempt < retries - 1:
                    continue
                return f"Timeout connecting to Ghidra server after {retries} attempts"
            except requests.exceptions.RequestException as e:
                self.logger.error(f"POST request failed: {str(e)}")
                return f"Request failed: {str(e)}"
            except Exception as e:
                self.logger.error(f"Unexpected error in POST: {str(e)}")
                return f"Unexpected error: {str(e)}"
        
        return "Unexpected error in safe_post"
    
    @staticmethod
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
