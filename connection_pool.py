import logging

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger(__name__)

class ConnectionPool:
    """
    A connection pool manager for the requests library that implements:
    - Connection pooling
    - Retry logic
    - Timeout settings
    - Context manager support for automatic cleanup
    """

    def __init__(
            self,
            pool_connections=10,
            pool_maxsize=10,
            max_retries=10,
            backoff_factor=1.5,
            timeout=(10, 27),  # (connect, read) timeouts
    ):
        self.session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 502, 503, 504],
        )

        # Create and configure the adapter with the retry strategy
        adapter = HTTPAdapter(
            pool_connections=pool_connections,  # number of connection pools
            pool_maxsize=pool_maxsize,  # connections per pool
            max_retries=retry_strategy,
            pool_block=False  # don't block when pool is full
        )

        # Mount the adapter for both HTTP and HTTPS
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        self.timeout = timeout

    def get(self, url, **kwargs):
        """Send a GET request using the pooled session."""
        kwargs.setdefault('timeout', self.timeout)
        response = self.session.get(url, **kwargs)
        log.debug("GET %s %s", url, response.status_code)
        return response

    def post(self, url, **kwargs):
        """Send a POST request using the pooled session."""
        kwargs.setdefault('timeout', self.timeout)
        response = self.session.post(url, **kwargs)
        log.debug("POST %s %s", url, response.status_code)
        return response

    def close(self):
        """Close the session and cleanup."""
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
