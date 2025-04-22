import asyncio
import aiohttp
import logging
import re
import json
import hashlib
import os
from bs4 import BeautifulSoup
import random
import time
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from typing import Optional, Dict, Set, Any, List, Tuple
from collections import defaultdict
import heapq
import sys
import ssl
from datetime import datetime
import io
import concurrent.futures
import traceback

# Import structlog for structured logging
try:
    import structlog
    HAS_STRUCTLOG = True
except ImportError:
    HAS_STRUCTLOG = False
    print("structlog not installed. Using standard logging.")

# Set up logger
logger = logging.getLogger(__name__)

# Create structured logger if available
if HAS_STRUCTLOG:
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    struct_logger = structlog.get_logger()
else:
    struct_logger = logger

# Initialize log samplers for high-volume logs
LOG_SAMPLERS = {
    'extract_urls': random.Random(),
    'extract_endpoints': random.Random(),
    'process_html': random.Random(),
    'process_js': random.Random()
}

def should_log(sampler_key, sample_rate=0.1):
    """Determine if a log message should be emitted based on sampling rate"""
    if sampler_key not in LOG_SAMPLERS:
        return True
    return LOG_SAMPLERS[sampler_key].random() < sample_rate

# Optional imports - handle gracefully if not available
try:
    from pyquery import PyQuery
except ImportError:
    PyQuery = None
    logger.warning("PyQuery not installed. Some features may be limited.")

# Compile common regex patterns at module level for performance
URL_PATTERNS = [
    # Full URLs in quotes
    re.compile(r'[\'"`](https?://[^\'"`\s><,;]+)[\'"`]'),
    # Absolute paths in quotes
    re.compile(r'[\'"`](/[^\'"`\s><,;]+)[\'"`]'),
    # URLs in fetch, axios calls
    re.compile(r'fetch\s*\(\s*[\'"`](https?://[^\'"`]+|/[^\'"`]+)[\'"`]'),
    re.compile(r'axios\s*\.\s*\w+\s*\(\s*[\'"`](https?://[^\'"`]+|/[^\'"`]+)[\'"`]'),
    # URLs in ajax calls
    re.compile(r'\$\s*\.\s*ajax\s*\(\s*\{\s*url\s*:\s*[\'"`](https?://[^\'"`]+|/[^\'"`]+)[\'"`]'),
]

REACT_ROUTE_PATTERNS = [
    re.compile(r'path\s*:\s*[\'"`]([^\'"`;]+)[\'"`]'),  # path: "/something"
    re.compile(r'<Route\s+[^>]*path\s*=\s*[\'"`]([^\'"`;]+)[\'"`]'), # <Route path="/something"
    re.compile(r'\.createBrowserRouter\(\[\s*\{\s*path\s*:\s*[\'"`]([^\'"`;]+)[\'"`]'), # createBrowserRouter([{ path: "/something"
    re.compile(r'routes\s*=\s*\[\s*\{\s*path\s*:\s*[\'"`]([^\'"`;]+)[\'"`]'), # routes = [{ path: "/something"
]

ROUTE_PATTERN = re.compile(r'routes\s*=\s*\[([^\]]+)\]')
PATH_MATCHES_PATTERN = re.compile(r'path\s*:\s*[\'"`]([^\'"`;]+)[\'"`]')
LAZY_ROUTE_PATTERN = re.compile(r'loadable\(\(\)\s*=>\s*import\([\'"`]([^\'"`;]+)[\'"`]\)')

# API endpoint patterns
ENDPOINT_PATTERNS = [
    re.compile(r'[\'"`](/api/[^\'"`\s><,;]+)[\'"`]'),      # API endpoints
    re.compile(r'[\'"`](/v\d+/[^\'"`\s><,;]+)[\'"`]'),     # Versioned API endpoints
    re.compile(r'[\'"`](/rest/[^\'"`\s><,;]+)[\'"`]'),     # REST API endpoints
    re.compile(r'[\'"`](/graphql/?[^\'"`\s><,;]*)[\'"`]'), # GraphQL endpoints
    re.compile(r'url\s*:\s*[\'"`]([^\'"`]+)[\'"`]'),       # URL parameters in configs
    re.compile(r'path\s*:\s*[\'"`]([^\'"`]+)[\'"`]'),      # Path parameters in configs
    re.compile(r'endpoint\s*:\s*[\'"`]([^\'"`]+)[\'"`]'),  # Endpoint in configs
    re.compile(r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]'),    # Fetch API calls
    re.compile(r'axios\s*\.\s*\w+\s*\(\s*[\'"`]([^\'"`]+)[\'"`]'), # Axios calls
    re.compile(r'\$\.(?:get|post|ajax)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]'), # jQuery AJAX calls
    re.compile(r'router\s*\.\s*\w+\s*\(\s*[\'"`]([^\'"`]+)[\'"`]'), # Router paths
    re.compile(r'route\s*\(\s*[\'"`]([^\'"`]+)[\'"`]'),    # Route definitions
    re.compile(r'<Route\s+path\s*=\s*[\'"`]([^\'"`]+)[\'"`]'), # React Router
    re.compile(r'app\s*\.\s*\w+\s*\(\s*[\'"`]([^\'"`]+)[\'"`]'), # Express routes
    re.compile(r'createResource\s*\(\s*[\'"`]([^\'"`]+)[\'"`]'), # REST resources
    re.compile(r'api\s*\.\s*\w+\s*\(\s*[\'"`]([^\'"`]+)[\'"`]'), # API client calls
]

# Create a thread pool executor at module level
THREAD_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=8)

# Define excluded file extensions for crawling
# These file types are either binary or static resources that don't need to be crawled
EXCLUDED_EXTENSIONS = {
    # Images
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg', '.ico', '.tiff',
    # Audio/Video
    '.mp3', '.mp4', '.wav', '.avi', '.mov', '.flv', '.wmv', '.ogg', '.webm',
    # Documents
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.epub',
    # Archives
    '.zip', '.rar', '.tar', '.gz', '.7z', '.bz2',
    # Fonts
    '.ttf', '.woff', '.woff2', '.eot', '.otf',
    # Other binaries
    '.exe', '.dll', '.bin', '.iso', '.dmg',
    # Scripts and stylesheets that don't need crawling
    '.js', '.css', '.scss', '.less',
    # Data files
    '.xml', '.csv', '.json', '.yaml', '.yml'
}

# JavaScript framework detection patterns
FRAMEWORK_PATTERNS = {
    'react': [
        'react.', 'reactjs', 'react-dom', '__REACT_ROOT__', 'react.development.js',
        'react.production.min.js', '_reactRootContainer', 'react-app', '__REACT_DATA__',
        'ReactDOM', '<Provider', '<Router', '<Route', 'createRoot', 'useEffect', 'useState',
        'useContext', 'createContext'
    ],
    'angular': [
        'ng-app', 'ng-controller', 'ng-model', 'angular.js', 'angular.min.js',
        'ng-', '[ng-', 'ng_', '*ngIf', '*ngFor', 'NgModule', 'formGroup', '[(ngModel)]',
        '@angular', 'ngOnInit', '@Component', '@Injectable', '@Input', '@Output', 'ngClass',
        'ngStyle', 'routerLink'
    ],
    'vue': [
        'vue.js', 'vue.min.js', 'v-bind', 'v-model', 'v-if', 'v-for', 'v-on',
        'v-show', 'Vue.', '__vue__', 'data-v-', 'VueRouter', 'Vuex', 'vuex.esm.browser.js',
        'vue-router', 'v-html', 'Vue.component', 'Vue.directive', '<template', 'computed:',
        'methods:'
    ],
    'jquery': [
        'jquery', 'jQuery', '$(', 'jquery.min.js', 'jquery-ui.js', 'ready(', '.ajax(',
        '.load(', '.post(', '.get(', '$.', 'jQuery.'
    ],
    'ember': [
        'ember.js', 'ember.min.js', 'EmberENV', 'Ember.Application', 'data-ember-',
        'ember-view', 'ember-application', 'Ember.Route', 'Ember.Controller', 'Ember.Component'
    ],
    'svelte': [
        'svelte', '__SVELTE', 'svelte-', 'SvelteComponent', 'createSvelteComponent',
        '<svelte:', 'svelte3', 'svelte/internal'
    ],
    'next': [
        'next/router', 'next/link', 'NextJS', 'next/head', '__NEXT_DATA__', '__NEXT_LOADED_PAGES__',
        'next/script', '__next', 'next/image', '/_next/'
    ],
    'nuxt': [
        'nuxt.js', '__NUXT__', 'nuxt-link', 'nuxt-child', 'NuxtLink', '$nuxt', '_nuxt',
        'nuxt-render', 'nuxt-layout', 'NuxtJS', 'asyncData', 'fetch('
    ]
}

class AdaptiveRateLimiter:
    def __init__(self, initial_rate_limit: float = 1.0, burst_limit: int = 10):
        self.logger = logging.getLogger(__name__)
        # Changed initial rate limit from 5.0 to 1.0 for conservative starting point
        self.rate_limit = initial_rate_limit
        self.burst_limit = burst_limit
        self.last_request_time = defaultdict(float)
        self.token_bucket = defaultdict(lambda: burst_limit)
        self.lock = asyncio.Lock()
        self.success_count = defaultdict(int)
        self.failure_count = defaultdict(int)
        self.response_times = defaultdict(list)
        self.concurrency = defaultdict(lambda: 3)  # Default concurrency of 3
        self.last_adjustment_time = defaultdict(float)
        # Track domain-specific rate limits
        self.domain_rate_limits = defaultdict(lambda: initial_rate_limit)
        # Track retry-after directives
        self.retry_after = defaultdict(float)
        
    async def acquire(self, domain: Optional[str] = None) -> bool:
        async with self.lock:
            current_time = time.time()
            domain = domain or "default"
            
            # Check if we're in a retry-after period
            if self.retry_after[domain] > current_time:
                return False
                
            # Use domain-specific rate limit
            rate_limit = self.domain_rate_limits[domain]
            
            time_since_last = current_time - self.last_request_time[domain]
            new_tokens = time_since_last * rate_limit
            self.token_bucket[domain] = min(self.token_bucket[domain] + new_tokens, self.burst_limit)
            
            if self.token_bucket[domain] >= 1:
                self.token_bucket[domain] -= 1
                self.last_request_time[domain] = current_time
                return True
            return False
    
    async def wait_for_token(self, domain: Optional[str] = None):
        domain = domain or "default"
        while not await self.acquire(domain):
            # Calculate wait time based on domain-specific rate and retry-after
            current_time = time.time()
            if self.retry_after[domain] > current_time:
                # Wait until retry-after period expires
                wait_time = self.retry_after[domain] - current_time + 0.1  # Add a small buffer
                if HAS_STRUCTLOG:
                    struct_logger.debug("retry_after_wait", domain=domain, wait_time=wait_time)
                else:
                    self.logger.debug(f"Waiting for retry-after period: {wait_time:.2f}s for {domain}")
            else:
                # Dynamic wait time based on domain rate limit
                rate_limit = self.domain_rate_limits[domain]
                wait_time = 1.0 / rate_limit if rate_limit > 0 else 1.0
                
            await asyncio.sleep(min(wait_time, 10.0))  # Cap max sleep at 10 seconds
    
    def report_failure(self, domain: Optional[str] = None):
        domain = domain or "default"
        # Reduce the domain-specific rate limit
        self.domain_rate_limits[domain] = max(0.2, self.domain_rate_limits[domain] / 1.5)
        self.failure_count[domain] += 1
        
        if HAS_STRUCTLOG:
            struct_logger.warning("rate_limit_reduced", 
                                domain=domain, 
                                new_rate=self.domain_rate_limits[domain],
                                failures=self.failure_count[domain])
        else:
            self.logger.warning(f"Reduced rate limit for {domain} to {self.domain_rate_limits[domain]:.2f} req/s after failure")
        
        # Adjust concurrency when there's a significant failure rate
        if self.failure_count[domain] + self.success_count[domain] >= 10:
            failure_rate = self.failure_count[domain] / (self.failure_count[domain] + self.success_count[domain])
            
            if failure_rate > 0.2:  # More than 20% failure rate
                prev_concurrency = self.concurrency[domain]
                # More gradual concurrency reduction
                if prev_concurrency > 5:
                    self.concurrency[domain] = max(5, prev_concurrency - 2)
                elif prev_concurrency > 2:
                    self.concurrency[domain] = max(2, prev_concurrency - 1)
                
                # Only log if concurrency actually changed
                if prev_concurrency != self.concurrency[domain]:
                    if HAS_STRUCTLOG:
                        struct_logger.info("concurrency_reduced", 
                                         domain=domain,
                                         old_concurrency=prev_concurrency,
                                         new_concurrency=self.concurrency[domain],
                                         failure_rate=failure_rate,
                                         avg_response_time=self._get_avg_response_time(domain))
                    else:
                        self.logger.info(f"Reducing concurrency significantly: {prev_concurrency} -> {self.concurrency[domain]} (error rate: {failure_rate:.2f}, avg response time: {self._get_avg_response_time(domain):.2f}s)")
                
                # Reset counters to adapt to changing conditions
                self._reset_counters(domain)
    
    def report_429(self, domain: Optional[str], retry_after: Optional[str] = None):
        """Handle 429 Too Many Requests responses with Retry-After headers"""
        domain = domain or "default"
        current_time = time.time()
        
        # Process Retry-After header if present
        if retry_after:
            try:
                # Handle seconds format
                if retry_after.isdigit():
                    delay = float(retry_after)
                    self.retry_after[domain] = current_time + delay
                else:
                    # Handle HTTP-date format
                    retry_date = datetime.strptime(retry_after, "%a, %d %b %Y %H:%M:%S %Z")
                    delay = (retry_date - datetime.now()).total_seconds()
                    if delay > 0:
                        self.retry_after[domain] = current_time + delay
                    else:
                        # If date is in the past, use a default backoff
                        self.retry_after[domain] = current_time + 30
                
                if HAS_STRUCTLOG:
                    struct_logger.warning("rate_limit_429", 
                                        domain=domain, 
                                        retry_after=retry_after, 
                                        wait_seconds=self.retry_after[domain] - current_time)
                else:
                    self.logger.warning(f"Rate limited (429) for {domain}. Waiting until {datetime.fromtimestamp(self.retry_after[domain])} ({self.retry_after[domain] - current_time:.2f}s)")
            except Exception as e:
                # If we can't parse the retry-after, use a default value
                if HAS_STRUCTLOG:
                    struct_logger.error("retry_after_parse_error", 
                                      domain=domain, 
                                      retry_after=retry_after, 
                                      error=str(e))
                else:
                    self.logger.error(f"Error parsing Retry-After header '{retry_after}': {str(e)}")
                # Default to 30 seconds backoff
                self.retry_after[domain] = current_time + 30
        else:
            # No explicit retry time, use a default exponential backoff
            backoff = min(60 * (self.failure_count[domain] + 1), 300)  # Cap at 5 minutes
            self.retry_after[domain] = current_time + backoff
            if HAS_STRUCTLOG:
                struct_logger.warning("rate_limit_backoff", 
                                    domain=domain, 
                                    backoff_seconds=backoff)
            else:
                self.logger.warning(f"Rate limited for {domain}. Using exponential backoff: {backoff}s")
        
        # Significantly reduce the rate limit for this domain
        prev_rate = self.domain_rate_limits[domain]
        self.domain_rate_limits[domain] = max(0.1, prev_rate / 4)  # More aggressive reduction for 429
        
        if HAS_STRUCTLOG:
            struct_logger.warning("rate_limit_reduced_drastically", 
                                domain=domain, 
                                old_rate=prev_rate,
                                new_rate=self.domain_rate_limits[domain])
        else:
            self.logger.warning(f"Drastically reduced rate limit for {domain} from {prev_rate:.2f} to {self.domain_rate_limits[domain]:.2f} req/s")
        
        # Also report as a normal failure to adjust concurrency
        self.report_failure(domain)
    
    def report_success(self, domain: Optional[str] = None, response_time: float = None):
        domain = domain or "default"
        # Gradually increase the domain-specific rate limit after successful requests
        self.domain_rate_limits[domain] = min(5.0, self.domain_rate_limits[domain] * 1.05)  # More gradual increase, capped at 5 req/sec
        self.success_count[domain] += 1
        
        # Track response time for concurrency adjustments
        if response_time is not None:
            self.response_times[domain].append(response_time)
            # Keep only the last 20 response times
            if len(self.response_times[domain]) > 20:
                self.response_times[domain].pop(0)
        
        # Consider increasing concurrency when enough successful requests
        current_time = time.time()
        # Don't adjust too frequently - at most every 15 seconds
        if current_time - self.last_adjustment_time[domain] > 15:
            if self.success_count[domain] >= 10 and self.failure_count[domain] == 0:
                avg_time = self._get_avg_response_time(domain)
                prev_concurrency = self.concurrency[domain]
                
                # Increase concurrency if response times are good
                if avg_time < 1.0 and self.concurrency[domain] < 10:
                    self.concurrency[domain] += 1
                    if HAS_STRUCTLOG:
                        struct_logger.info("concurrency_increased", 
                                         domain=domain,
                                         old_concurrency=prev_concurrency,
                                         new_concurrency=self.concurrency[domain],
                                         avg_response_time=avg_time)
                    else:
                        self.logger.info(f"Increasing concurrency: {prev_concurrency} -> {self.concurrency[domain]} (avg response time: {avg_time:.2f}s)")
                    self._reset_counters(domain)
                    self.last_adjustment_time[domain] = current_time
    
    def get_domain_concurrency(self, domain: Optional[str] = None) -> int:
        """Get the current recommended concurrency for a domain"""
        domain = domain or "default"
        return self.concurrency[domain]
        
    def get_domain_rate_limit(self, domain: Optional[str] = None) -> float:
        """Get the current rate limit for a domain"""
        domain = domain or "default"
        return self.domain_rate_limits[domain]
    
    def _get_avg_response_time(self, domain: str) -> float:
        """Calculate average response time for the domain"""
        if not self.response_times[domain]:
            return 0
        return sum(self.response_times[domain]) / len(self.response_times[domain])
    
    def _reset_counters(self, domain: str):
        """Reset success and failure counters for a domain"""
        self.success_count[domain] = 0
        self.failure_count[domain] = 0

def normalize_url(url: str, target_domain: Optional[str] = None) -> Optional[str]:
    """
    Normalize URL by removing tracking parameters and standardizing format.
    Filter out binary/static files and external domains if target_domain is provided.
    
    Args:
        url: The URL to normalize
        target_domain: The target domain to restrict URLs to (optional)
        
    Returns:
        Normalized URL string or None if URL should be excluded
    """
    try:
        parsed = urlparse(url)
        
        # Skip URLs with invalid or unsupported protocols
        if parsed.scheme not in ('http', 'https', ''):
            if HAS_STRUCTLOG:
                struct_logger.debug("skipped_unsupported_protocol", url=url, protocol=parsed.scheme)
            else:
                logger.debug(f"Skipping URL with unsupported protocol: {url}")
            return None
            
        # Check file extension
        path = parsed.path.lower()
        _, ext = os.path.splitext(path)
        if ext in EXCLUDED_EXTENSIONS:
            if HAS_STRUCTLOG:
                struct_logger.debug("skipped_binary_file", url=url, extension=ext)
            else:
                logger.debug(f"Skipping binary/static file URL: {url} (extension: {ext})")
            return None
            
        # Check domain if target_domain is provided
        if target_domain and parsed.netloc:
            url_domain = parsed.netloc.lower()
            # Allow the exact domain and its subdomains
            if url_domain != target_domain and not url_domain.endswith('.' + target_domain):
                if HAS_STRUCTLOG:
                    struct_logger.debug("skipped_external_domain", 
                                      url=url, 
                                      url_domain=url_domain, 
                                      target_domain=target_domain)
                else:
                    logger.debug(f"Skipping external domain URL: {url} (domain: {url_domain})")
                return None
        
        # Continue with regular URL normalization
        query_params = parse_qs(parsed.query)
        
        # List of tracking and unnecessary parameters to remove
        tracking_params = [
            'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
            'fbclid', 'gclid', 'ref', 'source', 'campaign', 'referrer', 'click_id',
            '_ga', '_gl', 'mc_cid', 'mc_eid', 'zanpid', 'ref_src', 'ref_url',
            'affiliate', 'partner', 'from', 'feature', 'social', 'share',
            'timestamp', 'ts', 'time', 'date', 'random', 'rand', 'r',
            'banner', 'impression', 'ad', 'adid', 'adref', 'adposition',
            'network', 'placement', 'creative', 'keyword',
            'session', 'sid', 'sessionid', 'visitor', 'visitorid',
            'redirect', 'redirected', 'referer', 'redir'
        ]
        
        # Remove all tracking parameters
        for param in list(query_params.keys()):
            if param in tracking_params or any(param.startswith(prefix) for prefix in ['utm_', 'pk_', 'fb_', 'yclid', 'mkwid']):
                del query_params[param]
        
        # Rebuild query string
        query_string = urlencode(query_params, doseq=True)
        parsed = parsed._replace(query=query_string)
        
        # Convert the URL back to a string
        normalized = urlunparse(parsed)
        
        # Strip trailing slash for consistency, unless it's the root URL
        if normalized.endswith('/') and parsed.path != '/':
            normalized = normalized[:-1]
            
        return normalized
    except Exception as e:
        if HAS_STRUCTLOG:
            struct_logger.warning("url_normalization_error", url=url, error=str(e))
        else:
            logger.warning(f"Error normalizing URL {url}: {str(e)}")
        return None

def canonicalize_url(url: str) -> Optional[str]:
    """
    Create a canonical version of a URL for consistent comparison.
    
    Args:
        url: The URL to canonicalize
        
    Returns:
        Canonicalized URL or None if URL should be excluded
    """
    normalized = normalize_url(url)
    if normalized is None:
        return None
        
    parsed = urlparse(normalized)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path
    if not path:
        path = '/'
    elif not path.endswith('/') and '.' not in path.split('/')[-1]:
        path = path + '/'
    if parsed.query:
        query_params = parse_qs(parsed.query)
        sorted_query = urlencode(sorted(query_params.items()), doseq=True)
    else:
        sorted_query = ''
    canonicalized = urlunparse((scheme, netloc, path, parsed.params, sorted_query, ''))
    return canonicalized

def generate_url_fingerprint(url: str) -> Optional[str]:
    """
    Generate a unique fingerprint for a URL for deduplication.
    
    Args:
        url: The URL to generate a fingerprint for
        
    Returns:
        MD5 hash of the canonicalized URL or None if URL should be excluded
    """
    canonicalized = canonicalize_url(url)
    if canonicalized is None:
        return None
    hash_obj = hashlib.md5(canonicalized.encode('utf-8'))
    return hash_obj.hexdigest()

def filter_framework_urls(urls, framework_types=None):
    """
    Filter out URLs that are likely related to UI frameworks like React, Angular, Vue, etc.
    
    Args:
        urls (list): List of URLs to filter
        framework_types (dict, optional): Dictionary of detected frameworks {framework_name: bool}
    
    Returns:
        list: Filtered list of URLs without framework-related paths
    """
    if not urls:
        return []
    
    # If no framework types provided, create empty dict
    if framework_types is None:
        framework_types = {}
    
    filtered_urls = []
    
    # Common framework-related path patterns to exclude
    framework_path_patterns = [
        # React patterns
        r'/react-', r'/reactjs', r'/react\.', r'/react-dom',
        
        # Angular patterns
        r'/angular', r'/ng-', r'/ngIf', r'/ngFor',
        
        # Vue patterns
        r'/vue', r'/v-', r'/vuex',
        
        # Other UI frameworks
        r'/ui/', r'/material-ui/', r'/base-ui/', r'/joy-ui/',
        
        # Common component names across frameworks
        r'/component', r'/button', r'/modal', r'/slider', r'/menu',
        r'/form', r'/input', r'/select', r'/checkbox', r'/radio',
        r'/grid', r'/table', r'/list', r'/card', r'/tabs', r'/nav',
        r'/dialog', r'/tooltip', r'/popover', r'/drawer',
        
        # Framework documentation patterns
        r'/customization/', r'/theming/', r'/components/', r'/api/',
        r'/guides/', r'/hooks-api/', r'/components-api/',
        r'/getting-started/'
    ]
    
    # Add additional patterns based on detected frameworks
    if framework_types.get('react', False):
        framework_path_patterns.extend([r'/jsx', r'/hooks/', r'/context/'])
    
    if framework_types.get('angular', False):
        framework_path_patterns.extend([r'/directive', r'/module', r'/component', r'/service'])
    
    if framework_types.get('vue', False):
        framework_path_patterns.extend([r'/template', r'/component', r'/vuex'])
    
    # Compile patterns for efficiency
    compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in framework_path_patterns]
    
    for url in urls:
        path = urlparse(url).path.lower()
        
        # Skip URLs with framework-related paths
        if any(pattern.search(path) for pattern in compiled_patterns):
            continue
        
        # Include URLs that are likely to be app endpoints rather than framework resources
        endpoint_indicators = [
            r'/api/', r'/v1/', r'/v2/', r'/rest/', r'/graphql',
            r'/admin', r'/login', r'/logout', r'/register', r'/signup', r'/signin',
            r'/account', r'/user', r'/profile', '/dashboard', r'/settings',
            r'/products', r'/services', r'/cart', r'/checkout'
        ]
        
        if any(re.search(indicator, path, re.IGNORECASE) for indicator in endpoint_indicators):
            filtered_urls.append(url)
            continue
            
        # Skip JSON webpack files which are common in SPA applications
        if '.json' in path and ('webpack' in path or '_nuxt' in path):
            continue
            
        # Include if no framework patterns matched
        if not any(pattern.search(path) for pattern in compiled_patterns):
            filtered_urls.append(url)
    
    return filtered_urls

def detect_framework_types(soup: BeautifulSoup, framework_types: Dict[str, bool]) -> None:
    html_content = str(soup)
    scripts = soup.find_all('script')
    script_srcs = [script.get('src', '') for script in scripts if script.get('src')]
    script_content = ' '.join([script.text for script in scripts if script.text])
    all_attrs = ' '.join([str(attr) for tag in soup.find_all() for attr in tag.attrs.items()])
    combined_text = html_content + ' ' + script_content + ' ' + ' '.join(script_srcs) + ' ' + all_attrs
    for framework, patterns in FRAMEWORK_PATTERNS.items():
        for pattern in patterns:
            if pattern.lower() in combined_text.lower():
                framework_types[framework] = True
                break
    if 'graphql' in combined_text.lower() or '__schema' in combined_text or 'apollo' in combined_text.lower():
        framework_types['graphql'] = True
    if any(api_term in combined_text.lower() for api_term in ['fetch(', 'axios.', '.ajax', 'api/', '/v1/', '/v2/', 'rest/']):
        framework_types['rest_api'] = True

def extract_javascript_urls(soup: BeautifulSoup, domain: str) -> Set[str]:
    """Extract URLs of JavaScript files from the HTML."""
    js_urls = set()
    # Find script tags with src attribute
    for script in soup.find_all('script', src=True):
        src = script.get('src', '')
        if src and not src.startswith('data:'):
            # Handle both absolute and relative URLs
            if src.startswith(('http://', 'https://')):
                parsed_url = urlparse(src)
                if parsed_url.netloc == domain or not parsed_url.netloc:
                    js_urls.add(src)
            else:
                # Construct absolute URL for relative paths
                base_url = f"https://{domain}" if domain else ""
                full_url = urljoin(base_url, src)
                js_urls.add(full_url)
    return js_urls

def extract_urls_from_html(soup: BeautifulSoup, domain: str, base_url: str, target_domain: Optional[str] = None) -> Set[str]:
    """Extract URLs from HTML content."""
    extracted_urls = set()
    
    # Extract all links from anchor tags
    try:
        links = soup.find_all('a', href=True)
        logger.debug(f"Found {len(links)} anchor tags with href attributes")
        
        for link in links:
            try:
                href = link['href']
                if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                    continue
                    
                url = urljoin(base_url, href)
                # Apply URL filtering through normalize_url
                normalized_url = normalize_url(url, target_domain)
                if normalized_url:
                    extracted_urls.add(normalized_url)
            except Exception as e:
                logger.debug(f"Error processing link href '{link.get('href', '')}': {str(e)}")
    except Exception as e:
        logger.debug(f"Error extracting links: {str(e)}")
    
    # Extract forms
    try:
        forms = soup.find_all('form', action=True)
        logger.debug(f"Found {len(forms)} form tags with action attributes")
        
        for form in forms:
            try:
                action = form['action']
                if not action:
                    continue
                    
                url = urljoin(base_url, action)
                # Apply URL filtering
                normalized_url = normalize_url(url, target_domain)
                if normalized_url:
                    extracted_urls.add(normalized_url)
            except Exception as e:
                logger.debug(f"Error processing form action '{form.get('action', '')}': {str(e)}")
    except Exception as e:
        logger.debug(f"Error extracting forms: {str(e)}")
    
    # Extract URLs from all attributes that might contain URLs
    try:
        url_attrs = ['src', 'href', 'data-src', 'data-href', 'data-url', 'data-link']
        for attr in url_attrs:
            elements = soup.find_all(attrs={attr: True})
            logger.debug(f"Found {len(elements)} elements with {attr} attribute")
            
            for elem in elements:
                value = elem.get(attr)
                if isinstance(value, str) and (value.startswith('/') or value.startswith('http')):
                    try:
                        url = urljoin(base_url, value)
                        # Apply URL filtering
                        normalized_url = normalize_url(url, target_domain)
                        if normalized_url:
                            extracted_urls.add(normalized_url)
                    except Exception as e:
                        logger.debug(f"Error processing {attr} '{value}': {str(e)}")
    except Exception as e:
        logger.debug(f"Error processing URL attributes: {str(e)}")
                
    # Handle SPA routes for common frameworks
    try:
        # React Router
        react_links = soup.find_all(attrs={"to": True})
        logger.debug(f"Found {len(react_links)} React Router links")
        for tag in react_links:
            to_val = tag["to"]
            try:
                url = urljoin(base_url, to_val)
                # Apply URL filtering
                normalized_url = normalize_url(url, target_domain)
                if normalized_url:
                    extracted_urls.add(normalized_url)
            except Exception as e:
                logger.debug(f"Error processing React Router link '{to_val}': {str(e)}")
        
        # Angular Router
        angular_links = soup.find_all(attrs={"routerLink": True})
        logger.debug(f"Found {len(angular_links)} Angular Router links")
        for tag in angular_links:
            router_link = tag["routerLink"]
            try:
                url = urljoin(base_url, router_link)
                # Apply URL filtering
                normalized_url = normalize_url(url, target_domain)
                if normalized_url:
                    extracted_urls.add(normalized_url)
            except Exception as e:
                logger.debug(f"Error processing Angular Router link '{router_link}': {str(e)}")
    except Exception as e:
        logger.debug(f"Error processing SPA routes: {str(e)}")
    
    # Handle onclick attributes that might contain URLs
    try:
        onclick_pattern = r'(?:window\.location|location\.href|navigate|open|url)\s*=\s*[\'"`](https?://[^\'"`]+|/[^\'"`]+)[\'"`]'
        onclick_elements = soup.find_all(attrs={"onclick": True})
        logger.debug(f"Found {len(onclick_elements)} elements with onclick attribute")
        
        for tag in onclick_elements:
            onclick = tag["onclick"]
            urls = re.findall(onclick_pattern, onclick)
            for url_match in urls:
                try:
                    url = urljoin(base_url, url_match)
                    # Apply URL filtering
                    normalized_url = normalize_url(url, target_domain)
                    if normalized_url:
                        extracted_urls.add(normalized_url)
                except Exception as e:
                    logger.debug(f"Error processing onclick URL '{url_match}': {str(e)}")
    except Exception as e:
        logger.debug(f"Error processing onclick attributes: {str(e)}")
    
    # Look for common URL patterns in inline scripts
    try:
        scripts = soup.find_all('script')
        logger.debug(f"Found {len(scripts)} script tags")
        
        for script in scripts:
            if script.string:
                try:
                    # Find URL assignments in JavaScript
                    js_urls = extract_urls_from_javascript_string(script.string, base_url, target_domain)
                    if js_urls:
                        logger.debug(f"Extracted {len(js_urls)} URLs from script content")
                        extracted_urls.update(js_urls)
                except Exception as e:
                    logger.debug(f"Error extracting URLs from script content: {str(e)}")
    except Exception as e:
        logger.debug(f"Error processing script tags: {str(e)}")
                
    # Extract URLs from meta refresh tags
    try:
        meta_tags = soup.find_all('meta', attrs={'http-equiv': 'refresh'})
        logger.debug(f"Found {len(meta_tags)} meta refresh tags")
        
        for meta in meta_tags:
            if 'content' in meta.attrs:
                content = meta['content']
                match = re.search(r'url=([^\s"\']+)', content, re.IGNORECASE)
                if match:
                    try:
                        url = urljoin(base_url, match.group(1))
                        # Apply URL filtering
                        normalized_url = normalize_url(url, target_domain)
                        if normalized_url:
                            extracted_urls.add(normalized_url)
                    except Exception as e:
                        logger.debug(f"Error processing meta refresh '{match.group(1)}': {str(e)}")
    except Exception as e:
        logger.debug(f"Error processing meta tags: {str(e)}")
                
    # Extract from canonical and alternate links
    try:
        link_tags = soup.find_all('link', attrs={'rel': ['canonical', 'alternate']})
        logger.debug(f"Found {len(link_tags)} canonical/alternate link tags")
        
        for link in link_tags:
            if 'href' in link.attrs:
                try:
                    url = urljoin(base_url, link['href'])
                    # Apply URL filtering
                    normalized_url = normalize_url(url, target_domain)
                    if normalized_url:
                        extracted_urls.add(normalized_url)
                except Exception as e:
                    logger.debug(f"Error processing link tag href '{link['href']}': {str(e)}")
    except Exception as e:
        logger.debug(f"Error processing link tags: {str(e)}")
    
    logger.debug(f"Completed URL extraction, found {len(extracted_urls)} URLs")
    return extracted_urls

def extract_urls_from_javascript_string(js_content: str, base_url: str, target_domain: Optional[str] = None) -> Set[str]:
    """Extract URLs from a JavaScript string or code."""
    extracted_urls = set()
    domain = urlparse(base_url).netloc
    
    # Use sampling for debug logs
    if should_log('extract_urls'):
        if HAS_STRUCTLOG:
            struct_logger.debug("extracting_js_urls", 
                                content_length=len(js_content), 
                                base_url=base_url)
        else:
            logger.debug(f"Extracting URLs from JavaScript content of length {len(js_content)}")
    
    # Process in chunks for very large files
    chunk_size = 1024 * 100  # 100 KB chunks
    if len(js_content) > chunk_size * 3:  # Only chunk if file is sufficiently large
        logger.debug(f"Processing large JavaScript file in chunks")
        # Process in overlapping chunks to avoid missing matches at boundaries
        overlap = 1000  # 1 KB overlap
        position = 0
        
        while position < len(js_content):
            end_pos = min(position + chunk_size, len(js_content))
            chunk = js_content[position:end_pos]
            
            # Process this chunk
            for pattern in URL_PATTERNS:
                try:
                    matches = pattern.findall(chunk)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0]
                        if not match:
                            continue
                        # Skip data URLs and email links
                        if match.startswith(('mailto:', 'tel:', 'data:', 'blob:', 'javascript:')):
                            continue
                        
                        url = urljoin(base_url, match)
                        # Apply URL filtering
                        normalized_url = normalize_url(url, target_domain)
                        if normalized_url:
                            extracted_urls.add(normalized_url)
                except Exception as e:
                    logger.debug(f"Error extracting URLs using pattern in chunk: {str(e)}")
            
            # Move to next chunk with overlap
            position = end_pos - overlap if end_pos < len(js_content) else len(js_content)
    else:
        # Process the whole content at once for smaller files
        for pattern in URL_PATTERNS:
            try:
                matches = pattern.findall(js_content)
                if matches:
                    logger.debug(f"Found {len(matches)} URLs using pattern")
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    if not match:
                        continue
                    # Skip data URLs and email links
                    if match.startswith(('mailto:', 'tel:', 'data:', 'blob:', 'javascript:')):
                        continue
                    
                    url = urljoin(base_url, match)
                    # Apply URL filtering
                    normalized_url = normalize_url(url, target_domain)
                    if normalized_url:
                        extracted_urls.add(normalized_url)
            except Exception as e:
                logger.debug(f"Error extracting URLs using pattern: {str(e)}")
    
    # Enhanced React Router route extraction
    try:
        # Directly look for React route configurations 
        route_configs = ROUTE_PATTERN.findall(js_content)
        
        if route_configs and should_log('extract_urls'):
            if HAS_STRUCTLOG:
                struct_logger.debug("found_react_routes", 
                                   count=len(route_configs))
            else:
                logger.debug(f"Found React route configurations")
        for config in route_configs:
            # Extract paths from route config
            path_matches = PATH_MATCHES_PATTERN.findall(config)
            for path in path_matches:
                if path.startswith('/'):
                    url = urljoin(base_url, path)
                    # Apply URL filtering
                    normalized_url = normalize_url(url, target_domain)
                    if normalized_url:
                        extracted_urls.add(normalized_url)
    except Exception as e:
        if HAS_STRUCTLOG:
            struct_logger.error("react_route_extraction_error", 
                              error=str(e), 
                              exc_info=True)
        else:
            logger.debug(f"Error extracting React route configurations: {str(e)}")
    
    # Look for router path definitions
    for pattern in REACT_ROUTE_PATTERNS:
        try:
            route_matches = pattern.findall(js_content)
            if route_matches:
                logger.debug(f"Found {len(route_matches)} routes")
            for route in route_matches:
                if route.startswith('/'):
                    url = urljoin(base_url, route)
                    # Apply URL filtering
                    normalized_url = normalize_url(url, target_domain)
                    if normalized_url:
                        extracted_urls.add(normalized_url)
        except Exception as e:
            logger.debug(f"Error extracting routes: {str(e)}")
    
    # Enhanced route extraction for lazy loaded components
    try:
        lazy_routes = LAZY_ROUTE_PATTERN.findall(js_content)
        if lazy_routes:
            logger.debug(f"Found {len(lazy_routes)} lazy loaded components")
        for route in lazy_routes:
            if route.startswith('./') or route.startswith('../'):
                # These are relative imports, not URLs
                continue
            if route.startswith('/'):
                url = urljoin(base_url, route)
                # Apply URL filtering
                normalized_url = normalize_url(url, target_domain)
                if normalized_url:
                    extracted_urls.add(normalized_url)
    except Exception as e:
        logger.debug(f"Error extracting lazy loaded routes: {str(e)}")
    
    # Look for common SPA routes
    common_spa_routes = [
        '/home', '/about', '/contact', '/login', '/register', '/signup', 
        '/dashboard', '/profile', '/settings', '/admin', '/logout',
        '/products', '/services', '/blog', '/news', '/faq', '/help',
        '/cart', '/checkout', '/search', '/categories', '/privacy',
        '/terms', '/support'
    ]
    
    for route in common_spa_routes:
        url = urljoin(base_url, route)
        # Apply URL filtering
        normalized_url = normalize_url(url, target_domain)
        if normalized_url:
            extracted_urls.add(normalized_url)
    
    return extracted_urls

def extract_endpoints_from_js(js_content: str, base_url: str, target_domain: Optional[str] = None) -> Set[str]:
    """Extract API endpoints and URLs from JavaScript content."""
    extracted_endpoints = set()
    domain = urlparse(base_url).netloc
    
    # Use sampling for debug logs
    if should_log('extract_endpoints'):
        if HAS_STRUCTLOG:
            struct_logger.debug("extracting_js_endpoints", 
                               content_length=len(js_content), 
                               base_url=base_url)
        else:
            logger.debug(f"Extracting endpoints from JavaScript content of length {len(js_content)}")
    
    # Processing in chunks for large files
    chunk_size = 1024 * 100  # 100 KB chunks
    if len(js_content) > chunk_size * 3:  # Only chunk if file is sufficiently large
        logger.debug(f"Processing large JavaScript file in chunks for endpoint extraction")
        # Process in overlapping chunks to avoid missing matches at boundaries
        overlap = 1000  # 1 KB overlap
        position = 0
        
        while position < len(js_content):
            end_pos = min(position + chunk_size, len(js_content))
            chunk = js_content[position:end_pos]
            
            # Find endpoints in this chunk
            for pattern in ENDPOINT_PATTERNS:
                try:
                    matches = pattern.findall(chunk)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0]
                        if not match:
                            continue
                        if not match.startswith(('http://', 'https://')):
                            match = urljoin(base_url, match)
                        # Apply URL filtering
                        normalized_url = normalize_url(match, target_domain)
                        if normalized_url:
                            extracted_endpoints.add(normalized_url)
                except Exception as e:
                    logger.debug(f"Error extracting endpoints with pattern in chunk: {str(e)}")
            
            # Move to next chunk with overlap
            position = end_pos - overlap if end_pos < len(js_content) else len(js_content)
    else:
        # Basic URL extraction for smaller files
        extracted_endpoints.update(extract_urls_from_javascript_string(js_content, base_url, target_domain))
        
        # Check for common React patterns
        for pattern in ENDPOINT_PATTERNS:
            try:
                matches = pattern.findall(js_content)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    if not match:
                        continue
                    if not match.startswith(('http://', 'https://')):
                        match = urljoin(base_url, match)
                    # Apply URL filtering
                    normalized_url = normalize_url(match, target_domain)
                    if normalized_url:
                        extracted_endpoints.add(normalized_url)
            except Exception as e:
                logger.debug(f"Error extracting endpoints with pattern: {str(e)}")
    
    # Add common SPA routes but only if they pass the domain filter
    common_spa_routes = [
        '/home', '/about', '/contact', '/login', '/register', '/signup', 
        '/dashboard', '/profile', '/settings', '/admin', '/logout',
        '/products', '/services', '/blog', '/news', '/faq', '/help',
        '/cart', '/checkout', '/search', '/categories', '/privacy',
        '/terms', '/support'
    ]
    
    for route in common_spa_routes:
        url = urljoin(base_url, route)
        # Apply URL filtering
        normalized_url = normalize_url(url, target_domain)
        if normalized_url:
            extracted_endpoints.add(normalized_url)
    
    return extracted_endpoints

def extract_urls_from_json(json_data: Any, domain: str, target_domain: Optional[str] = None) -> Set[str]:
    """Extract URLs from JSON data recursively."""
    base_url = f"https://{domain}"
    urls = set()
    
    def _process_value(value):
        if isinstance(value, str):
            # Check if the value is a URL or path
            if value.startswith(('http://', 'https://')):
                normalized_url = normalize_url(value, target_domain)
                if normalized_url:
                    urls.add(normalized_url)
            elif value.startswith('/'):
                full_url = f"https://{domain}{value}"
                normalized_url = normalize_url(full_url, target_domain)
                if normalized_url:
                    urls.add(normalized_url)
    
    def _walk_data(data):
        if isinstance(data, dict):
            for key, value in data.items():
                # Check keys that commonly hold URLs
                if any(url_term in key.lower() for url_term in ['url', 'link', 'href', 'src', 'path', 'endpoint', 'uri']):
                    _process_value(value)
                
                # Recursively process values
                if isinstance(value, (dict, list)):
                    _walk_data(value)
                
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    _walk_data(item)
                elif isinstance(item, str):
                    _process_value(item)
                    
    _walk_data(json_data)
    return urls

class RobotsTxtParser:
    """Simple robots.txt parser to check if a URL can be crawled."""
    
    def __init__(self, robots_txt_content: str, user_agent: str = '*'):
        self.rules = defaultdict(list)
        self.sitemaps = []
        self.parse(robots_txt_content)
        self.user_agent = user_agent
        
    def parse(self, content: str):
        current_agent = None
        for line in content.split('\n'):
            line = line.strip().lower()
            if not line or line.startswith('#'):
                continue
                
            parts = line.split(':', 1)
            if len(parts) != 2:
                continue
                
            key, value = parts[0].strip(), parts[1].strip()
            
            if key == 'user-agent':
                current_agent = value
            elif key == 'disallow' and current_agent:
                self.rules[current_agent].append(('disallow', value))
            elif key == 'allow' and current_agent:
                self.rules[current_agent].append(('allow', value))
            elif key == 'sitemap':
                self.sitemaps.append(value)
    
    def can_fetch(self, url: str) -> bool:
        path = urlparse(url).path
        
        # Check specific user agent rules first
        if self.user_agent in self.rules:
            return self._check_rules(self.rules[self.user_agent], path)
            
        # Fall back to wildcard rules
        if '*' in self.rules:
            return self._check_rules(self.rules['*'], path)
            
        # No rules found, allow by default
        return True
        
    def _check_rules(self, rules: List[Tuple[str, str]], path: str) -> bool:
        longest_match = None
        longest_match_type = None
        longest_match_length = -1
        
        for rule_type, pattern in rules:
            if pattern and path.startswith(pattern):
                if len(pattern) > longest_match_length:
                    longest_match = pattern
                    longest_match_type = rule_type
                    longest_match_length = len(pattern)
        
        # If no patterns match, allow
        if longest_match is None:
            return True
            
        # Allow overrides Disallow for same pattern length
        return longest_match_type == 'allow'

class CacheManager:
    """Manage a cache of downloaded pages to avoid redownloading."""
    
    def __init__(self, max_size: int = 1000):
        self.cache = {}
        self.max_size = max_size
        self.access_times = {}
    
    def get(self, url: str) -> Optional[Dict[str, Any]]:
        """Get a cached response for a URL."""
        if url in self.cache:
            self.access_times[url] = time.time()
            return self.cache[url]
        return None
    
    def put(self, url: str, response: Dict[str, Any]):
        """Store a response in the cache."""
        if len(self.cache) >= self.max_size:
            # Evict least recently used item
            least_recent_url = min(self.access_times, key=self.access_times.get)
            del self.cache[least_recent_url]
            del self.access_times[least_recent_url]
        
        self.cache[url] = response
        self.access_times[url] = time.time()

class PriorityQueue:
    """Priority queue for URL processing based on importance score."""
    
    def __init__(self):
        self.queue = []
        self.entry_finder = {}
        self.counter = 0
    
    def add_url(self, url: str, depth: int, priority: int = 0):
        """Add a URL to the queue with a given priority."""
        if url in self.entry_finder:
            self.remove_url(url)
        entry = [-priority, self.counter, url, depth]  # Negative for max-heap behavior
        self.entry_finder[url] = entry
        heapq.heappush(self.queue, entry)
        self.counter += 1
    
    def remove_url(self, url: str):
        """Remove a URL from the queue."""
        entry = self.entry_finder.pop(url)
        entry[0] = float('inf')  # Mark as removed
    
    def pop_url(self) -> Optional[Tuple[str, int]]:
        """Get the highest priority URL."""
        while self.queue:
            _, _, url, depth = heapq.heappop(self.queue)
            if url in self.entry_finder:
                del self.entry_finder[url]
                return (url, depth)
        return None
    
    def is_empty(self) -> bool:
        """Check if the queue is empty."""
        return not bool(self.queue)
    
    def __len__(self) -> int:
        """Return the number of URLs in the queue."""
        return len(self.entry_finder)

class IntelligentCrawler:
    def __init__(self, max_crawl_depth: int = 5, max_crawl_urls: int = 200, max_concurrent_requests: int = 3, 
               respect_robots_txt: bool = True, user_agent: str = None, timeout: int = 300, 
               check_common_paths: bool = True):
        """
        Initialize the crawler with configuration.
        
        Args:
            max_crawl_depth: Maximum depth to crawl (default 5)
            max_crawl_urls: Maximum number of URLs to crawl (default 200)
            max_concurrent_requests: Maximum concurrent requests (default 3)
            respect_robots_txt: Whether to respect robots.txt rules (default True)
            user_agent: Custom user agent to use (default None)
            timeout: Request timeout in seconds (default 300)
            check_common_paths: Whether to check common paths (default True)
        """
        # Initialize logger
        self.logger = logging.getLogger(__name__)
        
        # Create domain-aware rate limiter with conservative initial rate
        self.rate_limiter = AdaptiveRateLimiter(initial_rate_limit=1.0)
        
        # Create semaphore for concurrency control
        self.request_semaphore = asyncio.BoundedSemaphore(max_concurrent_requests)
        
        # Store other configuration
        self.max_crawl_depth = max_crawl_depth
        self.max_crawl_urls = max_crawl_urls
        self.max_concurrent_requests = max_concurrent_requests
        self.respect_robots_txt = respect_robots_txt
        self.timeout = timeout
        self.check_common_paths = check_common_paths
        
        # Target domain for restricting crawls (set in crawl method)
        self.target_domain = None
        
        # Initialize per-domain semaphores
        self.domain_semaphores = {}
        
        # User agent for requests
        if user_agent:
            self.user_agent = user_agent
        else:
            self.user_agent = f"Mozilla/5.0 IntelligentCrawler/1.0 (+https://example.com/bot)"
            
        # Initialize result tracking
        self.discovered_urls = set()
        self.crawled_urls = set()
        self.urls_to_crawl = PriorityQueue()
        self.url_fingerprints = set()
        self.stats = defaultdict(int)
        self.start_time = time.time()
        self.robots_parsers = {}
        self.framework_info = defaultdict(bool)
        self.directly_extracted_urls = set()
        
        # Counts for skipped URLs
        self.stats.update({
            'skipped_external_domains': 0,
            'skipped_binary_files': 0
        })
        
        # SPA framework patterns
        self.spa_patterns = {
            "react": ["reactjs", "react.js", "react-dom", "createelement", "react.createelement", "usestate", "useeffect"],
            "angular": ["ng-app", "ng-controller", "ng-model", "angular.js", "angular.min.js", "ngfor", "ngif"],
            "vue": ["vue.js", "vue.min.js", "v-bind", "v-model", "v-for", "v-if", "vuejs"],
            "ember": ["ember.js", "ember.min.js", "emberjs"],
            "svelte": ["svelte.js", "svelte-app"],
            "next": ["__next", "next.js", "next/router", "next/link"],
            "nuxt": ["nuxt.js", "__nuxt", "nuxt-link"],
        }
        
        # HTTP client options for aiohttp
        self.client_options = {
            "timeout": aiohttp.ClientTimeout(total=timeout),
            "headers": {
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Cache-Control": "no-cache"
            }
        }
        
        # Cache for responses
        self.cache = CacheManager()
        
        # Configuration dictionary
        self.config = {
            'skip_final_verification': False,
            'max_crawl_depth': max_crawl_depth,
            'max_crawl_urls': max_crawl_urls,
            'respect_robots_txt': respect_robots_txt,
            'check_common_paths': check_common_paths
        }
        
        # Additional properties to support filter_frameworks
        self.filter_frameworks = True
        self.additional_urls = set()
    
    async def _make_rate_limited_request(self, url: str, method="GET", data=None, headers=None, params=None, json_data=None, semaphore=None, retries=2, allow_redirects=True, silent_errors=False, timeout=None) -> Optional[Dict[str, Any]]:
        """
        Make an HTTP request with rate limiting.
        
        Args:
            url: The URL to request
            method: HTTP method (GET, POST, etc.)
            data: Request data
            headers: Request headers
            params: Query parameters
            json_data: JSON data for the request
            semaphore: Optional semaphore for concurrency control
            retries: Number of retries on failure
            allow_redirects: Whether to follow redirects
            silent_errors: Whether to silence error messages
            timeout: Request timeout in seconds (overrides default)
            
        Returns:
            Dict containing response data or None if failed
        """
        try:
            # Use the provided timeout or fall back to the default
            request_timeout = timeout or self.timeout
            
            parsed_url = urlparse(url)
            hostname = parsed_url.netloc
            
            # Handle empty or malformed URLs
            if not hostname:
                if not silent_errors:
                    self.logger.warning(f"Invalid URL (no hostname): {url}")
                return None
            
            # Set up proper headers if needed
            if headers is None:
                headers = {}
            if 'User-Agent' not in headers:
                headers['User-Agent'] = self.user_agent
            
            # Add semaphore context manager if provided
            if semaphore:
                try:
                    async with semaphore:
                        return await self._perform_request(url, method, data, headers, params, json_data, hostname, retries, allow_redirects, silent_errors, timeout=request_timeout)
                except Exception as e:
                    if not silent_errors:
                        self.logger.error(f"Error making rate-limited request with semaphore for {url}: {str(e)}")
                    return None
            else:
                return await self._perform_request(url, method, data, headers, params, json_data, hostname, retries, allow_redirects, silent_errors, timeout=request_timeout)
        except Exception as e:
            if not silent_errors:
                self.logger.error(f"Unexpected error in _make_rate_limited_request for {url}: {str(e)}")
                self.logger.debug(f"Traceback for request error with {url}:\n{traceback.format_exc()}")
            return None

    async def _process_response(self, response, url, hostname, head_request=False) -> Dict[str, Any]:
        """
        Process the HTTP response.
        
        Args:
            response: The aiohttp response object
            url: The requested URL
            hostname: The hostname from the URL
            head_request: Whether this was a HEAD request
            
        Returns:
            Dict containing processed response data
        """
        try:
            duration = 0
            text = ""
            is_binary = False
            content_type = response.headers.get('content-type', '').lower()
            
            # Check for 429 Too Many Requests status
            if response.status == 429:
                # Handle rate limiting specifically
                retry_after = response.headers.get('retry-after')
                if HAS_STRUCTLOG:
                    struct_logger.error("rate_limited_response", 
                                      url=url, 
                                      retry_after=retry_after)
                else:
                    self.logger.error(f"Rate limited (429) at {url}. Retry-After: {retry_after}")
                
                # Let rate limiter know we need to back off with specific retry-after info
                self.rate_limiter.report_429(hostname, retry_after)
                
                # Update stats
                self.stats['rate_limited_requests'] = self.stats.get('rate_limited_requests', 0) + 1
            
            # Calculate response time
            try:
                if hasattr(response, 'start_time'):
                    duration = time.time() - response.start_time
            except Exception as time_err:
                if HAS_STRUCTLOG:
                    struct_logger.warning("response_time_calculation_error", 
                                        url=url, 
                                        error=str(time_err))
                else:
                    self.logger.warning(f"Error calculating response time for {url}: {str(time_err)}")
            
            # Don't try to read text content for HEAD requests or binary files
            if not head_request and response.status < 300:
                try:
                    is_text = any(text_type in content_type for text_type in [
                        'text/', 'application/json', 'application/javascript', 'application/xml',
                        'application/x-www-form-urlencoded'
                    ])
                    
                    if is_text:
                        try:
                            max_size = 10 * 1024 * 1024  # 10 MB limit
                            text = await response.text(encoding='utf-8', errors='replace')
                            if len(text) > max_size:
                                text = text[:max_size] + " ... [truncated]"
                                self.logger.warning(f"Response truncated for {url} - exceeded 10MB limit")
                        except UnicodeDecodeError as decode_err:
                            text = "(unicode decode error)"
                            self.logger.warning(f"Unicode decode error for {url}: {str(decode_err)}")
                        except asyncio.TimeoutError as timeout_err:
                            text = "(timeout reading content)"
                            self.logger.warning(f"Timeout reading content from {url}: {str(timeout_err)}")
                        except Exception as content_err:
                            text = "(error reading content)"
                            self.logger.warning(f"Error reading content from {url}: {str(content_err)}")
                except Exception as content_type_err:
                    text = "(error determining content type)"
                    self.logger.warning(f"Error determining content type for {url}: {str(content_type_err)}")
            
            # Let rate limiter know this was a success
            try:
                self.rate_limiter.report_success(hostname, duration)
            except Exception as rate_err:
                if HAS_STRUCTLOG:
                    struct_logger.warning("rate_limiter_report_error", url=url, error=str(rate_err))
                else:
                    self.logger.warning(f"Error reporting success to rate limiter for {url}: {str(rate_err)}")
            
            # Update stats
            try:
                # Store response status code distribution
                status_key = f"status_{response.status // 100}xx"
                self.stats[status_key] = self.stats.get(status_key, 0) + 1
            except Exception as stats_err:
                self.logger.warning(f"Error updating stats for {url}: {str(stats_err)}")
                
            return {
                "url": str(response.url),
                "status": response.status,
                "headers": dict(response.headers),
                "text": text,
                "duration": duration,
                "is_binary": is_binary,
                "content_type": content_type,
            }
            
        except Exception as e:
            error_trace = traceback.format_exc()
            if HAS_STRUCTLOG:
                struct_logger.error("response_processing_error", 
                                  url=url, 
                                  error=str(e),
                                  traceback=error_trace)
            else:
                self.logger.error(f"Fatal error processing response from {url}: {str(e)}\nTraceback: {error_trace}")
            raise

    async def crawl(self, url: str) -> Dict[str, Any]:
        """
        Main crawl method to discover and explore URLs starting from a seed URL.
        
        Args:
            url: The starting URL to begin crawling from
            
        Returns:
            Dictionary containing discovered URLs and crawl statistics
        """
        try:
            start_time = time.time()
            self.logger.info(f"Starting crawl from {url}")
            
            # Set the target domain from the start URL
            parsed_url = urlparse(url)
            # Remove 'www.' prefix if present for more flexible domain matching
            self.target_domain = parsed_url.netloc.lower()
            if self.target_domain.startswith('www.'):
                self.target_domain = self.target_domain[4:]
                
            if HAS_STRUCTLOG:
                struct_logger.info("crawl_started", 
                                  url=url, 
                                  target_domain=self.target_domain)
            else:
                self.logger.info(f"Target domain: {self.target_domain}")
            
            # Reset counters and collections
            self.stats = {
                'pages_crawled': 0,
                'successful_requests': 0,
                'failed_requests': 0,
                'total_size': 0,
                'queue_overflow': 0,
                'js_files_processed': 0,
                'css_files_processed': 0,
                'urls_discovered': 0,
                'request_errors': 0,
                'skipped_external_domains': 0,
                'skipped_binary_files': 0
            }
            
            # Initialize collections to track crawl state
            self.discovered_urls = set()
            self.url_fingerprints = set()  # For deduplication
            self.visited_urls = set()
            self.all_urls = set()
            self.queue = PriorityQueue()
            
            # Initialize framework detection
            self.framework_info = {
                'react': False,
                'angular': False,
                'vue': False,
                'jquery': False,
                'ember': False,
                'svelte': False,
                'next': False,
                'nuxt': False,
                'is_spa': False,
            }
            
            # Initialize directly extracted URLs set
            self.directly_extracted_urls = set()
            
            try:
                # Initialize robots.txt handling
                self.domain = urlparse(url).netloc
                self.base_url = f"{urlparse(url).scheme}://{self.domain}"
                self.robots_parsers = {}
                
                # Add starting URL to queue
                initial_url_fp = generate_url_fingerprint(url)
                self.url_fingerprints.add(initial_url_fp)
                self.discovered_urls.add(url)
                self.queue.add_url(url, 0, priority=100)  # Highest priority for seed URL
                
                # Load initial robots.txt if configured
                if self.respect_robots_txt:
                    try:
                        await self._load_robots_txt(self.base_url)
                    except Exception as e:
                        self.logger.error(f"Failed to load robots.txt: {str(e)}")
                
                # Add basic directories to check
                if self.check_common_paths:
                    try:
                        await self._queue_common_dirs(url, self.queue, self.url_fingerprints, self.discovered_urls)
                    except Exception as e:
                        self.logger.error(f"Failed to queue common dirs: {str(e)}")
            except Exception as setup_err:
                self.logger.error(f"Error during crawl setup: {str(setup_err)}")
                import traceback
                self.logger.debug(f"Traceback for setup error:\n{traceback.format_exc()}")
                # Continue with what we have
            
            # Main crawl loop
            # Create a new semaphore for this crawl session with proper concurrency control
            semaphore = asyncio.Semaphore(self.max_concurrent_requests)
            self.semaphore = semaphore  # Store at class level for use by other methods
            tasks = []
            processed_count = 0
            
            self.logger.info(f"Starting crawl with concurrency {self.max_concurrent_requests}")
            
            # Process URL queue until empty or limits reached
            try:
                while not self.queue.is_empty() and len(self.visited_urls) < self.max_crawl_urls:
                    try:
                        # Pop URL from queue
                        queue_item = self.queue.pop_url()
                        if not queue_item:
                            self.logger.debug("Empty queue item returned, skipping")
                            continue
                            
                        current_url, current_depth = queue_item
                        
                        # Skip if already processed or too deep
                        if current_url in self.visited_urls:
                            self.logger.debug(f"Skipping {current_url} - already in visited_urls")
                            continue
                            
                        if current_depth > self.max_crawl_depth:
                            self.logger.debug(f"Skipping {current_url} - depth {current_depth} exceeds max {self.max_crawl_depth}")
                            continue
                        
                        # Check robots.txt rules
                        try:
                            if self.respect_robots_txt and not await self.check_robots_txt(self.base_url, current_url):
                                self.logger.debug(f"Skipping {current_url} (disallowed by robots.txt)")
                                continue
                        except Exception as robots_err:
                            self.logger.warning(f"Error checking robots.txt for {current_url}: {str(robots_err)}")
                            # Continue processing if robots.txt check fails
                        
                        # Process the URL (either directly or as a task)
                        if processed_count < self.max_concurrent_requests:
                            # Process first few URLs directly to warm up
                            try:
                                await self.process_url(current_url, current_depth)
                                self.visited_urls.add(current_url)
                                processed_count += 1
                                self.logger.debug(f"Directly processed URL {current_url}")
                            except Exception as direct_err:
                                self.logger.error(f"Error directly processing URL {current_url}: {str(direct_err)}")
                                import traceback
                                self.logger.debug(f"Traceback for direct process error:\n{traceback.format_exc()}")
                        else:
                            # Create task for concurrent processing with proper error handling
                            try:
                                task = asyncio.create_task(
                                    self._process_with_semaphore(semaphore, current_url, current_depth, self.visited_urls)
                                )
                                tasks.append(task)
                                self.logger.debug(f"Created task for URL {current_url}")
                            except Exception as task_err:
                                self.logger.error(f"Error creating task for {current_url}: {str(task_err)}")
                                import traceback
                                self.logger.debug(f"Traceback for task creation error:\n{traceback.format_exc()}")
                        
                        # Log progress occasionally
                        if len(self.visited_urls) % 10 == 0 and len(self.visited_urls) > 0:
                            self.logger.info(f"Crawled {len(self.visited_urls)} URLs, queue size: {len(self.queue)}")
                        
                        # Occasionally clean up completed tasks
                        if len(tasks) >= self.max_concurrent_requests * 2:
                            try:
                                # Use wait with timeout to avoid blocking indefinitely
                                done, pending = await asyncio.wait(
                                    tasks, 
                                    return_when=asyncio.FIRST_COMPLETED,
                                    timeout=5.0
                                )
                                
                                # Process completed tasks and check for exceptions
                                for task in done:
                                    try:
                                        # Get result to handle any exceptions
                                        task.result()
                                    except Exception as task_err:
                                        self.logger.error(f"Error in completed task: {str(task_err)}")
                                
                                # Update task list to only include pending tasks
                                tasks = list(pending)
                                self.logger.debug(f"Cleaned up tasks: {len(done)} completed, {len(pending)} pending")
                            except Exception as wait_err:
                                self.logger.error(f"Error waiting for tasks: {str(wait_err)}")
                                # If waiting for tasks fails, clear and recreate all tasks
                                for task in tasks:
                                    if not task.done():
                                        task.cancel()
                                tasks = []
                                self.logger.warning("Reset task list due to error")
                    except Exception as loop_err:
                        self.logger.error(f"Error in crawl loop: {str(loop_err)}")
                        import traceback
                        self.logger.debug(f"Traceback for loop error:\n{traceback.format_exc()}")
            except Exception as crawl_err:
                self.logger.error(f"Fatal error in crawl loop: {str(crawl_err)}")
                import traceback
                self.logger.debug(f"Traceback for fatal crawl error:\n{traceback.format_exc()}")
            
            # Wait for all remaining tasks to complete
            if tasks:
                self.logger.info(f"Waiting for {len(tasks)} remaining tasks to complete...")
                try:
                    # Use wait with timeout to avoid hanging indefinitely
                    done, pending = await asyncio.wait(tasks, timeout=30.0)
                    
                    # Cancel any tasks that didn't complete within the timeout
                    for task in pending:
                        task.cancel()
                        self.logger.warning("Cancelled task that didn't complete in time")
                    
                    # Check for exceptions in completed tasks
                    for task in done:
                        try:
                            task.result()
                        except asyncio.CancelledError:
                            pass
                        except Exception as task_err:
                            self.logger.error(f"Error in final task: {str(task_err)}")
                except Exception as e:
                    self.logger.error(f"Error gathering tasks: {str(e)}")
                    # Try to cancel all tasks if gathering failed
                    for task in tasks:
                        if not task.done():
                            task.cancel()
            
            # Combine all discovered URLs
            try:
                self.all_urls = self.discovered_urls.union(self.additional_urls if hasattr(self, 'additional_urls') else set())
                
                # Filter out framework-related URLs if needed
                if self.filter_frameworks:
                    pre_filter_count = len(self.all_urls)
                    self.all_urls = set(filter_framework_urls(self.all_urls, self.framework_info))
                    self.logger.info(f"After framework filtering: {len(self.all_urls)} URLs (removed {pre_filter_count - len(self.all_urls)} framework URLs)")
            except Exception as url_err:
                self.logger.error(f"Error finalizing URL list: {str(url_err)}")
                # Use what we have
            
            # Final verification of URLs - make more efficient by:
            # 1. Prioritizing more likely real URLs
            # 2. Limiting verification attempts
            # 3. Being more flexible in accepting URLs
            verified_urls = []
            try:
                if not self.config.get('skip_final_verification', False):
                    self.logger.info("Performing final verification of all URLs to ensure they exist...")
                    verification_count = 0
                    max_verifications = min(200, len(self.all_urls))  # Cap verification attempts
                    
                    # Prioritize URLs by likelihood of existence
                    sorted_urls = list(self.all_urls)
                    sorted_urls.sort(key=lambda u: 
                        # Higher priority for URLs that were directly extracted from HTML
                        (-100 if u in self.directly_extracted_urls else 0) +
                        # Lower priority for auto-generated routes
                        (100 if '/api/' in u else 0) +
                        # Simple paths more likely to exist
                        (50 if u.count('/') <= 2 else 0)
                    )
                    
                    # Initialize verified_urls list
                    verified_urls = []
                    
                    # Only verify a reasonable number of URLs to avoid long waits
                    for url in sorted_urls[:max_verifications]:
                        verification_count += 1
                        try:
                            if await self._verify_url_exists(url):
                                verified_urls.append(url)
                                self.logger.debug(f"Verified URL: {url}")
                        except Exception as verify_err:
                            self.logger.warning(f"Error verifying URL {url}: {str(verify_err)}")
                        
                        # Show progress
                        if verification_count % 10 == 0:
                            self.logger.info(f"Verified {len(verified_urls)} URLs out of {verification_count} attempts (total candidates: {len(self.all_urls)})")
                    
                    # If verification found too few URLs, fall back to including unverified ones
                    if len(verified_urls) < 5 and len(self.all_urls) > 10:
                        self.logger.warning(f"Very few URLs verified ({len(verified_urls)}). Including some unverified URLs in results.")
                        # Include direct URLs from HTML that weren't verified (they're more likely to be real)
                        for url in self.directly_extracted_urls:
                            if url not in verified_urls and len(verified_urls) < 50:
                                verified_urls.append(url)
                                
                    self.logger.info(f"Verified {len(verified_urls)} URLs out of {verification_count} attempts")
                    # Convert to set at the end
                    self.all_urls = set(verified_urls)
            except Exception as verify_err:
                self.logger.error(f"Error during URL verification: {str(verify_err)}")
                import traceback
                self.logger.debug(f"Traceback for verification error:\n{traceback.format_exc()}")
                # If verification fails, use the unverified URLs
                self.all_urls = self.discovered_urls
            
            # Calculate elapsed time
            elapsed_time = time.time() - start_time
            self.logger.info(f"Crawl completed in {elapsed_time:.2f} seconds. Total URLs: {len(self.all_urls)}")
            
            # Organize results
            results = {
                'urls': sorted(list(self.all_urls)),
                'stats': self.stats,
                'framework_info': self.framework_info,
                'elapsed_time': elapsed_time,
                'seed_url': url
            }
            
            return results
            
        except Exception as e:
            self.logger.error(f"Fatal error in crawl method: {str(e)}")
            import traceback
            self.logger.debug(f"Traceback for fatal crawl method error:\n{traceback.format_exc()}")
            
            # Return at least something useful
            return {
                'urls': sorted(list(self.discovered_urls)) if hasattr(self, 'discovered_urls') else [],
                'stats': self.stats if hasattr(self, 'stats') else {'error': str(e)},
                'framework_info': self.framework_info if hasattr(self, 'framework_info') else {},
                'elapsed_time': time.time() - (start_time if 'start_time' in locals() else time.time()),
                'seed_url': url,
                'error': str(e)
            }

    async def _perform_request(self, url: str, method, data, headers, params, json_data, hostname, retries, allow_redirects, silent_errors=False, timeout=None) -> Optional[Dict[str, Any]]:
        """
        Perform an HTTP request with retries.
        
        Args:
            url: URL to request
            method: HTTP method
            data: Request data
            headers: Request headers
            params: Request parameters
            json_data: JSON data
            hostname: Hostname for rate limiting
            retries: Number of retries on failure
            allow_redirects: Whether to follow redirects
            silent_errors: Whether to silence error messages
            timeout: Request timeout in seconds
            
        Returns:
            Dictionary with response data or None if failed
        """
        if not url:
            if not silent_errors:
                self.logger.warning(f"Invalid URL (no hostname): {url}")
            return None
            
        last_error = None
        timeout_obj = aiohttp.ClientTimeout(total=timeout or self.timeout)
        
        # Prepare request arguments
        request_args = {
            'method': method,
            'url': url,
            'data': data,
            'headers': headers,
            'params': params,
            'json': json_data,
            'allow_redirects': allow_redirects,
            'timeout': timeout_obj,
            'ssl': ssl.create_default_context()
        }
        
        # Enable skipping SSL verification in development/testing (careful!)
        if os.environ.get('IGNORE_SSL_ERRORS', '').lower() in ('1', 'true', 'yes'):
            request_args['ssl'] = False
        
        self.logger.debug(f"Requesting URL: {url} (method={method})")
        
        for attempt in range(retries + 1):
            try:
                async with aiohttp.ClientSession() as session:
                    # Record start time for response time measurement
                    start_time = time.time()
                    
                    async with session.request(**request_args) as response:
                        # Store start time on response object for duration calculation
                        response.start_time = start_time
                        
                        # Process the response
                        try:
                            return await self._process_response(response, url, hostname)
                        except Exception as process_err:
                            if not silent_errors:
                                self.logger.error(f"Error processing response from {url}: {str(process_err)}")
                                self.logger.debug(f"Traceback for response processing error with {url}:\n{traceback.format_exc()}")
                            # Report failure to rate limiter
                            self.rate_limiter.report_failure(hostname)
                            return None
                        
            except aiohttp.ClientResponseError as resp_err:
                # Handle HTTP errors (4xx, 5xx)
                last_error = resp_err
                if attempt < retries:
                    if not silent_errors:
                        self.logger.warning(f"HTTP error {resp_err.status} for {url}, retry {attempt}/{retries}")
                    # Wait before retrying
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                elif not silent_errors:
                    self.logger.error(f"HTTP error {resp_err.status} for {url} after {retries} retries")
                
                # Report failure to rate limiter
                self.rate_limiter.report_failure(hostname)
                
            except (aiohttp.ClientConnectorError, aiohttp.ClientOSError, 
                    aiohttp.ServerDisconnectedError, asyncio.TimeoutError) as e:
                # Handle network errors
                last_error = e
                if attempt < retries:
                    if not silent_errors:
                        self.logger.warning(f"Network error for {url}, retry {attempt}/{retries}: {str(e)}")
                    # Wait before retrying
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                elif not silent_errors:
                    self.logger.error(f"Failed to access URL after {retries} retries: {url}: {str(e)}")
                
                # Report failure to rate limiter
                self.rate_limiter.report_failure(hostname)
                
            except Exception as e:
                # Handle unexpected errors
                last_error = e
                if attempt < retries:
                    if not silent_errors:
                        self.logger.warning(f"Unexpected error for {url}, retry {attempt}/{retries}: {str(e)}")
                    # Wait before retrying
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                elif not silent_errors:
                    self.logger.error(f"Unexpected error requesting {url} after {retries} retries: {str(e)}")
                    self.logger.debug(f"Traceback for unexpected request error with {url}:\n{traceback.format_exc()}")
                
                # Report failure to rate limiter
                self.rate_limiter.report_failure(hostname)
        
        # If we get here, all retries have failed
        if not silent_errors and last_error:
            self.logger.error(f"Request to {url} failed with error: {str(last_error)}")
            
        return None
        
    async def _fetch_js_content(self, url: str) -> Optional[str]:
        """Fetch and return JavaScript content from a given URL."""
        try:
            # Perform the request with silent_errors=True to avoid excessive logging for JS files
            response = await self._make_rate_limited_request(url, silent_errors=True)
            if response and response["status"] == 200:
                return response["text"]
        except Exception as e:
            self.logger.error(f"Fatal error performing request to {url}: {str(e)}")
            self.logger.debug(f"Traceback for fatal request error with {url}:\n{traceback.format_exc()}")
        return None

    def _sort_urls_by_importance(self, urls: Set[str]) -> Set[str]:
        url_scores = {}
        for url in urls:
            score = 0
            if '?' in url and '=' in url:
                score += 30
            lower_url = url.lower()
            if any(pattern in lower_url for pattern in ['login', 'admin', 'dashboard', 'control']):
                score += 40
            if any(pattern in lower_url for pattern in ['upload', 'file', 'import', 'export']):
                score += 40
            if any(pattern in lower_url for pattern in ['user', 'profile', 'account', 'member']):
                score += 25
            if any(pattern in lower_url for pattern in ['search', 'find', 'query', 'filter']):
                score += 20
            if any(pattern in lower_url for pattern in ['edit', 'update', 'save', 'delete', 'remove']):
                score += 20
            if any(pattern in lower_url for pattern in ['api', 'rest', 'json', 'graphql', 'v1', 'v2']):
                score += 35
            if any(lower_url.endswith(ext) for ext in ['.php', '.asp', '.aspx', '.jsp', '.do', '.action']):
                score += 15
            if any(lower_url.endswith(ext) for ext in ['.css', '.js', '.png', '.jpg', '.gif', '.svg']):
                score -= 20
            url_scores[url] = score
        sorted_urls = sorted(urls, key=lambda url: url_scores.get(url, 0), reverse=True)
        return set(sorted_urls)

    def detect_spa_type(self, html_content: str) -> Tuple[bool, str]:
        """Detect if the website is a Single Page Application and what framework it uses."""
        is_spa = False
        framework = "unknown"
        
        # Check for common SPA framework indicators
        for fw, patterns in self.spa_patterns.items():
            for pattern in patterns:
                if pattern in html_content:
                    is_spa = True
                    framework = fw
                    break
            if is_spa:
                break

        # Generic SPA indicators if no specific framework was detected
        if not is_spa:
            generic_spa_indicators = [
                'angular', 'react', 'vue', 'ember', 'backbone', 'knockout', 
                'spa', 'single page application', 'router', 'route',
                '"routes":', 'pushState', 'history.push', 'navigation',
                'window.onhashchange', '#/', '#!/', '#!', 'routeProvider'
            ]
            if any(indicator in html_content.lower() for indicator in generic_spa_indicators):
                is_spa = True
                
        return is_spa, framework

    async def _process_html_response(self, response, current_url, current_depth, domain, base_url, 
                                   discovered_urls, url_fingerprints, queue, framework_info, visited_urls):
        """Process HTML responses to extract URLs and gather information."""
        try:
            # Skip processing if response text is empty or not valid HTML
            if not response.get('text') or response.get('is_binary', False):
                if HAS_STRUCTLOG:
                    struct_logger.debug("skipping_empty_response", url=current_url)
                else:
                    logger.debug(f"Skipping empty or binary response from {current_url}")
                return
                
            # Use sampling for debug logs
            if should_log('process_html'):
                if HAS_STRUCTLOG:
                    struct_logger.debug("processing_html", 
                                       url=current_url, 
                                       content_length=len(response.get('text', '')))
                else:
                    logger.debug(f"Processing HTML response from {current_url}, content length: {len(response.get('text', ''))}")
            
            # Try to parse with BeautifulSoup using thread pool for CPU-bound work
            try:
                # Use thread pool for BeautifulSoup parsing
                loop = asyncio.get_event_loop()
                soup = await loop.run_in_executor(
                    THREAD_POOL, 
                    lambda: BeautifulSoup(response['text'], 'html.parser')
                )
                if should_log('process_html'):
                    if HAS_STRUCTLOG:
                        struct_logger.debug("parsed_html", url=current_url)
                    else:
                        logger.debug(f"Successfully created BeautifulSoup object for {current_url}")
            except Exception as e:
                if HAS_STRUCTLOG:
                    struct_logger.error("html_parse_error", 
                                      url=current_url, 
                                      error=str(e), 
                                      exc_info=True)
                else:
                    logger.error(f"Failed to parse HTML from {current_url}: {str(e)}")
                    logger.debug(f"Failed to parse HTML from {current_url}: {str(e)}")
                return
            
            # Print a snippet of the HTML for debugging
            html_snippet = response['text'][:500] + "..." if len(response['text']) > 500 else response['text']
            self.logger.debug(f"HTML snippet from {current_url}:\n{html_snippet}")
                
            # Detect frameworks to adapt crawling strategy
            try:
                detect_framework_types(soup, framework_info)
                self.logger.debug(f"Detected frameworks: {[k for k, v in framework_info.items() if v]}")
                
                # Check if this is a SPA
                try:
                    is_spa, spa_framework = self.detect_spa_type(response['text'])
                    # Make sure the stats dictionary has the expected keys
                    if 'spa_detected' not in self.stats:
                        self.stats['spa_detected'] = False
                    if 'framework_type' not in self.stats:
                        self.stats['framework_type'] = 'unknown'
                        
                    if is_spa:
                        self.logger.info(f"Detected Single Page Application ({spa_framework}) at {current_url}")
                        self.stats['spa_detected'] = True
                        self.stats['framework_type'] = spa_framework
                        framework_info['spa'] = True
                        framework_info[spa_framework] = True
                        
                        # Special SPA handling - add common resource files to queue
                        if current_depth <= 1:  # Only for main domain or first-level pages
                            self._queue_spa_resource_files(domain, base_url, current_depth, queue, 
                                                         url_fingerprints, discovered_urls)
                except KeyError as e:
                    self.logger.error(f"KeyError in SPA detection for {current_url}: {str(e)}")
                except Exception as e:
                    self.logger.error(f"Error in SPA detection for {current_url}: {str(e)}")
            except Exception as e:
                self.logger.warning(f"Framework detection failed for {current_url}: {str(e)}")
                self.logger.debug(f"Framework detection failed: {str(e)}")
            
            # Extract URLs from HTML
            try:
                self.logger.debug(f"Extracting URLs from HTML at {current_url}")
                new_urls = extract_urls_from_html(soup, domain, current_url, self.target_domain)
                self.logger.debug(f"Extracted {len(new_urls)} URLs from {current_url}")
                
                # Mark URLs directly extracted from HTML
                self.directly_extracted_urls.update(new_urls)
                
                # Display some of the extracted URLs for debugging
                if new_urls:
                    sample_urls = list(new_urls)[:5]
                    self.logger.debug(f"Sample extracted URLs: {sample_urls}")
                
                # Process discovered URLs
                for new_url in new_urls:
                    try:
                        # Apply domain filtering and binary file filtering via normalize_url
                        normalized_url = normalize_url(new_url, self.target_domain)
                        if normalized_url is None:
                            continue
                            
                        # Generate URL fingerprint
                        url_fp = generate_url_fingerprint(normalized_url)
                        if url_fp is None:
                            continue
                            
                        if url_fp not in url_fingerprints:
                            self.logger.debug(f"Adding new URL to crawl queue: {normalized_url}")
                            discovered_urls.add(normalized_url)
                            url_fingerprints.add(url_fp)
                            # Safe access to stats dictionary
                            if 'urls_discovered' in self.stats:
                                self.stats['urls_discovered'] += 1
                                
                            # Calculate priority based on URL characteristics
                            priority = self._calculate_url_priority(normalized_url, framework_info)
                                
                            # Increase priority for possible upload endpoints
                            if 'upload' in normalized_url.lower() or 'file' in normalized_url.lower():
                                priority += 30
                                    
                            queue.add_url(normalized_url, current_depth + 1, priority=priority)
                    except Exception as inner_e:
                        self.logger.debug(f"Error processing URL {new_url}: {str(inner_e)}")
                        continue
            except Exception as e:
                self.logger.warning(f"URL extraction failed for {current_url}: {str(e)}")
            
            # For SPAs, look deeper into JavaScript
            try:
                if framework_info.get('spa', False) or self.stats.get('spa_detected', False) or any(fw for fw, v in framework_info.items() if v and fw in ['react', 'vue', 'angular', 'next', 'nuxt']):
                    self.logger.debug(f"Processing JavaScript in SPA at {current_url}")
                    # Extract all script tags
                    script_tags = soup.find_all('script')
                    self.logger.debug(f"Found {len(script_tags)} script tags")
                    
                    for script in script_tags:
                        # Process both inline scripts and external script files
                        if script.string:
                            # Process inline script
                            js_urls = extract_urls_from_javascript_string(script.string, base_url, self.target_domain)
                            if js_urls:
                                self.logger.debug(f"Extracted {len(js_urls)} URLs from inline script")
                            
                            for js_url in js_urls:
                                url_fp = generate_url_fingerprint(js_url)
                                if url_fp not in url_fingerprints:
                                    discovered_urls.add(js_url)
                                    url_fingerprints.add(url_fp)
                                    queue.add_url(js_url, current_depth + 1, priority=50)
                        
                        # Process external JS files
                        src = script.get('src')
                        if src:
                            self.logger.debug(f"Found external script: {src}")
                            if not src.startswith(('http://', 'https://')):
                                src = urljoin(base_url, src)
                                self.logger.debug(f"Converted to absolute URL: {src}")
                            if domain in urlparse(src).netloc or current_depth <= 1:  # Only process same-domain JS or first-level
                                url_fp = generate_url_fingerprint(src)
                                if url_fp not in url_fingerprints and src not in visited_urls:
                                    self.logger.debug(f"Adding script URL to queue: {src}")
                                    discovered_urls.add(src)
                                    url_fingerprints.add(url_fp)
                                    queue.add_url(src, current_depth + 1, priority=60)
            except Exception as e:
                self.logger.warning(f"JavaScript processing failed for SPA at {current_url}: {str(e)}")
                
            # Extract JavaScript files for all sites
            try:
                self.logger.debug(f"Extracting JavaScript URLs from {current_url}")
                js_urls = extract_javascript_urls(soup, domain)
                self.logger.debug(f"Found {len(js_urls)} JavaScript files")
                
                for js_url in js_urls:
                    url_fp = generate_url_fingerprint(js_url)
                    if url_fp not in url_fingerprints and js_url not in visited_urls:
                        self.logger.debug(f"Adding JavaScript URL to queue: {js_url}")
                        discovered_urls.add(js_url)
                        url_fingerprints.add(url_fp)
                        queue.add_url(js_url, current_depth + 1, priority=20)
            except Exception as e:
                self.logger.warning(f"Failed to extract JavaScript URLs from {current_url}: {str(e)}")
                
        except Exception as e:
            self.logger.error(f"Error processing HTML response from {current_url}: {str(e)}")

    async def _process_json_response(self, response, current_url, current_depth, domain, 
                                   discovered_urls, url_fingerprints, queue):
        """Process JSON responses to extract URLs and API endpoints."""
        try:
            self.stats['json_responses_analyzed'] += 1
            json_data = json.loads(response['text'])
            json_urls = extract_urls_from_json(json_data, domain, self.target_domain)
            
            for json_url in json_urls:
                normalized_url = normalize_url(json_url)
                url_fp = generate_url_fingerprint(normalized_url)
                
                if url_fp not in url_fingerprints:
                    discovered_urls.add(normalized_url)
                    url_fingerprints.add(url_fp)
                    self.stats['urls_discovered'] += 1
                    
                    # API endpoints get higher priority
                    priority = 40 if any(term in normalized_url for term in ['/api/', '/v1/', '/v2/']) else 30
                    queue.add_url(normalized_url, current_depth + 1, priority=priority)
        except json.JSONDecodeError:
            self.logger.warning(f"Failed to parse JSON response from {current_url}")
        except Exception as e:
            self.logger.error(f"Error processing JSON from {current_url}: {str(e)}")

    async def _process_javascript_response(self, response, current_url, current_depth, domain, base_url,
                                         discovered_urls, url_fingerprints, queue):
        """Process JavaScript responses to extract URLs and endpoints."""
        if should_log('process_js'):
            if HAS_STRUCTLOG:
                struct_logger.debug("processing_javascript", url=current_url)
            else:
                logger.debug(f"Processing JavaScript response from {current_url}")
                
        if not response.get('text'):
            if HAS_STRUCTLOG:
                struct_logger.debug("empty_javascript", url=current_url)
            else:
                logger.debug(f"Empty JavaScript content from {current_url}")
            return
        
        # Track JS processing in stats
        self.stats['js_files_processed'] = self.stats.get('js_files_processed', 0) + 1
        
        # Clean up the URL
        normalized_url = normalize_url(current_url)
        
        # Use streaming approach for large JavaScript files
        js_content = response.get('text')
        js_length = len(js_content)
        
        if js_length > 1024 * 100:  # More than 100KB
            self.logger.debug(f"Using streaming approach for large JS file ({js_length} bytes)")
            
            # Process in chunks using thread pool for CPU-bound work
            loop = asyncio.get_event_loop()
            extracted_urls = await loop.run_in_executor(
                THREAD_POOL,
                lambda: extract_endpoints_from_js(js_content, base_url, self.target_domain)
            )
        else:
            # Use normal processing for smaller files
            extracted_urls = extract_endpoints_from_js(js_content, base_url, self.target_domain)
        
        self.logger.debug(f"Extracted {len(extracted_urls)} URLs/endpoints from JavaScript")
        
        # Process discovered URLs
        for js_url in extracted_urls:
            url_fp = generate_url_fingerprint(js_url)
            
            if url_fp not in url_fingerprints:
                discovered_urls.add(js_url)
                url_fingerprints.add(url_fp)
                
                # Add with appropriate priority
                is_api = any(term in js_url.lower() for term in ['/api/', '/v1/', '/v2/', '/graphql'])
                priority = 70 if is_api else 30
                queue.add_url(js_url, current_depth + 1, priority=priority)

    async def _process_xml_response(self, response, current_url, current_depth, domain, base_url,
                                   discovered_urls, url_fingerprints, queue):
        """Process XML responses such as sitemaps and RSS feeds."""
        try:
            soup = BeautifulSoup(response['text'], 'xml')
            
            # Process potential sitemap
            if current_url.endswith('sitemap.xml') or 'sitemap' in current_url:
                # Extract links from sitemap
                for loc in soup.find_all('loc'):
                    if loc.string:
                        url = loc.string.strip()
                        parsed_url = urlparse(url)
                        new_domain = parsed_url.netloc
                        
                        # Check if the domain is related
                        is_related = False
                        if new_domain == domain:
                            is_related = True
                        elif new_domain.endswith('.' + domain):
                            is_related = True
                        elif domain.endswith('.' + new_domain):
                            is_related = True
                            
                        if is_related:
                            normalized_url = normalize_url(url)
                            url_fp = generate_url_fingerprint(normalized_url)
                            
                            if url_fp not in url_fingerprints:
                                discovered_urls.add(normalized_url)
                                url_fingerprints.add(url_fp)
                                self.stats['urls_discovered'] += 1
                                # Sitemap URLs are high priority
                                queue.add_url(normalized_url, current_depth + 1, priority=45)
            
            # Process RSS feed
            for link in soup.find_all(['link', 'guid', 'url']):
                if link.string and (link.string.startswith('http') or link.string.startswith('/')):
                    url = link.string.strip()
                    if url.startswith('/'):
                        url = urljoin(base_url, url)
                        
                    parsed_url = urlparse(url)
                    new_domain = parsed_url.netloc
                    
                    # Check if the domain is related
                    is_related = False
                    if new_domain == domain:
                        is_related = True
                    elif new_domain.endswith('.' + domain):
                        is_related = True
                    elif domain.endswith('.' + new_domain):
                        is_related = True
                        
                    if is_related:
                        normalized_url = normalize_url(url)
                        url_fp = generate_url_fingerprint(normalized_url)
                        
                        if url_fp not in url_fingerprints:
                            discovered_urls.add(normalized_url)
                            url_fingerprints.add(url_fp)
                            self.stats['urls_discovered'] += 1
                            queue.add_url(normalized_url, current_depth + 1, priority=25)
        except Exception as e:
            self.logger.warning(f"Failed to parse XML from {current_url}: {str(e)}")

    def _calculate_url_priority(self, url: str, framework_info: Dict[str, bool]) -> int:
        """Calculate a priority score for the URL based on its characteristics."""
        score = 0
        lower_url = url.lower()
        parsed_url = urlparse(url)
        
        # Lower priority for external domains but don't exclude completely
        if parsed_url.netloc != self.domain:
            # Check if it's a subdomain
            if parsed_url.netloc.endswith('.' + self.domain) or self.domain.endswith('.' + parsed_url.netloc):
                score -= 20  # Slight penalty for subdomains
            else:
                # Compare base domains
                base_domain_pattern = r'([^.]+\.[^.]+)$'
                domain_match = re.search(base_domain_pattern, self.domain)
                url_match = re.search(base_domain_pattern, parsed_url.netloc)
                if domain_match and url_match and domain_match.group(1) == url_match.group(1):
                    score -= 30  # Moderate penalty for related domains
                else:
                    score -= 50  # Higher penalty for unrelated domains
            
        # URLs with query parameters often important
        if '?' in url and '=' in url:
            score += 30
            
        # Different types of pages get different priorities
        if any(pattern in lower_url for pattern in ['login', 'admin', 'dashboard', 'control']):
            score += 40
        if any(pattern in lower_url for pattern in ['upload', 'file', 'import', 'export']):
            score += 35
        if any(pattern in lower_url for pattern in ['user', 'profile', 'account', 'member']):
            score += 25
        if any(pattern in lower_url for pattern in ['search', 'find', 'query', 'filter']):
            score += 20
        
        # Action pages
        if any(pattern in lower_url for pattern in ['edit', 'update', 'save', 'delete', 'remove']):
            score += 20
            
        # API endpoints
        if any(pattern in lower_url for pattern in ['api', 'rest', 'json', 'graphql', 'v1', 'v2']):
            score += 35
            
        # Server-side pages often important
        if any(lower_url.endswith(ext) for ext in ['.php', '.asp', '.aspx', '.jsp', '.do', '.action']):
            score += 15
            
        # Static resources less important but don't exclude completely
        if any(lower_url.endswith(ext) for ext in ['.css', '.png', '.jpg', '.jpeg', '.gif', '.svg']):
            score -= 40
            
        # JS files - moderate priority now
        if lower_url.endswith('.js'):
            if '/api/' in lower_url or '/js/api/' in lower_url:
                score += 10  # Higher priority for API-related JS files
            else:
                score -= 20
                
        # Home page and important sections
        if parsed_url.path == '/' or parsed_url.path == '/index.html':
            score += 50
            
        return score

    def _queue_spa_resource_files(self, domain, base_url, current_depth, queue, url_fingerprints, discovered_urls):
        """
        Queue common SPA resource files and routes.
        Modified to be more selective about which common routes to check.
        """
        if not self.framework_info.get('is_spa', False):
            return
            
        # Extract main url parts
        parsed_base = urlparse(base_url)
        domain_base = f"{parsed_base.scheme}://{parsed_base.netloc}"
        
        # More focused list of common routes - these have higher likelihood of existing
        basic_routes = ['/home', '/about', '/contact', '/login', '/register', '/api']
        
        # Limit the number of special routes to try based on the site's characteristics
        # This prevents the crawler from spending too much time on non-existent routes
        for route in basic_routes:
            full_url = f"{domain_base}{route}"
            url_fingerprint = generate_url_fingerprint(full_url)
            
            if url_fingerprint not in url_fingerprints:
                url_fingerprints.add(url_fingerprint)
                discovered_urls.add(full_url)
                self.logger.debug(f"Added common SPA route: {full_url}")
                queue.add_url(full_url, current_depth + 1, 20)  # Higher priority for these routes
                
        # Look for API endpoints if it's an SPA
        # Usually patterns like /api/v1, /api/data, etc. are commonly found
        api_patterns = ['/api', '/api/v1', '/api/v2', '/api/data', '/api/user', '/api/auth']
        for pattern in api_patterns:
            full_url = f"{domain_base}{pattern}"
            url_fingerprint = generate_url_fingerprint(full_url)
            
            if url_fingerprint not in url_fingerprints:
                url_fingerprints.add(url_fingerprint)
                discovered_urls.add(full_url)
                self.logger.debug(f"Added API endpoint: {full_url}")
                queue.add_url(full_url, current_depth + 1, 30)  # Highest priority for API endpoints

    async def simple_crawl(self, base_url: str, max_urls: int = 100) -> List[str]:
        """
        A simplified brute-force crawling approach for when the advanced crawler can't find URLs.
        This is a fallback method that's more aggressive but verifies paths before adding them.
        """
        self.logger.info(f"Using simplified crawler approach for {base_url}")
        discovered_urls = set([base_url])
        to_visit = [base_url]
        visited = set()
        
        # Only check common paths if enabled
        if self.check_common_paths:
            # Common paths to try
            common_paths = [
                '/', '/index.html', '/home', '/login', '/admin', '/upload', '/uploads', '/files',
                '/images', '/img', '/css', '/js', '/javascript', '/assets', '/static',
                '/api', '/rest', '/graphql', '/v1', '/v2', '/api/v1', '/api/v2',
                '/users', '/user', '/profile', '/account', '/dashboard', '/admin',
                '/about', '/contact', '/search', '/find', '/catalog', '/products', '/services',
                '/blog', '/news', '/events', '/gallery', '/media', '/downloads', '/docs',
                '/documentation', '/help', '/support', '/faq', '/cart', '/checkout', '/store',
                '/signup', '/register', '/signin', '/logout', '/auth', '/oauth', '/settings',
                '/config', '/backup', '/wp-admin', '/wp-content', '/wp-includes', '/wp-login',
                '/administrator', '/admin.php', '/admin.html', '/admin/index.php',
                '/forum', '/forums', '/comments', '/feed', '/rss', '/sitemap', '/sitemap.xml',
                '/robots.txt', '/security', '/secure', '/private', '/public', '/cgi-bin',
                '/test', '/demo', '/example', '/examples', '/temp', '/tmp', '/testing',
                '/dev', '/development', '/staging', '/production', '/old', '/new', '/beta',
                '/admin/login', '/admin/upload', '/admin/uploads', '/admin/dashboard'
            ]
            
            # Special extensions to try
            extensions = ['.php', '.asp', '.aspx', '.jsp', '.do', '.action', '.html', '.htm', '']
            
            # Try common paths with extensions but verify they exist first
            verification_tasks = []
            verified_paths = []
            
            # Create a batch of verification tasks for each path+extension combination
            for path in common_paths:
                for ext in extensions:
                    url = urljoin(base_url, path + ext)
                    if url not in discovered_urls:
                        # Create proper task objects
                        task = asyncio.create_task(self._verify_url_exists(url))
                        verification_tasks.append((url, task))
            
            # Process verification tasks in batches to avoid overwhelming the server
            batch_size = 10
            for i in range(0, len(verification_tasks), batch_size):
                batch = verification_tasks[i:i+batch_size]
                # Set a reasonable timeout for each batch
                batch_timeout = time.time() + 15
                active_tasks = batch.copy()
                
                while active_tasks and time.time() < batch_timeout:
                    for i, (url, task) in enumerate(active_tasks[:]):
                        if task.done():
                            try:
                                if task.result():
                                    # URL exists, add it to verified paths
                                    discovered_urls.add(url)
                                    to_visit.append(url)
                                    verified_paths.append(url)
                                    self.logger.debug(f"Verified path exists: {url}")
                            except Exception as e:
                                self.logger.debug(f"Error verifying path {url}: {str(e)}")
                            active_tasks.pop(i)
                    
                    if active_tasks:
                        await asyncio.sleep(0.1)
                
                # Cancel any remaining tasks in this batch that didn't complete
                for _, task in active_tasks:
                    if not task.done():
                        task.cancel()
            
            self.logger.info(f"Verified {len(verified_paths)} additional paths")
        
        # Now perform the crawl on actually verified URLs
        while to_visit and len(visited) < max_urls:
            current_url = to_visit.pop(0)
            if current_url in visited:
                continue
                
            try:
                self.logger.debug(f"Simplified crawler visiting: {current_url}")
                response = await self._make_rate_limited_request(current_url)
                visited.add(current_url)
                
                if not response or not response.get('text'):
                    continue
                    
                # Parse HTML and extract links
                if 'text/html' in response.get('headers', {}).get('content-type', ''):
                    soup = BeautifulSoup(response['text'], 'html.parser')
                    
                    # Extract links from anchor tags
                    for a_tag in soup.find_all('a', href=True):
                        href = a_tag['href']
                        if href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                            continue
                            
                        # Convert to absolute URL
                        url = urljoin(current_url, href)
                        
                        # Check if URL belongs to the same domain
                        if urlparse(url).netloc == urlparse(base_url).netloc:
                            if url not in discovered_urls and url not in visited:
                                discovered_urls.add(url)
                                to_visit.append(url)
                    
                    # Extract form actions
                    for form in soup.find_all('form', action=True):
                        action = form['action']
                        url = urljoin(current_url, action)
                        
                        if urlparse(url).netloc == urlparse(base_url).netloc:
                            if url not in discovered_urls and url not in visited:
                                discovered_urls.add(url)
                                to_visit.append(url)
            except Exception as e:
                self.logger.debug(f"Error in simplified crawler for {current_url}: {str(e)}")
                
        self.logger.info(f"Simplified crawler found {len(discovered_urls)} URLs")
        return list(discovered_urls)

    def _process_css_for_urls(self, response, current_url, current_depth, domain, base_url,
                             discovered_urls, url_fingerprints, queue):
        """Process CSS files to extract URLs like background images and imports."""
        try:
            css_content = response.get('text', '')
            
            # Find all url() patterns
            url_pattern = r'url\([\'"]?(https?://[^\'"\)]+|/[^\'"\)]+)[\'"]?\)'
            urls = re.findall(url_pattern, css_content)
            
            # Find all @import patterns
            import_pattern = r'@import\s+[\'"]?(https?://[^\'"\s;]+|/[^\'"\s;]+)[\'"]?'
            urls.extend(re.findall(import_pattern, css_content))
            
            for url in urls:
                url = url.strip()
                if not url:
                    continue
                    
                # Convert to absolute URL if needed
                if not url.startswith(('http://', 'https://')):
                    url = urljoin(base_url, url)
                    
                url_fp = generate_url_fingerprint(url)
                if url_fp not in url_fingerprints:
                    discovered_urls.add(url)
                    url_fingerprints.add(url_fp)
                    queue.add_url(url, current_depth + 1, priority=5)  # Low priority for CSS resources
                    
        except Exception as e:
            self.logger.warning(f"Error processing CSS for URLs from {current_url}: {str(e)}")

    async def _verify_url_exists(self, url: str) -> bool:
        """
        Verify if a URL exists by sending a HEAD request.
        Used to avoid adding non-existent URLs to the final list.
        """
        try:
            # Skip URLs with query parameters as these might be dynamic
            if '?' in url:
                return True
                
            response = await self._make_rate_limited_request(
                url=url, 
                method="HEAD", 
                allow_redirects=True,
                silent_errors=True,
                timeout=5  # Short timeout for verification
            )
            
            if response:
                status = response.get('status', 0)
                # Accept 2xx, 3xx responses
                return 200 <= status < 400
                
            return False
        except Exception as e:
            self.logger.debug(f"Error verifying URL {url}: {str(e)}")
            return False

    async def _process_response(self, response, url, hostname, head_request=False) -> Dict[str, Any]:
        """
        Process the HTTP response.
        
        Args:
            response: The aiohttp response object
            url: The requested URL
            hostname: The hostname from the URL
            head_request: Whether this was a HEAD request
            
        Returns:
            Dict containing processed response data
        """
        try:
            duration = 0
            text = ""
            is_binary = False
            content_type = response.headers.get('content-type', '').lower()
            
            # Check for 429 Too Many Requests status
            if response.status == 429:
                # Handle rate limiting specifically at ERROR level
                retry_after = response.headers.get('retry-after')
                if HAS_STRUCTLOG:
                    struct_logger.error("rate_limited_response", 
                                      url=url, 
                                      retry_after=retry_after)
                else:
                    logger.error(f"Rate limited (429) at {url}. Retry-After: {retry_after}")
                
                # Let rate limiter know we need to back off
                self.rate_limiter.report_failure(hostname)
                
                # Update stats
                self.stats['rate_limited_requests'] = self.stats.get('rate_limited_requests', 0) + 1
            
            # Calculate response time
            try:
                if hasattr(response, 'start_time'):
                    duration = time.time() - response.start_time
            except Exception as time_err:
                if HAS_STRUCTLOG:
                    struct_logger.warning("response_time_calculation_error", 
                                        url=url, 
                                        error=str(time_err))
                else:
                    logger.warning(f"Error calculating response time for {url}: {str(time_err)}")
            
            # Don't try to read text content for HEAD requests or binary files
            if not head_request and response.status < 300:
                try:
                    is_text = any(text_type in content_type for text_type in [
                        'text/', 'application/json', 'application/javascript', 'application/xml',
                        'application/x-www-form-urlencoded'
                    ])
                    
                    if is_text:
                        try:
                            max_size = 10 * 1024 * 1024  # 10 MB limit
                            text = await response.text(encoding='utf-8', errors='replace')
                            if len(text) > max_size:
                                text = text[:max_size] + " ... [truncated]"
                                self.logger.warning(f"Response truncated for {url} - exceeded 10MB limit")
                        except UnicodeDecodeError as decode_err:
                            # If we can't decode it, it's probably binary
                            self.logger.warning(f"Unicode decode error for {url}: {str(decode_err)}")
                            text = f"[Binary content: unable to decode]"
                            is_binary = True
                        except asyncio.TimeoutError as timeout_err:
                            # Handle timeout during text reading
                            self.logger.warning(f"Timeout reading content from {url}: {str(timeout_err)}")
                            text = f"[Timeout reading content]"
                        except Exception as content_err:
                            # Some other error with content reading
                            self.logger.warning(f"Error reading content from {url}: {str(content_err)}")
                            text = f"[Error reading content: {str(content_err)}]"
                    else:
                        # Non-text content
                        text = f"[Non-text content: {content_type}]"
                        is_binary = True
                except Exception as content_type_err:
                    self.logger.warning(f"Error determining content type for {url}: {str(content_type_err)}")
                    text = "[Error determining content type]"
            
            # Report success to rate limiter
            try:
                self.rate_limiter.report_success(hostname)
            except Exception as rate_err:
                self.logger.warning(f"Error reporting success to rate limiter for {url}: {str(rate_err)}")
            
            # Update stats
            try:
                self.stats['successful_requests'] = self.stats.get('successful_requests', 0) + 1
            except Exception as stats_err:
                self.logger.warning(f"Error updating stats for {url}: {str(stats_err)}")
            
            # Return processed response
            return {
                "status": response.status,
                "text": text,
                "url": str(response.url),
                "headers": {k.lower(): v for k, v in response.headers.items()},
                "duration": duration,
                "is_binary": is_binary,
                "content_type": content_type
            }
        except Exception as e:
            # Include full stack trace at ERROR level
            error_trace = traceback.format_exc()
            if HAS_STRUCTLOG:
                struct_logger.error("response_processing_error", 
                                  url=url, 
                                  error=str(e), 
                                  traceback=error_trace)
            else:
                logger.error(f"Fatal error processing response from {url}: {str(e)}\nTraceback: {error_trace}")
            
            # Return a minimal response that won't break downstream processing
            return {
                "status": getattr(response, 'status', 0),
                "text": f"[Error processing response: {str(e)}]",
                "url": url,
                "headers": getattr(response, 'headers', {}),
                "duration": 0,
                "is_binary": False,
                "content_type": ""
            }

    async def _process_with_semaphore(self, semaphore, url, depth, visited_urls):
        """
        Process a URL with semaphore-based concurrency control.
        
        Args:
            semaphore: The asyncio.Semaphore to use for concurrency control
            url: The URL to process
            depth: The current crawl depth
            visited_urls: Set of already visited URLs
            
        Raises:
            ValueError: If semaphore is None
        """
        try:
            # Skip already visited URLs early
            if url in visited_urls:
                return
                
            # Require a valid semaphore - don't create a fallback one
            if semaphore is None:
                error_msg = f"No semaphore provided for {url} - semaphore is required"
                if HAS_STRUCTLOG:
                    struct_logger.error("missing_semaphore", url=url)
                else:
                    self.logger.error(error_msg)
                raise ValueError(error_msg)
            
            # Get hostname for rate limiter
            hostname = urlparse(url).netloc
            
            # Always use semaphore for concurrency control
            try:
                async with semaphore:
                    if HAS_STRUCTLOG:
                        struct_logger.debug("acquired_semaphore", url=url)
                    else:
                        self.logger.debug(f"Acquired semaphore for processing {url}")
                        
                    if url not in visited_urls:  # Double-check in case status changed during await
                        try:
                            await self.process_url(url, depth)
                            # Mark as visited - handle both set and list types
                            if isinstance(visited_urls, set):
                                visited_urls.add(url)
                            else:
                                visited_urls.append(url)
                                
                            if should_log('process_url'):
                                if HAS_STRUCTLOG:
                                    struct_logger.debug("processed_url", url=url, depth=depth)
                                else:
                                    self.logger.debug(f"Successfully processed URL with semaphore: {url}")
                        except Exception as process_err:
                            error_trace = traceback.format_exc()
                            if HAS_STRUCTLOG:
                                struct_logger.error("url_processing_error", 
                                                 url=url, 
                                                 error=str(process_err),
                                                 traceback=error_trace)
                            else:
                                self.logger.error(f"Error processing URL {url} within semaphore: {str(process_err)}")
                                self.logger.debug(f"Traceback for URL {url}:\n{error_trace}")
            except (TypeError, AttributeError) as sem_err:
                error_trace = traceback.format_exc()
                if HAS_STRUCTLOG:
                    struct_logger.error("semaphore_error", 
                                     url=url, 
                                     error=str(sem_err),
                                     traceback=error_trace)
                else:
                    self.logger.error(f"Semaphore error for {url}: {str(sem_err)}")
                    
                # Use dynamic backoff based on rate limiter's state instead of fixed delay
                rate_limit = self.rate_limiter.get_domain_rate_limit(hostname)
                if rate_limit > 0:
                    backoff_time = 1.0 / rate_limit  # Calculate backoff based on rate limit
                else:
                    backoff_time = 5.0  # Default if rate limit is zero
                    
                if HAS_STRUCTLOG:
                    struct_logger.warning("dynamic_backoff", 
                                       url=url, 
                                       backoff_time=backoff_time, 
                                       rate_limit=rate_limit)
                else:
                    self.logger.warning(f"Using dynamic backoff for {url}: {backoff_time:.2f}s (rate: {rate_limit:.2f} req/s)")
                
                # Don't try to process without semaphore - just back off and report failure
                self.rate_limiter.report_failure(hostname)
            
        except ValueError as ve:
            # Pass through the semaphore validation error
            raise
        except Exception as e:
            error_trace = traceback.format_exc()
            if HAS_STRUCTLOG:
                struct_logger.error("process_with_semaphore_error", 
                                 url=url, 
                                 error=str(e),
                                 traceback=error_trace)
            else:
                self.logger.error(f"Unexpected error in _process_with_semaphore for {url}: {str(e)}")
                self.logger.debug(f"Traceback for unexpected error with {url}:\n{error_trace}")

    async def _load_robots_txt(self, base_url):
        """
        Load and parse robots.txt file for the given base URL.
        
        Args:
            base_url: The base URL to load robots.txt from
        """
        robots_url = urljoin(base_url, '/robots.txt')
        try:
            response = await self._make_rate_limited_request(
                url=robots_url,
                method="GET",
                retries=1,
                silent_errors=True
            )
            
            if response and response.get('status', 0) == 200:
                robots_content = response.get('text', '')
                parser = RobotsTxtParser(robots_content, self.user_agent or '*')
                self.robots_parsers[base_url] = parser
                self.logger.debug(f"Loaded robots.txt from {robots_url}")
            else:
                # No robots.txt or error loading it
                self.logger.debug(f"No robots.txt found at {robots_url}")
                # Create an empty parser that allows everything
                self.robots_parsers[base_url] = RobotsTxtParser("", self.user_agent or '*')
        except Exception as e:
            self.logger.error(f"Error loading robots.txt from {robots_url}: {str(e)}")
            # Create an empty parser in case of error
            self.robots_parsers[base_url] = RobotsTxtParser("", self.user_agent or '*')

    async def _queue_common_dirs(self, url, queue, url_fingerprints, discovered_urls):
        """
        Queue common directories and paths for the site to check.
        
        Args:
            url: The base URL
            queue: The priority queue to add URLs to
            url_fingerprints: Set of URL fingerprints for deduplication
            discovered_urls: Set of discovered URLs
        """
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        # Common paths that often exist on websites
        common_paths = [
            '/about', '/contact', '/faq', '/help', '/support',
            '/login', '/register', '/signup', '/account', '/profile',
            '/admin', '/dashboard', '/settings', '/privacy', '/terms',
            '/api', '/sitemap.xml', '/feeds', '/rss', '/atom.xml',
            '/blog', '/news', '/articles', '/events', '/products', '/services',
            '/search', '/download', '/uploads', '/media', '/assets', '/static'
        ]
        
        # Queue each common path with medium priority
        for path in common_paths:
            common_url = urljoin(base, path)
            url_fp = generate_url_fingerprint(common_url)
            
            if url_fp not in url_fingerprints:
                url_fingerprints.add(url_fp)
                discovered_urls.add(common_url)
                self.logger.debug(f"Queued common path: {common_url}")
                queue.add_url(common_url, 1, priority=40)  # Medium priority

    async def check_robots_txt(self, base_url, url):
        """
        Check if a URL is allowed by robots.txt rules.
        
        Args:
            base_url: The base URL (domain)
            url: The URL to check
            
        Returns:
            bool: True if URL is allowed, False otherwise
        """
        try:
            if not self.respect_robots_txt:
                return True
                
            if base_url not in self.robots_parsers:
                await self._load_robots_txt(base_url)
                
            parser = self.robots_parsers.get(base_url)
            if parser:
                return parser.can_fetch(url)
            
            # Default to allowing if no parser is available
            return True
        except Exception as e:
            self.logger.warning(f"Error checking robots.txt rules for {url}: {str(e)}")
            # Default to allowing if there's an error
            return True
    
    async def process_url(self, url, depth):
        """
        Process a single URL by crawling it and extracting information.
        
        Args:
            url: The URL to process
            depth: The current crawl depth
            
        Returns:
            Dict: Response data and extracted information
        """
        try:
            self.logger.debug(f"Processing URL: {url} at depth {depth}")
            
            # Skip if we've reached the maximum crawl depth
            if depth > self.max_crawl_depth:
                self.logger.debug(f"Skipping {url} - exceeds max depth {self.max_crawl_depth}")
                return None
                
            # Get page content
            response = await self._make_rate_limited_request(url)
            if not response:
                self.logger.debug(f"No response from {url}")
                return None
                
            # Extract hostname/domain for use in processing
            parsed_url = urlparse(url)
            hostname = parsed_url.netloc
            domain = hostname
            if domain.startswith('www.'):
                domain = domain[4:]
                
            # Base URL for resolving relative URLs
            base_url = f"{parsed_url.scheme}://{hostname}"
            
            # Record stats
            self.stats['pages_crawled'] += 1
            
            if response['status'] >= 200 and response['status'] < 300:
                self.stats['successful_requests'] += 1
                
                # Determine content type and process accordingly
                content_type = response.get('headers', {}).get('content-type', '').lower()
                
                try:
                    if 'text/html' in content_type or 'application/xhtml+xml' in content_type:
                        # Process HTML
                        await self._process_html_response(
                            response, url, depth, domain, base_url,
                            self.discovered_urls, self.url_fingerprints, 
                            self.urls_to_crawl, self.framework_info, self.crawled_urls
                        )
                    elif 'application/json' in content_type:
                        # Process JSON
                        await self._process_json_response(
                            response, url, depth, domain,
                            self.discovered_urls, self.url_fingerprints, self.urls_to_crawl
                        )
                    elif 'javascript' in content_type or 'application/x-javascript' in content_type:
                        # Process JavaScript
                        await self._process_javascript_response(
                            response, url, depth, domain, base_url,
                            self.discovered_urls, self.url_fingerprints, self.urls_to_crawl
                        )
                    elif 'text/xml' in content_type or 'application/xml' in content_type:
                        # Process XML
                        await self._process_xml_response(
                            response, url, depth, domain, base_url,
                            self.discovered_urls, self.url_fingerprints, self.urls_to_crawl
                        )
                    elif 'text/css' in content_type:
                        # Process CSS
                        self._process_css_for_urls(
                            response, url, depth, domain, base_url,
                            self.discovered_urls, self.url_fingerprints, self.urls_to_crawl
                        )
                    else:
                        # Other content types - just log
                        self.logger.debug(f"Skipping unsupported content type: {content_type} for {url}")
                except Exception as process_err:
                    self.logger.error(f"Error processing content from {url}: {str(process_err)}")
                    import traceback
                    self.logger.debug(f"Traceback for content processing error:\n{traceback.format_exc()}")
            else:
                self.stats['failed_requests'] += 1
                self.logger.debug(f"Request failed for {url}: HTTP {response['status']}")
                
            return response
        except Exception as e:
            self.logger.error(f"Error processing URL {url}: {str(e)}")
            import traceback
            self.logger.debug(f"Traceback for URL processing error:\n{traceback.format_exc()}")
            self.stats['request_errors'] += 1
            return None
    
    def filter_frameworks(self):
        """
        Filter out URLs that are likely framework-related.
        
        Returns:
            Set[str]: Filtered set of URLs
        """
        try:
            pre_filter_count = len(self.all_urls)
            self.all_urls = set(filter_framework_urls(self.all_urls, self.framework_info))
            self.logger.info(f"After framework filtering: {len(self.all_urls)} URLs (removed {pre_filter_count - len(self.all_urls)} framework URLs)")
            return self.all_urls
        except Exception as e:
            self.logger.error(f"Error in filter_frameworks: {str(e)}")
            # Return the original set if filtering fails
            return self.all_urls

