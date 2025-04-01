import uuid
import aiohttp
import asyncio
from typing import List, Dict, Any, Optional
import re

class EnhancedHTTPScanner:
    """
    Enhanced scanner for detecting HTTP method vulnerabilities and server information.
    """
    
    # HTTP methods to test
    http_methods = [
        "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", 
        "TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", 
        "COPY", "MOVE", "LOCK", "UNLOCK", "SEARCH"
    ]
    
    # Methods that are considered potentially dangerous if enabled
    dangerous_methods = [
        "PUT", "DELETE", "TRACE", "CONNECT", "PROPFIND", 
        "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", 
        "UNLOCK", "SEARCH"
    ]
    
    # Headers to check for information disclosure
    security_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Feature-Policy",
        "Permissions-Policy",
        "Public-Key-Pins",
        "Cache-Control",
        "Pragma"
    ]
    
    # Headers that might disclose sensitive information
    sensitive_headers = [
        "Server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-AspNetMvc-Version",
        "X-Runtime",
        "X-Version",
        "X-Generator",
        "X-Backend-Server",
        "X-Forwarded-For",
        "X-Real-IP",
        "Via"
    ]
    
    async def scan_url(self, url: str) -> List[Dict[str, Any]]:
        """
        Scan a URL for HTTP method vulnerabilities and server information.
        
        Args:
            url: The URL to scan
            
        Returns:
            List[Dict[str, Any]]: List of vulnerabilities found
        """
        print(f"Starting Enhanced HTTP Methods scan for URL: {url}")
        
        vulnerabilities = []
        
        # Create a semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(5)
        
        # Test each HTTP method
        method_tasks = []
        for method in self.http_methods:
            task = self._test_http_method(url, method, semaphore)
            method_tasks.append(task)
        
        # Run all method tests concurrently
        method_results = await asyncio.gather(*method_tasks, return_exceptions=True)
        
        # Filter out exceptions and None results
        for result in method_results:
            if isinstance(result, list):
                vulnerabilities.extend(result)
        
        # Check for security headers
        header_vulns = await self._check_security_headers(url, semaphore)
        vulnerabilities.extend(header_vulns)
        
        # Check for CORS misconfiguration
        cors_vulns = await self._check_cors_config(url, semaphore)
        vulnerabilities.extend(cors_vulns)
        
        return vulnerabilities
    
    async def _test_http_method(self, url: str, method: str, semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
        """
        Test an HTTP method on the URL.
        
        Args:
            url: The URL to test
            method: The HTTP method to test
            semaphore: Semaphore to limit concurrent requests
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            async with semaphore:
                async with aiohttp.ClientSession() as session:
                    try:
                        # Create a request with the specified method
                        custom_headers = {
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36",
                            "Accept": "*/*",
                            "Accept-Language": "en-US,en;q=0.9",
                            "Connection": "close"
                        }
                        
                        async with session.request(method, url, headers=custom_headers, timeout=10, allow_redirects=False) as response:
                            # Check if the method is dangerous and not properly rejected
                            if method in self.dangerous_methods:
                                if response.status not in [405, 501, 403, 401]:
                                    # The dangerous method is not properly rejected
                                    severity = "high" if method in ["PUT", "DELETE"] else "medium"
                                    
                                    vulnerabilities.append({
                                        "id": str(uuid.uuid4()),
                                        "name": f"Dangerous HTTP Method Allowed: {method}",
                                        "description": f"The server allows the potentially dangerous HTTP method: {method} without proper authorization",
                                        "severity": severity,
                                        "location": url,
                                        "evidence": f"HTTP {response.status} response for {method} request",
                                        "remediation": f"Disable the {method} HTTP method or implement proper authorization for it"
                                    })
                            
                            # Special check for TRACE method (XST vulnerability)
                            if method == "TRACE":
                                response_text = await response.text()
                                # Check if response contains our headers (indicates TRACE is reflecting request)
                                if "User-Agent" in response_text and "Mozilla" in response_text:
                                    vulnerabilities.append({
                                        "id": str(uuid.uuid4()),
                                        "name": "Cross-Site Tracing (XST) Vulnerability",
                                        "description": "The server reflects the TRACE request which can lead to credential theft via Cross-Site Tracing",
                                        "severity": "high",
                                        "location": url,
                                        "evidence": "TRACE method response contains the request headers",
                                        "remediation": "Disable the TRACE HTTP method on your web server"
                                    })
                            
                            # Check for information disclosure in headers
                            for header, value in response.headers.items():
                                if header.lower() in [h.lower() for h in self.sensitive_headers]:
                                    vulnerabilities.append({
                                        "id": str(uuid.uuid4()),
                                        "name": f"Information Disclosure: {header}",
                                        "description": f"The server discloses potentially sensitive information in the {header} header",
                                        "severity": "low",
                                        "location": url,
                                        "evidence": f"{header}: {value}",
                                        "remediation": f"Remove or obfuscate the {header} header"
                                    })
                    
                    except aiohttp.ClientError as e:
                        # If the method is not supported by the server, an error might be raised
                        pass
        
        except Exception as e:
            print(f"Error testing HTTP method {method}: {str(e)}")
        
        return vulnerabilities
    
    async def _check_security_headers(self, url: str, semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
        """
        Check for missing security headers.
        
        Args:
            url: The URL to check
            semaphore: Semaphore to limit concurrent requests
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            async with semaphore:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=10) as response:
                        # Check for missing security headers
                        present_headers = [h.lower() for h in response.headers.keys()]
                        
                        for header in self.security_headers:
                            if header.lower() not in present_headers:
                                # Determine severity based on the importance of the header
                                severity = "medium"
                                if header in ["Strict-Transport-Security", "Content-Security-Policy"]:
                                    severity = "medium"
                                elif header in ["X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection"]:
                                    severity = "medium"
                                else:
                                    severity = "low"
                                
                                vulnerabilities.append({
                                    "id": str(uuid.uuid4()),
                                    "name": f"Missing Security Header: {header}",
                                    "description": f"The HTTP response is missing the security header: {header}",
                                    "severity": severity,
                                    "location": url,
                                    "evidence": f"Header {header} not found in response",
                                    "remediation": f"Implement the {header} security header"
                                })
        
        except Exception as e:
            print(f"Error checking security headers: {str(e)}")
        
        return vulnerabilities
    
    async def _check_cors_config(self, url: str, semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
        """
        Check for CORS misconfiguration.
        
        Args:
            url: The URL to check
            semaphore: Semaphore to limit concurrent requests
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            async with semaphore:
                async with aiohttp.ClientSession() as session:
                    # Make a request with Origin header set to a different domain
                    headers = {
                        "Origin": "https://evil.example.com",
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36",
                    }
                    
                    async with session.options(url, headers=headers, timeout=10) as response:
                        # Check Access-Control-Allow-Origin header
                        allow_origin = response.headers.get("Access-Control-Allow-Origin", "")
                        
                        # Check if CORS is too permissive
                        if allow_origin == "*":
                            vulnerabilities.append({
                                "id": str(uuid.uuid4()),
                                "name": "CORS Misconfiguration: Wildcard Origin",
                                "description": "The server allows any origin to access its resources via CORS",
                                "severity": "medium",
                                "location": url,
                                "evidence": "Access-Control-Allow-Origin: *",
                                "remediation": "Restrict CORS to specific trusted domains instead of using a wildcard"
                            })
                        elif "evil.example.com" in allow_origin:
                            vulnerabilities.append({
                                "id": str(uuid.uuid4()),
                                "name": "CORS Misconfiguration: Origin Reflection",
                                "description": "The server reflects the Origin header value in Access-Control-Allow-Origin header",
                                "severity": "high",
                                "location": url,
                                "evidence": f"Access-Control-Allow-Origin: {allow_origin}",
                                "remediation": "Only allow specific trusted domains in the Access-Control-Allow-Origin header"
                            })
                        
                        # Check if credentials are allowed
                        allow_credentials = response.headers.get("Access-Control-Allow-Credentials", "")
                        if allow_credentials.lower() == "true" and allow_origin == "*":
                            vulnerabilities.append({
                                "id": str(uuid.uuid4()),
                                "name": "CORS Misconfiguration: Credentials with Wildcard",
                                "description": "The server allows credentials to be sent cross-origin with a wildcard origin",
                                "severity": "high",
                                "location": url,
                                "evidence": "Access-Control-Allow-Credentials: true with Access-Control-Allow-Origin: *",
                                "remediation": "When allowing credentials, specify exact origins instead of using a wildcard"
                            })
        
        except Exception as e:
            print(f"Error checking CORS configuration: {str(e)}")
        
        return vulnerabilities 