import asyncio
import uuid
import socket
import requests
import re
from typing import List, Dict, Any
from urllib.parse import urlparse

# SSL warnings are noisy for security testing
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Common ports to scan and their default services
COMMON_PORTS = {
    21: {'service': 'FTP', 'severity': 'medium', 'description': 'File Transfer Protocol'},
    22: {'service': 'SSH', 'severity': 'low', 'description': 'Secure Shell'},
    23: {'service': 'Telnet', 'severity': 'high', 'description': 'Telnet (unencrypted)'},
    25: {'service': 'SMTP', 'severity': 'medium', 'description': 'Simple Mail Transfer Protocol'},
    53: {'service': 'DNS', 'severity': 'low', 'description': 'Domain Name System'},
    80: {'service': 'HTTP', 'severity': 'low', 'description': 'Hypertext Transfer Protocol'},
    110: {'service': 'POP3', 'severity': 'medium', 'description': 'Post Office Protocol v3'},
    111: {'service': 'RPC', 'severity': 'medium', 'description': 'Remote Procedure Call'},
    135: {'service': 'RPC', 'severity': 'high', 'description': 'Windows RPC Endpoint Mapper'},
    139: {'service': 'NetBIOS', 'severity': 'high', 'description': 'NetBIOS Session Service'},
    143: {'service': 'IMAP', 'severity': 'medium', 'description': 'Internet Message Access Protocol'},
    161: {'service': 'SNMP', 'severity': 'high', 'description': 'Simple Network Management Protocol'},
    389: {'service': 'LDAP', 'severity': 'medium', 'description': 'Lightweight Directory Access Protocol'},
    443: {'service': 'HTTPS', 'severity': 'low', 'description': 'HTTP Secure'},
    445: {'service': 'SMB', 'severity': 'high', 'description': 'Server Message Block'},
    465: {'service': 'SMTPS', 'severity': 'low', 'description': 'SMTP over SSL'},
    587: {'service': 'SMTP', 'severity': 'medium', 'description': 'SMTP Submission'},
    593: {'service': 'RPC', 'severity': 'high', 'description': 'HTTP RPC Endpoint Mapper'},
    631: {'service': 'IPP', 'severity': 'low', 'description': 'Internet Printing Protocol'},
    636: {'service': 'LDAPS', 'severity': 'low', 'description': 'LDAP over SSL'},
    993: {'service': 'IMAPS', 'severity': 'low', 'description': 'IMAP over SSL'},
    995: {'service': 'POP3S', 'severity': 'low', 'description': 'POP3 over SSL'},
    1433: {'service': 'MSSQL', 'severity': 'high', 'description': 'Microsoft SQL Server'},
    1521: {'service': 'Oracle', 'severity': 'high', 'description': 'Oracle Database'},
    1723: {'service': 'PPTP', 'severity': 'medium', 'description': 'Point-to-Point Tunneling Protocol'},
    3306: {'service': 'MySQL', 'severity': 'high', 'description': 'MySQL Database'},
    3389: {'service': 'RDP', 'severity': 'high', 'description': 'Remote Desktop Protocol'},
    5432: {'service': 'PostgreSQL', 'severity': 'high', 'description': 'PostgreSQL Database'},
    5900: {'service': 'VNC', 'severity': 'high', 'description': 'Virtual Network Computing'},
    5985: {'service': 'WinRM', 'severity': 'high', 'description': 'Windows Remote Management HTTP'},
    5986: {'service': 'WinRM', 'severity': 'high', 'description': 'Windows Remote Management HTTPS'},
    6379: {'service': 'Redis', 'severity': 'high', 'description': 'Redis Database'},
    8080: {'service': 'HTTP-Alt', 'severity': 'medium', 'description': 'Alternative HTTP Port'},
    8443: {'service': 'HTTPS-Alt', 'severity': 'medium', 'description': 'Alternative HTTPS Port'},
    9200: {'service': 'Elasticsearch', 'severity': 'high', 'description': 'Elasticsearch'},
    27017: {'service': 'MongoDB', 'severity': 'high', 'description': 'MongoDB Database'}
}

class BasicScanner:
    """
    Basic scanner that checks for common security issues like HTTP headers and open ports.
    """
    
    async def scan_url(self, url: str) -> List[Dict[str, Any]]:
        """
        Scan a URL for basic security vulnerabilities.
        
        Args:
            url: The URL to scan
            
        Returns:
            List[Dict[str, Any]]: List of vulnerabilities found
        """
        print(f"Starting basic security scan for URL: {url}")
        
        vulnerabilities = []
        
        # Analyze HTTP headers
        header_vulns = await self._analyze_http_headers(url)
        vulnerabilities.extend(header_vulns)
        
        # Parse the URL to get the hostname
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        if ':' in hostname:
            hostname = hostname.split(':')[0]
        
        # Scan common ports
        port_vulns = await self._scan_ports(hostname)
        vulnerabilities.extend(port_vulns)
        
        return vulnerabilities
    
    async def _analyze_http_headers(self, url: str) -> List[Dict[str, Any]]:
        """
        Analyze HTTP headers for security issues.
        
        Args:
            url: The URL to analyze
            
        Returns:
            List[Dict[str, Any]]: List of vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            # Make a request to the URL
            response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            headers = response.headers
            
            # Check for missing security headers
            security_headers = {
                'Strict-Transport-Security': {
                    'name': 'Missing HSTS Header',
                    'description': 'HTTP Strict Transport Security header is missing, which helps protect against protocol downgrade attacks',
                    'severity': 'medium',
                    'remediation': 'Add the Strict-Transport-Security header with a max-age of at least 31536000 (1 year) and includeSubDomains directive'
                },
                'Content-Security-Policy': {
                    'name': 'Missing Content Security Policy',
                    'description': 'Content Security Policy header is missing, which helps mitigate XSS and other code injection attacks',
                    'severity': 'medium',
                    'remediation': 'Implement a Content Security Policy with appropriate directives for your site'
                },
                'X-Frame-Options': {
                    'name': 'Missing X-Frame-Options Header',
                    'description': 'X-Frame-Options header is missing, which can lead to clickjacking attacks',
                    'severity': 'medium',
                    'remediation': 'Add the X-Frame-Options header with DENY or SAMEORIGIN value'
                },
                'X-Content-Type-Options': {
                    'name': 'Missing X-Content-Type-Options Header',
                    'description': 'X-Content-Type-Options header is missing, which can lead to MIME sniffing attacks',
                    'severity': 'low',
                    'remediation': 'Add the X-Content-Type-Options header with nosniff value'
                },
                'X-XSS-Protection': {
                    'name': 'Missing X-XSS-Protection Header',
                    'description': 'X-XSS-Protection header is missing, which can help prevent XSS attacks in older browsers',
                    'severity': 'low',
                    'remediation': 'Add the X-XSS-Protection header with 1; mode=block value'
                },
                'Referrer-Policy': {
                    'name': 'Missing Referrer-Policy Header',
                    'description': 'Referrer-Policy header is missing, which controls how much referrer information is included with requests',
                    'severity': 'low',
                    'remediation': 'Add the Referrer-Policy header with appropriate value like no-referrer or same-origin'
                },
                'Permissions-Policy': {
                    'name': 'Missing Permissions-Policy Header',
                    'description': 'Permissions-Policy header is missing, which controls which browser features can be used',
                    'severity': 'low',
                    'remediation': 'Add the Permissions-Policy header to restrict access to sensitive browser features'
                },
                'Clear-Site-Data': {
                    'name': 'Missing Clear-Site-Data Header on Logout',
                    'description': 'Clear-Site-Data header can be used to clear browsing data associated with a site during logout',
                    'severity': 'info',
                    'remediation': 'Consider adding Clear-Site-Data header to logout responses'
                }
            }
            
            for header, info in security_headers.items():
                if header not in headers:
                    vulnerabilities.append({
                        "id": str(uuid.uuid4()),
                        "name": info['name'],
                        "description": info['description'],
                        "severity": info['severity'],
                        "location": url,
                        "evidence": f"Header {header} not found in response",
                        "remediation": info['remediation']
                    })
            
            # Check HSTS max-age if present
            if 'Strict-Transport-Security' in headers:
                hsts_header = headers['Strict-Transport-Security']
                if 'max-age=' in hsts_header:
                    max_age_match = re.search(r'max-age=(\d+)', hsts_header)
                    if max_age_match:
                        max_age = int(max_age_match.group(1))
                        if max_age < 31536000:  # Less than 1 year
                            vulnerabilities.append({
                                "id": str(uuid.uuid4()),
                                "name": 'HSTS Max-Age Too Short',
                                "description": f'HSTS max-age is set to {max_age} seconds, which is less than the recommended 1 year (31536000 seconds)',
                                "severity": 'low',
                                "location": url,
                                "evidence": f"Strict-Transport-Security: {hsts_header}",
                                "remediation": 'Increase the HSTS max-age to at least 31536000 (1 year)'
                            })
                if 'includeSubDomains' not in hsts_header:
                    vulnerabilities.append({
                        "id": str(uuid.uuid4()),
                        "name": 'HSTS Missing includeSubDomains',
                        "description": 'HSTS header is missing the includeSubDomains directive, which extends protection to subdomains',
                        "severity": 'low',
                        "location": url,
                        "evidence": f"Strict-Transport-Security: {hsts_header}",
                        "remediation": 'Add the includeSubDomains directive to the HSTS header'
                    })
            
            # Check CSP for unsafe directives if present
            if 'Content-Security-Policy' in headers:
                csp_header = headers['Content-Security-Policy']
                if "unsafe-inline" in csp_header:
                    vulnerabilities.append({
                        "id": str(uuid.uuid4()),
                        "name": 'CSP Contains unsafe-inline',
                        "description": 'Content Security Policy contains unsafe-inline directive, which reduces protection against XSS attacks',
                        "severity": 'medium',
                        "location": url,
                        "evidence": f"Content-Security-Policy: {csp_header}",
                        "remediation": 'Remove unsafe-inline from CSP and use nonces or hashes instead'
                    })
                if "unsafe-eval" in csp_header:
                    vulnerabilities.append({
                        "id": str(uuid.uuid4()),
                        "name": 'CSP Contains unsafe-eval',
                        "description": 'Content Security Policy contains unsafe-eval directive, which reduces protection against XSS attacks',
                        "severity": 'medium',
                        "location": url,
                        "evidence": f"Content-Security-Policy: {csp_header}",
                        "remediation": 'Remove unsafe-eval from CSP and refactor code to avoid eval()'
                    })
            
            # Check for server information disclosure
            if 'Server' in headers:
                server = headers['Server']
                vulnerabilities.append({
                    "id": str(uuid.uuid4()),
                    "name": 'Server Information Disclosure',
                    "description": f'Server header reveals information about the server software: {server}',
                    "severity": 'low',
                    "location": url,
                    "evidence": f"Server: {server}",
                    "remediation": 'Configure the server to hide version information'
                })
            
            # Check for X-Powered-By header
            if 'X-Powered-By' in headers:
                x_powered_by = headers['X-Powered-By']
                vulnerabilities.append({
                    "id": str(uuid.uuid4()),
                    "name": 'X-Powered-By Information Disclosure',
                    "description": f'X-Powered-By header reveals information about the server technology: {x_powered_by}',
                    "severity": 'low',
                    "location": url,
                    "evidence": f"X-Powered-By: {x_powered_by}",
                    "remediation": 'Remove the X-Powered-By header'
                })
            
            # Check for cookies without secure flag
            if 'Set-Cookie' in headers:
                cookies = headers.getlist('Set-Cookie') if hasattr(headers, 'getlist') else [headers['Set-Cookie']]
                for cookie in cookies:
                    if 'secure' not in cookie.lower():
                        vulnerabilities.append({
                            "id": str(uuid.uuid4()),
                            "name": 'Insecure Cookie',
                            "description": 'Cookie set without Secure flag, which means it can be transmitted over unencrypted connections',
                            "severity": 'medium',
                            "location": url,
                            "evidence": f"Cookie: {cookie}",
                            "remediation": 'Set the Secure flag on all cookies'
                        })
                    if 'httponly' not in cookie.lower():
                        vulnerabilities.append({
                            "id": str(uuid.uuid4()),
                            "name": 'Cookie Without HttpOnly Flag',
                            "description": 'Cookie set without HttpOnly flag, which makes it accessible to JavaScript',
                            "severity": 'medium',
                            "location": url,
                            "evidence": f"Cookie: {cookie}",
                            "remediation": 'Set the HttpOnly flag on all cookies'
                        })
                    if 'samesite' not in cookie.lower():
                        vulnerabilities.append({
                            "id": str(uuid.uuid4()),
                            "name": 'Cookie Without SameSite Attribute',
                            "description": 'Cookie set without SameSite attribute, which can make it vulnerable to CSRF attacks',
                            "severity": 'medium',
                            "location": url,
                            "evidence": f"Cookie: {cookie}",
                            "remediation": 'Set the SameSite attribute (Lax or Strict) on all cookies'
                        })
            
            # Check for insecure HTTP
            if url.startswith('http://'):
                vulnerabilities.append({
                    "id": str(uuid.uuid4()),
                    "name": 'Insecure HTTP',
                    "description": 'The website is using HTTP instead of HTTPS, which means data is transmitted in plaintext',
                    "severity": 'high',
                    "location": url,
                    "evidence": "URL uses HTTP protocol",
                    "remediation": 'Configure the server to use HTTPS and redirect HTTP to HTTPS'
                })
                
                # Also check if HTTPS is available but not forced
                https_url = url.replace('http://', 'https://')
                try:
                    https_response = requests.get(https_url, timeout=5, verify=False)
                    if https_response.status_code == 200:
                        vulnerabilities.append({
                            "id": str(uuid.uuid4()),
                            "name": 'HTTPS Not Enforced',
                            "description": 'HTTPS is available but not enforced, allowing users to access the site over insecure HTTP',
                            "severity": 'medium',
                            "location": url,
                            "evidence": f"HTTPS is available at {https_url} but not forced",
                            "remediation": 'Implement HTTP to HTTPS redirection'
                        })
                except Exception:
                    pass  # HTTPS not available
            
            # Check for CORS misconfiguration
            if 'Access-Control-Allow-Origin' in headers:
                cors_origin = headers['Access-Control-Allow-Origin']
                if cors_origin == '*':
                    vulnerabilities.append({
                        "id": str(uuid.uuid4()),
                        "name": 'CORS Misconfiguration',
                        "description": 'Access-Control-Allow-Origin header is set to *, allowing any domain to access resources',
                        "severity": 'medium',
                        "location": url,
                        "evidence": "Access-Control-Allow-Origin: *",
                        "remediation": 'Restrict CORS access to specific trusted domains'
                    })
                
                if 'Access-Control-Allow-Credentials' in headers and headers['Access-Control-Allow-Credentials'].lower() == 'true':
                    if cors_origin == '*' or ',' in cors_origin:
                        vulnerabilities.append({
                            "id": str(uuid.uuid4()),
                            "name": 'Insecure CORS Configuration',
                            "description": 'Access-Control-Allow-Credentials is true with a wildcard or multiple origin, which is a security risk',
                            "severity": 'high',
                            "location": url,
                            "evidence": f"Access-Control-Allow-Origin: {cors_origin}, Access-Control-Allow-Credentials: true",
                            "remediation": 'When using Access-Control-Allow-Credentials: true, Access-Control-Allow-Origin must be set to a specific domain, not a wildcard'
                        })
            
            # Check for cache control headers for sensitive pages
            sensitive_paths = ['/login', '/admin', '/account', '/profile', '/settings', '/dashboard']
            parsed_url = urlparse(url)
            if any(path in parsed_url.path for path in sensitive_paths):
                if 'Cache-Control' not in headers or 'no-store' not in headers.get('Cache-Control', '').lower():
                    vulnerabilities.append({
                        "id": str(uuid.uuid4()),
                        "name": 'Missing Cache Control for Sensitive Page',
                        "description": 'Cache-Control header with no-store directive is missing on a sensitive page',
                        "severity": 'medium',
                        "location": url,
                        "evidence": f"Cache-Control header missing or missing no-store directive: {headers.get('Cache-Control', 'Not set')}",
                        "remediation": 'Add Cache-Control: no-store, no-cache, must-revalidate, private to sensitive pages'
                    })
        
        except Exception as e:
            print(f"Error analyzing HTTP headers: {str(e)}")
            # Add a vulnerability for connection issues
            vulnerabilities.append({
                "id": str(uuid.uuid4()),
                "name": 'Connection Issue',
                "description": f'Could not connect to the URL: {str(e)}',
                "severity": 'info',
                "location": url,
                "evidence": str(e),
                "remediation": 'Ensure the URL is accessible'
            })
        
        return vulnerabilities
    
    async def _scan_ports(self, hostname: str) -> List[Dict[str, Any]]:
        """
        Scan common ports on the hostname with enhanced service detection.
        
        Args:
            hostname: The hostname to scan
            
        Returns:
            List[Dict[str, Any]]: List of vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            # Resolve hostname to IP
            try:
                ip = socket.gethostbyname(hostname)
                print(f"Resolved {hostname} to {ip}")
            except Exception as e:
                print(f"Could not resolve hostname {hostname}: {str(e)}")
                # If hostname resolution fails, use the hostname as is
                ip = hostname
            
            open_ports = []
            
            # Scan common ports with timeout for faster scanning
            for port, info in COMMON_PORTS.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)  # 1 second timeout
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    
                    if result == 0:
                        print(f"Port {port} ({info['service']}) is open")
                        open_ports.append(port)
                        
                        # Try to get more detailed service information
                        service_info = self._detect_service(ip, port, info['service'])
                        severity = info['severity']
                        
                        # Adjust severity based on some service-specific checks
                        if port == 22 and "openssh" in service_info.lower():
                            # OpenSSH is generally secure
                            severity = "low"
                        
                        # This is the generic check for all open ports
                        vulnerabilities.append({
                            "id": str(uuid.uuid4()),
                            "name": f'Open Port: {port} ({info["service"]})',
                            "description": f'Port {port} ({info["service"]} - {info["description"]}) is open on {hostname}',
                            "severity": severity,
                            "location": f"{hostname}:{port}",
                            "evidence": f"Port {port} is open" + (f", detected service: {service_info}" if service_info else ""),
                            "remediation": f'Close port {port} if not needed or restrict access with a firewall'
                        })
                        
                        # Add service-specific vulnerability checks
                        service_vulns = self._check_service_vulnerabilities(ip, port, info['service'], service_info)
                        vulnerabilities.extend(service_vulns)
                
                except Exception as e:
                    print(f"Error scanning port {port}: {str(e)}")
            
            # If we found a lot of open ports, report it as a vulnerability
            if len(open_ports) > 10:
                vulnerabilities.append({
                    "id": str(uuid.uuid4()),
                    "name": 'Excessive Open Ports',
                    "description": f'Host has {len(open_ports)} open ports, which increases the attack surface',
                    "severity": 'high',
                    "location": hostname,
                    "evidence": f"Open ports: {', '.join(map(str, open_ports))}",
                    "remediation": 'Close unnecessary ports and restrict access to required ports with a firewall'
                })
        
        except Exception as e:
            print(f"Error scanning ports: {str(e)}")
        
        return vulnerabilities
    
    def _detect_service(self, ip: str, port: int, default_service: str) -> str:
        """
        Try to detect the service running on a port.
        
        Args:
            ip: The IP address
            port: The port number
            default_service: The default service name for this port
            
        Returns:
            str: The detected service information
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            
            # Send a generic request that should trigger a banner response
            if port == 22:  # SSH
                # SSH will send a banner without any request
                data = sock.recv(1024)
            elif port in [80, 443, 8080, 8443]:  # HTTP/HTTPS
                # Send an HTTP request
                sock.sendall(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
                data = sock.recv(1024)
            elif port == 21:  # FTP
                # FTP server will send a banner without any request
                data = sock.recv(1024)
            elif port == 25 or port == 587 or port == 465:  # SMTP
                # SMTP server will send a banner without any request
                data = sock.recv(1024)
            elif port == 110 or port == 995:  # POP3
                # POP3 server will send a banner without any request
                data = sock.recv(1024)
            else:
                # For other ports, just try to receive data
                sock.sendall(b"\r\n")
                data = sock.recv(1024)
            
            sock.close()
            
            return data.decode('utf-8', errors='ignore').strip()
        except Exception as e:
            print(f"Error detecting service on port {port}: {str(e)}")
            return ""
    
    def _check_service_vulnerabilities(self, ip: str, port: int, service: str, service_info: str) -> List[Dict[str, Any]]:
        """
        Check for service-specific vulnerabilities.
        
        Args:
            ip: The IP address
            port: The port number
            service: The service name
            service_info: Detected service information
            
        Returns:
            List[Dict[str, Any]]: List of vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            # Check for common service-specific vulnerabilities
            if service == 'FTP' and ('anonymous' in service_info.lower() or 'ftp' in service_info.lower()):
                # Try anonymous FTP login
                try:
                    import ftplib
                    ftp = ftplib.FTP()
                    ftp.connect(ip, port, timeout=5)
                    ftp.login('anonymous', 'anonymous@example.com')
                    ftp.quit()
                    
                    vulnerabilities.append({
                        "id": str(uuid.uuid4()),
                        "name": 'Anonymous FTP Access',
                        "description": 'FTP server allows anonymous login, which could expose sensitive files',
                        "severity": 'high',
                        "location": f"{ip}:{port}",
                        "evidence": "Successfully logged in as anonymous",
                        "remediation": 'Disable anonymous FTP access if not required'
                    })
                except Exception:
                    pass
            
            elif service == 'SMTP':
                # Check for SMTP relay (Note: This is a passive check, we don't actually try to relay)
                if 'relay' in service_info.lower() and 'disabled' not in service_info.lower():
                    vulnerabilities.append({
                        "id": str(uuid.uuid4()),
                        "name": 'Potential SMTP Relay',
                        "description": 'SMTP server might allow relaying, which could be abused for spam',
                        "severity": 'high',
                        "location": f"{ip}:{port}",
                        "evidence": f"Service banner: {service_info}",
                        "remediation": 'Configure SMTP server to prevent unauthorized relaying'
                    })
            
            elif service in ['HTTP', 'HTTPS', 'HTTP-Alt', 'HTTPS-Alt']:
                # Check for HTTP server information disclosure
                if 'apache' in service_info.lower() or 'nginx' in service_info.lower() or 'iis' in service_info.lower():
                    vulnerabilities.append({
                        "id": str(uuid.uuid4()),
                        "name": 'Web Server Information Disclosure',
                        "description": 'Web server reveals its software version in HTTP headers',
                        "severity": 'low',
                        "location": f"{ip}:{port}",
                        "evidence": f"Server banner: {service_info}",
                        "remediation": 'Configure web server to hide version information'
                    })
            
            elif service == 'MySQL' or service == 'MSSQL' or service == 'PostgreSQL' or service == 'Oracle':
                # Database server is exposed to the internet
                vulnerabilities.append({
                    "id": str(uuid.uuid4()),
                    "name": f'Exposed Database Server ({service})',
                    "description": f'{service} database server is exposed to the internet, which is a security risk',
                    "severity": 'high',
                    "location": f"{ip}:{port}",
                    "evidence": f"Open {service} port",
                    "remediation": f'Restrict {service} access to trusted IP addresses or put it behind a VPN'
                })
            
            elif service == 'RDP':
                # RDP server is exposed to the internet
                vulnerabilities.append({
                    "id": str(uuid.uuid4()),
                    "name": 'Exposed RDP Server',
                    "description": 'Remote Desktop Protocol is exposed to the internet, which is a security risk',
                    "severity": 'high',
                    "location": f"{ip}:{port}",
                    "evidence": "Open RDP port",
                    "remediation": 'Restrict RDP access to trusted IP addresses or put it behind a VPN'
                })
            
            elif service == 'Telnet':
                # Telnet is unencrypted
                vulnerabilities.append({
                    "id": str(uuid.uuid4()),
                    "name": 'Telnet Service Enabled',
                    "description": 'Telnet is an unencrypted protocol that transmits credentials in plaintext',
                    "severity": 'high',
                    "location": f"{ip}:{port}",
                    "evidence": "Open Telnet port",
                    "remediation": 'Replace Telnet with SSH for secure remote access'
                })
        
        except Exception as e:
            print(f"Error checking service vulnerabilities for {service} on port {port}: {str(e)}")
        
        return vulnerabilities 