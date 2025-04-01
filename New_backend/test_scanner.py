import asyncio
import json
import sys
from datetime import datetime
from app.services.basic_scanner import BasicScanner
from app.services.enhanced_xss_scanner import EnhancedXSSScanner
from app.services.enhanced_sql_scanner import EnhancedSQLScanner
from app.services.enhanced_http_scanner import EnhancedHTTPScanner
from app.services.enhanced_file_upload_scanner import EnhancedFileUploadScanner

async def test_scanners(url):
    print(f"Testing scanners on URL: {url}")
    
    # Test Basic Scanner (HTTP Headers and Port Scanning)
    print("\n=== Testing Basic Scanner ===")
    basic_scanner = BasicScanner()
    basic_results = await basic_scanner.scan_url(url)
    print(f"Found {len(basic_results)} basic vulnerabilities")
    if basic_results:
        print(json.dumps(basic_results[0], indent=2))
    
    # Test Enhanced XSS Scanner
    print("\n=== Testing Enhanced XSS Scanner ===")
    xss_scanner = EnhancedXSSScanner()
    xss_results = await xss_scanner.scan_url(url)
    print(f"Found {len(xss_results)} XSS vulnerabilities")
    if xss_results:
        print(json.dumps(xss_results[0], indent=2))
    
    # Test Enhanced SQL Injection Scanner
    print("\n=== Testing Enhanced SQL Injection Scanner ===")
    sqli_scanner = EnhancedSQLScanner()
    sqli_results = await sqli_scanner.scan_url(url)
    print(f"Found {len(sqli_results)} SQL Injection vulnerabilities")
    if sqli_results:
        print(json.dumps(sqli_results[0], indent=2))
    
    # Test Enhanced HTTP Methods Scanner
    print("\n=== Testing Enhanced HTTP Methods Scanner ===")
    http_scanner = EnhancedHTTPScanner()
    http_results = await http_scanner.scan_url(url)
    print(f"Found {len(http_results)} HTTP Method vulnerabilities")
    if http_results:
        print(json.dumps(http_results[0], indent=2))
    
    # Test Enhanced File Upload Scanner
    print("\n=== Testing Enhanced File Upload Scanner ===")
    file_scanner = EnhancedFileUploadScanner()
    file_results = await file_scanner.scan_url(url)
    print(f"Found {len(file_results)} File Upload vulnerabilities")
    if file_results:
        print(json.dumps(file_results[0], indent=2))
    
    # Return all results combined
    return {
        "Basic": len(basic_results),
        "XSS": len(xss_results),
        "SQL_Injection": len(sqli_results),
        "HTTP_Methods": len(http_results),
        "File_Upload": len(file_results)
    }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_scanner.py <URL> [output_file]")
        print("Example: python test_scanner.py https://example.com results.json")
        sys.exit(1)
    
    url = sys.argv[1]
    results = asyncio.run(test_scanners(url))
    
    print("\n=== Summary ===")
    print(json.dumps(results, indent=2))
    
    # Export results to file if specified
    if len(sys.argv) > 2:
        output_file = sys.argv[2]
        try:
            # Create a more structured result object
            full_results = {
                "scan_id": f"scan-{asyncio.current_task().get_name()}",
                "url": url,
                "timestamp": datetime.now().isoformat(),
                "summary": results
            }
            
            with open(output_file, 'w') as f:
                json.dump(full_results, f, indent=2)
            print(f"Results exported to {output_file}")
        except Exception as e:
            print(f"Error exporting results: {e}") 