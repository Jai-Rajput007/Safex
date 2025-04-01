import asyncio
import json
import sys
from datetime import datetime
from app.services.enhanced_xss_scanner import EnhancedXSSScanner
from app.services.enhanced_sql_scanner import EnhancedSQLScanner
from app.services.enhanced_http_scanner import EnhancedHTTPScanner
from app.services.enhanced_file_upload_scanner import EnhancedFileUploadScanner
from app.services.basic_scanner import BasicScanner

class EnhancedTestRunner:
    def __init__(self, url: str):
        self.url = url
        self.results = {}
        self.vulnerabilities = {}
        self.start_time = None
        self.end_time = None
    
    async def run_tests(self):
        """Run all scanners and collect results."""
        self.start_time = datetime.now()
        
        # Run Basic Scanner
        print("[+] Running Basic Scanner (Security Headers, Port Scanning)...")
        basic_vulnerabilities = await self.test_basic_scanner()
        self.vulnerabilities["Basic"] = basic_vulnerabilities
        print(f"  ✓ Found {len(basic_vulnerabilities)} basic vulnerabilities")
        if basic_vulnerabilities:
            for i, vuln in enumerate(basic_vulnerabilities[:3], 1):
                print(f"    {i}. {vuln['name']} ({vuln['severity']})")
        
        # Run XSS Scanner
        print("[+] Running XSS Scanner...")
        xss_vulnerabilities = await self.test_xss_scanner()
        self.vulnerabilities["XSS"] = xss_vulnerabilities
        
        # Run SQL Injection Scanner
        print("[+] Running Enhanced SQL Injection Scanner...")
        sql_vulnerabilities = await self.test_sql_injection_scanner()
        self.vulnerabilities["SQL_Injection"] = sql_vulnerabilities
        
        # Run HTTP Methods Scanner
        print("[+] Running Enhanced HTTP Methods Scanner...")
        http_vulnerabilities = await self.test_http_methods_scanner()
        self.vulnerabilities["HTTP_Methods"] = http_vulnerabilities
        
        # Run File Upload Scanner
        print("[+] Running Enhanced File Upload Scanner...")
        file_upload_vulnerabilities = await self.test_file_upload_scanner()
        self.vulnerabilities["File_Upload"] = file_upload_vulnerabilities
        
        # Extract and count potential upload paths
        upload_paths_count = 0
        verified_paths_count = 0
        upload_paths = []
        verified_paths = []
        directory_listings = 0
        
        for vuln in file_upload_vulnerabilities:
            if vuln["name"] == "Potential File Upload Paths Detected":
                # Get counts from description and evidence
                desc_parts = vuln["description"].split(" ")
                if len(desc_parts) > 1 and desc_parts[1].isdigit():
                    upload_paths_count = int(desc_parts[1])
                
                # Get verified count from evidence
                evidence_parts = vuln["evidence"].split(" ")
                if "verified" in vuln["evidence"]:
                    for i, part in enumerate(evidence_parts):
                        if part == "verified," and i > 0 and evidence_parts[i-1].isdigit():
                            verified_paths_count = int(evidence_parts[i-1])
                
                # Get directory listing count
                if "directory listing" in vuln["evidence"]:
                    for i, part in enumerate(evidence_parts):
                        if part == "listing)" and i > 0 and evidence_parts[i-1].isdigit():
                            directory_listings = int(evidence_parts[i-1])
                
                # Get path examples
                if "upload_paths" in vuln:
                    upload_paths = vuln["upload_paths"]
                if "verified_paths" in vuln:
                    verified_paths = vuln["verified_paths"]
                break
            elif vuln["name"] == "Directory Listing Enabled on Upload Paths":
                directory_listings = int(vuln["description"].split(" ")[1])
        
        # Print results
        print(f"  ✓ Found {len(file_upload_vulnerabilities)} File Upload vulnerabilities")
        if upload_paths_count > 0:
            verified_str = f" ({verified_paths_count} verified)" if verified_paths_count > 0 else ""
            dir_listing_str = f", {directory_listings} with directory listing" if directory_listings > 0 else ""
            print(f"  ✓ Detected {upload_paths_count} potential upload paths{verified_str}{dir_listing_str}")
            
            # Show verified paths first if available, otherwise show regular paths
            display_paths = verified_paths if verified_paths else upload_paths
            if display_paths:
                print("    Example paths:")
                for i, path in enumerate(display_paths[:5], 1):
                    path_type = "Verified" if path in verified_paths else "Potential"
                    print(f"    {i}. {path_type}: {path}")
        
        print(f"  ✓ Found {len(xss_vulnerabilities)} XSS vulnerabilities")
        if xss_vulnerabilities:
            for i, vuln in enumerate(xss_vulnerabilities[:3], 1):
                print(f"    {i}. {vuln['name']} ({vuln['severity']}) - {vuln['location']}")
        
        print(f"  ✓ Found {len(sql_vulnerabilities)} SQL Injection vulnerabilities")
        if sql_vulnerabilities:
            for i, vuln in enumerate(sql_vulnerabilities[:3], 1):
                print(f"    {i}. {vuln['name']} ({vuln['severity']}) - {vuln['location']}")
        
        print(f"  ✓ Found {len(http_vulnerabilities)} HTTP Methods vulnerabilities")
        if http_vulnerabilities:
            for i, vuln in enumerate(http_vulnerabilities[:3], 1):
                print(f"    {i}. {vuln['name']} ({vuln['severity']}) - {vuln['location']}")
        
        self.end_time = datetime.now()
        
        # Format results
        self.results = {
            "scan_id": "enhanced-scan-" + datetime.now().strftime("%Y%m%d%H%M%S"),
            "url": self.url,
            "timestamp": datetime.now().isoformat(),
            "scan_duration": (self.end_time - self.start_time).total_seconds(),
            "vulnerabilities": self.vulnerabilities,
            "summary": {
                "Basic": len(basic_vulnerabilities),
                "XSS": len(xss_vulnerabilities),
                "SQL_Injection": len(sql_vulnerabilities),
                "HTTP_Methods": len(http_vulnerabilities),
                "File_Upload": len(file_upload_vulnerabilities),
                "Potential_Upload_Paths": upload_paths_count,
                "Verified_Upload_Paths": verified_paths_count,
                "Directory_Listings": directory_listings,
                "total_vulnerabilities": len(basic_vulnerabilities) + len(xss_vulnerabilities) + 
                          len(sql_vulnerabilities) + len(http_vulnerabilities) + len(file_upload_vulnerabilities),
                "total_findings": len(basic_vulnerabilities) + len(xss_vulnerabilities) + 
                          len(sql_vulnerabilities) + len(http_vulnerabilities) + len(file_upload_vulnerabilities) +
                          (1 if upload_paths_count > 0 else 0)  # Count upload paths as one finding
            }
        }
        
        return self.results
    
    async def test_basic_scanner(self):
        """Run basic scanner."""
        scanner = BasicScanner()
        return await scanner.scan_url(self.url)
    
    async def test_xss_scanner(self):
        """Run XSS scanner."""
        scanner = EnhancedXSSScanner()
        return await scanner.scan_url(self.url)
    
    async def test_sql_injection_scanner(self):
        """Run SQL injection scanner."""
        scanner = EnhancedSQLScanner()
        return await scanner.scan_url(self.url)
    
    async def test_http_methods_scanner(self):
        """Run HTTP methods scanner."""
        scanner = EnhancedHTTPScanner()
        return await scanner.scan_url(self.url)
    
    async def test_file_upload_scanner(self):
        """Run file upload scanner."""
        scanner = EnhancedFileUploadScanner()
        return await scanner.scan_url(self.url)
    
    def print_summary(self):
        """Print a summary of the scan results."""
        duration = (self.end_time - self.start_time).total_seconds()
        print("=" * 80)
        print(f"SCAN SUMMARY (completed in {duration:.2f} seconds)")
        print("=" * 80)
        
        # Extract upload paths count and details
        upload_paths_count = 0
        verified_paths_count = 0
        directory_listings = 0
        
        for vuln in self.vulnerabilities.get("File_Upload", []):
            if vuln["name"] == "Potential File Upload Paths Detected":
                # Extract count from description
                desc_parts = vuln["description"].split(" ")
                if len(desc_parts) > 1 and desc_parts[1].isdigit():
                    upload_paths_count = int(desc_parts[1])
                
                # Get verified count from evidence
                evidence_parts = vuln["evidence"].split(" ")
                if "verified" in vuln["evidence"]:
                    for i, part in enumerate(evidence_parts):
                        if part == "verified," and i > 0 and evidence_parts[i-1].isdigit():
                            verified_paths_count = int(evidence_parts[i-1])
                
                # Get directory listing count
                if "directory listing" in vuln["evidence"]:
                    for i, part in enumerate(evidence_parts):
                        if part == "listing)" and i > 0 and evidence_parts[i-1].isdigit():
                            directory_listings = int(evidence_parts[i-1])
                break
            elif vuln["name"] == "Directory Listing Enabled on Upload Paths":
                directory_listings = int(vuln["description"].split(" ")[1])
                
        # Print summary with vulnerabilities count
        for scanner_name, vulns in self.vulnerabilities.items():
            count_str = f"{len(vulns)} vulnerabilities found"
            if scanner_name == "File_Upload":
                if upload_paths_count > 0:
                    verified_str = f" ({verified_paths_count} verified)" if verified_paths_count > 0 else ""
                    dir_listing_str = f", {directory_listings} with directory listing" if directory_listings > 0 else ""
                    count_str += f" and {upload_paths_count} potential upload paths{verified_str}{dir_listing_str}"
            print(f"{scanner_name}: {count_str}")
            
            if vulns:
                example = vulns[0]
                print(f"  - Example: {example['name']} ({example['severity']})")
                print(f"    Location: {example['location']}")
                
        # Calculate risk score based on vulnerabilities and upload paths
        total_vulns = sum(len(vulns) for vulns in self.vulnerabilities.values())
        # Directory listings are a higher risk than regular paths
        path_risk = upload_paths_count // 10 + verified_paths_count // 3 + directory_listings * 3
        risk_score = min(100, total_vulns * 2 + path_risk)
        
        risk_level = "Low"
        if risk_score > 30:
            risk_level = "Medium"
        if risk_score > 60:
            risk_level = "High"
        if risk_score > 85:
            risk_level = "Critical"
            
        print("-" * 80)
        print(f"Overall Risk: {risk_level} (Score: {risk_score}/100)")
        print("-" * 80)
    
    def export_to_json(self, filepath):
        """Export results to a JSON file."""
        try:
            with open(filepath, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"Results exported to {filepath}")
            return True
        except Exception as e:
            print(f"Error exporting results: {e}")
            return False

async def main():
    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description="Run enhanced security scanners on a URL")
    parser.add_argument("-u", "--url", help="Target URL to scan", required=True)
    parser.add_argument("-r", "--result", help="Output file for results (JSON format)")
    
    # Support both positional and named arguments for backward compatibility
    if "-u" in sys.argv or "--url" in sys.argv:
        args = parser.parse_args()
        url = args.url
        output_file = args.result
    else:
        # Legacy positional arguments support
        if len(sys.argv) < 2:
            print("Usage: python -m enhanced_test <url> [output_file]")
            return
        
        url = sys.argv[1]
        output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    try:
        # Print warning about dependencies
        try:
            import sklearn
            import numpy
        except ImportError:
            print("Warning: scikit-learn or numpy not available, ML detection disabled")
        
        print(f"Starting comprehensive vulnerability scan on {url}")
        print("=" * 80)
        
        runner = EnhancedTestRunner(url)
        await runner.run_tests()
        runner.print_summary()
        
        if output_file:
            runner.export_to_json(output_file)
    except Exception as e:
        print(f"Error during scan: {e}")

if __name__ == "__main__":
    asyncio.run(main()) 