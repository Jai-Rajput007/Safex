import requests
import json
import sys
import os
import time
from urllib.parse import urljoin

def test_connection(backend_url, target_url):
    """
    Test the connection between the backend and frontend by making API calls
    
    Args:
        backend_url: The URL of the backend API
        target_url: The URL to scan for vulnerabilities
    """
    print(f"Testing connection to backend at {backend_url}")
    print(f"Will scan {target_url} for vulnerabilities")
    print("=" * 80)
    
    # Test 1: Check if the API is running (root endpoint)
    print("\n[1] Testing API Root Endpoint")
    try:
        response = requests.get(backend_url)
        if response.status_code == 200:
            print(f"  ✓ API is running. Status: {response.status_code}")
            print(f"  Response: {response.json()}")
        else:
            print(f"  ✗ API returned status code {response.status_code}")
            print(f"  Response: {response.text}")
    except Exception as e:
        print(f"  ✗ Failed to connect to API: {str(e)}")
        sys.exit(1)
    
    # Test 2: Check API health
    print("\n[2] Testing Health Check Endpoint")
    try:
        health_url = urljoin(backend_url, "health")
        response = requests.get(health_url)
        if response.status_code == 200:
            print(f"  ✓ Health check passed. Status: {response.status_code}")
            print(f"  Response: {response.json()}")
        else:
            print(f"  ✗ Health check failed with status code {response.status_code}")
            print(f"  Response: {response.text}")
    except Exception as e:
        print(f"  ✗ Failed to connect to health endpoint: {str(e)}")
    
    # Test 3: Start a scan
    print("\n[3] Testing Start Scan Endpoint")
    try:
        scan_url = urljoin(backend_url, "api/v1/scanner/start")
        scan_data = {
            "url": target_url,
            "scanners": ["basic", "xss", "sql_injection", "http_methods"],
            "scanner_group": "common"
        }
        
        response = requests.post(scan_url, json=scan_data)
        if response.status_code == 200:
            print(f"  ✓ Scan started successfully. Status: {response.status_code}")
            scan_result = response.json()
            print(f"  Scan ID: {scan_result.get('scan_id')}")
            
            # Test 4: Check scan status
            print("\n[4] Testing Get Scan Status Endpoint")
            scan_id = scan_result.get('scan_id')
            status_url = urljoin(backend_url, f"api/v1/scanner/{scan_id}")
            
            # Poll for status a few times
            max_polls = 10
            poll_count = 0
            completed = False
            
            while poll_count < max_polls and not completed:
                poll_count += 1
                time.sleep(3)  # Wait 3 seconds between polls
                
                status_response = requests.get(status_url)
                if status_response.status_code == 200:
                    status_data = status_response.json()
                    status = status_data.get('status')
                    progress = status_data.get('progress', 0)
                    
                    print(f"  Poll {poll_count}: Status = {status}, Progress = {progress}%")
                    
                    if status == "completed" or status == "failed":
                        completed = True
                        
                        # Test 5: Get scan results
                        print("\n[5] Testing Get Scan Results Endpoint")
                        result_url = urljoin(backend_url, f"api/v1/scanner/{scan_id}/result")
                        result_response = requests.get(result_url)
                        
                        if result_response.status_code == 200:
                            result_data = result_response.json()
                            print(f"  ✓ Got scan results. Status: {result_response.status_code}")
                            
                            # Show summary
                            summary = result_data.get('summary', {})
                            print(f"\nVulnerability Summary:")
                            print(f"  Critical: {summary.get('critical', 0)}")
                            print(f"  High: {summary.get('high', 0)}")
                            print(f"  Medium: {summary.get('medium', 0)}")
                            print(f"  Low: {summary.get('low', 0)}")
                            print(f"  Info: {summary.get('info', 0)}")
                            
                            # Show a few vulnerabilities
                            findings = result_data.get('findings', [])
                            if findings:
                                print("\nSample Vulnerabilities:")
                                for i, vuln in enumerate(findings[:3], 1):
                                    print(f"  {i}. {vuln.get('name')} ({vuln.get('severity')})")
                                    print(f"     Location: {vuln.get('location')}")
                            else:
                                print("\nNo vulnerabilities found in the scan.")
                            
                            # Export results if requested
                            if len(sys.argv) > 3:
                                output_file = sys.argv[3]
                                with open(output_file, 'w') as f:
                                    json.dump(result_data, f, indent=2)
                                print(f"\nScan results exported to {output_file}")
                        else:
                            print(f"  ✗ Failed to get scan results. Status: {result_response.status_code}")
                else:
                    print(f"  ✗ Failed to get scan status. Status: {status_response.status_code}")
            
            if not completed:
                print("  ✗ Scan did not complete within expected time")
        else:
            print(f"  ✗ Failed to start scan. Status: {response.status_code}")
            print(f"  Response: {response.text}")
    except Exception as e:
        print(f"  ✗ Error during scan process: {str(e)}")
    
    print("\n" + "=" * 80)
    print("Connection testing completed.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python connect_to_frontend.py <backend_url> <target_url> [output_file]")
        print("Example: python connect_to_frontend.py http://localhost:8000 http://testphp.vulnweb.com/ results.json")
        sys.exit(1)
    
    backend_url = sys.argv[1]
    target_url = sys.argv[2]
    
    test_connection(backend_url, target_url) 