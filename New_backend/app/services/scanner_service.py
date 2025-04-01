import asyncio
import os
import time
import json
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional, Set

from ..models.scan import ScanRequest, ScanResponse, ScanResult, ScanStatus, ScannerType
from ..db.database import save_to_db, update_in_db, find_document, find_documents
from .xss_scanner import XSSScanner
from .enhanced_sql_scanner import EnhancedSQLScanner
from .enhanced_http_scanner import EnhancedHTTPScanner
from .enhanced_file_upload_scanner import EnhancedFileUploadScanner
from .basic_scanner import BasicScanner
from .enhanced_xss_scanner import EnhancedXSSScanner

class ScannerService:
    """
    Service for managing and running vulnerability scans.
    """
    
    # Dictionary to store active scan data
    _active_scans: Dict[str, Dict[str, Any]] = {}
    
    # Cache directory for scans if not using MongoDB
    _cache_dir: str = os.path.join(os.path.dirname(os.path.dirname(__file__)), "cache")
    
    @classmethod
    async def start_scan(cls, scan_request: ScanRequest) -> ScanResponse:
        """
        Start a new vulnerability scan.
        
        Args:
            scan_request: The scan request data
            
        Returns:
            ScanResponse: Initial response with scan ID and status
        """
        # Initialize storage if needed
        cls._init_storage()
        
        # Generate a unique scan ID
        scan_id = str(uuid.uuid4())
        
        # Determine which scanners to use
        scanners_to_use = scan_request.scanners if scan_request.scanners else []
        if ScannerType.ALL in scanners_to_use:
            scanners_to_use = [
                ScannerType.BASIC,
                ScannerType.XSS,
                ScannerType.SQL_INJECTION,
                ScannerType.HTTP_METHODS,
                ScannerType.FILE_UPLOAD
            ]
        
        # Create scan record
        scan_record = {
            "scan_id": scan_id,
            "url": str(scan_request.url),
            "status": ScanStatus.PENDING,
            "timestamp": datetime.utcnow().isoformat(),
            "scanners_used": [s.value for s in scanners_to_use],
            "progress": 0,
            "message": "Scan pending",
            "total_scanners": len(scanners_to_use),
            "completed_scanners": 0
        }
        
        # Store scan record
        try:
            await save_to_db("scans", scan_record)
        except Exception as e:
            print(f"Error saving to database: {e}")
            # Fallback to local storage
            cls._save_scan_to_file(scan_record)
        
        # Store scan in active scans
        cls._active_scans[scan_id] = scan_record
        
        # Start the scan in the background
        asyncio.create_task(cls._run_scan(scan_id, scan_request))
        
        # Return initial scan response
        return ScanResponse(
            scan_id=scan_id,
            url=str(scan_request.url),
            status=ScanStatus.PENDING,
            timestamp=datetime.fromisoformat(scan_record["timestamp"]),
            scanners_used=scan_record["scanners_used"],
            progress=0,
            message="Scan pending"
        )
    
    @classmethod
    async def _run_scan(cls, scan_id: str, scan_request: ScanRequest):
        """
        Run the scan in the background.
        
        Args:
            scan_id: The ID of the scan
            scan_request: The scan request data
        """
        # Update scan status to running
        cls._update_scan_status(scan_id, ScanStatus.RUNNING, message="Scan in progress")
        
        start_time = time.time()
        url = str(scan_request.url)
        scanners_to_use = scan_request.scanners if scan_request.scanners else []
        
        if ScannerType.ALL in scanners_to_use:
            scanners_to_use = [
                ScannerType.BASIC,
                ScannerType.XSS,
                ScannerType.SQL_INJECTION,
                ScannerType.HTTP_METHODS,
                ScannerType.FILE_UPLOAD
            ]
        
        all_vulnerabilities = []
        total_scanners = len(scanners_to_use)
        
        try:
            # Run Basic scanner if requested
            if ScannerType.BASIC in scanners_to_use:
                cls._update_scan_message(scan_id, "Running Basic scanner (HTTP Headers and Port Scanning)...")
                basic_scanner = BasicScanner()
                basic_vulns = await basic_scanner.scan_url(url)
                all_vulnerabilities.extend(basic_vulns)
                cls._update_completed_scanners(scan_id, 1)
            
            # Run XSS scanner if requested
            if ScannerType.XSS in scanners_to_use:
                cls._update_scan_message(scan_id, "Running Enhanced XSS scanner...")
                xss_scanner = EnhancedXSSScanner()
                xss_vulns = await xss_scanner.scan_url(url)
                all_vulnerabilities.extend(xss_vulns)
                cls._update_completed_scanners(scan_id, 1)
            
            # Run SQL Injection scanner if requested
            if ScannerType.SQL_INJECTION in scanners_to_use:
                cls._update_scan_message(scan_id, "Running Enhanced SQL Injection scanner...")
                sqli_scanner = EnhancedSQLScanner()
                sqli_vulns = await sqli_scanner.scan_url(url)
                all_vulnerabilities.extend(sqli_vulns)
                cls._update_completed_scanners(scan_id, 1)
            
            # Run HTTP Methods scanner if requested
            if ScannerType.HTTP_METHODS in scanners_to_use:
                cls._update_scan_message(scan_id, "Running Enhanced HTTP Methods scanner...")
                http_methods_scanner = EnhancedHTTPScanner()
                http_methods_vulns = await http_methods_scanner.scan_url(url)
                all_vulnerabilities.extend(http_methods_vulns)
                cls._update_completed_scanners(scan_id, 1)
            
            # Run File Upload scanner if requested
            if ScannerType.FILE_UPLOAD in scanners_to_use:
                cls._update_scan_message(scan_id, "Running Enhanced File Upload scanner...")
                file_upload_scanner = EnhancedFileUploadScanner()
                file_upload_vulns = await file_upload_scanner.scan_url(url)
                all_vulnerabilities.extend(file_upload_vulns)
                cls._update_completed_scanners(scan_id, 1)
            
            # Calculate scan duration
            scan_duration = time.time() - start_time
            
            # Combine results
            result = cls._combine_results(all_vulnerabilities)
            result.scan_id = scan_id
            result.url = url
            result.scan_duration = scan_duration
            result.scanners_used = [s.value for s in scanners_to_use]
            
            # Store result
            result_dict = result.dict()
            result_id = await save_to_db("scan_results", result_dict)
            
            if not result_id:
                # Fallback to local storage
                cls._save_result_to_file(result_dict)
                result_id = scan_id
            
            # Update scan status to completed
            cls._update_scan_status(
                scan_id, 
                ScanStatus.COMPLETED, 
                progress=100, 
                message=f"Scan completed. Found {len(all_vulnerabilities)} vulnerabilities.",
                result_id=result_id
            )
            
        except Exception as e:
            # Update scan status to failed
            cls._update_scan_status(
                scan_id, 
                ScanStatus.FAILED,
                message=f"Scan failed: {str(e)}"
            )
            print(f"Error running scan: {str(e)}")
    
    @classmethod
    def _init_storage(cls):
        """Initialize storage for scan data"""
        if not os.path.exists(cls._cache_dir):
            os.makedirs(cls._cache_dir)
            
        scans_dir = os.path.join(cls._cache_dir, "scans")
        if not os.path.exists(scans_dir):
            os.makedirs(scans_dir)
            
        results_dir = os.path.join(cls._cache_dir, "results")
        if not os.path.exists(results_dir):
            os.makedirs(results_dir)
    
    @classmethod
    def _save_scan_to_file(cls, scan_record: Dict[str, Any]):
        """
        Save scan record to file.
        
        Args:
            scan_record: The scan record to save
        """
        scan_id = scan_record["scan_id"]
        file_path = os.path.join(cls._cache_dir, "scans", f"{scan_id}.json")
        
        with open(file_path, "w") as f:
            json.dump(scan_record, f, indent=2)
    
    @classmethod
    def _update_scan_status(cls, scan_id: str, status: str, **kwargs):
        """
        Update scan status.
        
        Args:
            scan_id: The ID of the scan
            status: The new status
            **kwargs: Additional data to update
        """
        if scan_id in cls._active_scans:
            # Update in memory
            cls._active_scans[scan_id].update({"status": status, **kwargs})
            
            # Update in database
            try:
                update_in_db("scans", {"scan_id": scan_id}, {"status": status, **kwargs})
            except Exception as e:
                print(f"Error updating scan in database: {e}")
                # Fallback to local storage
                file_path = os.path.join(cls._cache_dir, "scans", f"{scan_id}.json")
                if os.path.exists(file_path):
                    try:
                        with open(file_path, "r") as f:
                            scan_record = json.load(f)
                        
                        scan_record.update({"status": status, **kwargs})
                        
                        with open(file_path, "w") as f:
                            json.dump(scan_record, f, indent=2)
                    except Exception as e2:
                        print(f"Error updating scan in file: {e2}")
    
    @classmethod
    def _save_result_to_file(cls, result_data: Dict[str, Any]):
        """
        Save scan result to file.
        
        Args:
            result_data: The result data to save
        """
        scan_id = result_data["scan_id"]
        file_path = os.path.join(cls._cache_dir, "results", f"{scan_id}.json")
        
        with open(file_path, "w") as f:
            json.dump(result_data, f, indent=2)
    
    @classmethod
    async def get_scan(cls, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Get scan record.
        
        Args:
            scan_id: The ID of the scan
            
        Returns:
            Optional[Dict[str, Any]]: The scan record if found, None otherwise
        """
        # Try to get from active scans first
        if scan_id in cls._active_scans:
            return cls._active_scans[scan_id]
        
        # Try to get from database
        try:
            scan = await find_document("scans", {"scan_id": scan_id})
            if scan:
                return scan
        except Exception as e:
            print(f"Error getting scan from database: {e}")
        
        # Fallback to local storage
        file_path = os.path.join(cls._cache_dir, "scans", f"{scan_id}.json")
        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                return json.load(f)
        
        return None
    
    @classmethod
    async def get_result(cls, result_id: str) -> Optional[Dict[str, Any]]:
        """
        Get scan result.
        
        Args:
            result_id: The ID of the result
            
        Returns:
            Optional[Dict[str, Any]]: The scan result if found, None otherwise
        """
        # Try to get from database
        try:
            result = await find_document("scan_results", {"scan_id": result_id})
            if result:
                return result
        except Exception as e:
            print(f"Error getting result from database: {e}")
        
        # Fallback to local storage
        file_path = os.path.join(cls._cache_dir, "results", f"{result_id}.json")
        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                return json.load(f)
        
        return None
    
    @classmethod
    async def get_scans(cls, limit: int = 10, skip: int = 0) -> Dict[str, Any]:
        """
        Get all scans.
        
        Args:
            limit: Maximum number of scans to return
            skip: Number of scans to skip
            
        Returns:
            Dict[str, Any]: Dictionary with scans and total count
        """
        try:
            # Get from database
            scans = await find_documents("scans", {}, limit, skip)
            
            # Get total count
            total = len(await find_documents("scans", {}))
            
            return {
                "scans": scans,
                "total": total
            }
        except Exception as e:
            print(f"Error getting scans from database: {e}")
            
            # Fallback to local storage
            scans_dir = os.path.join(cls._cache_dir, "scans")
            if os.path.exists(scans_dir):
                scan_files = os.listdir(scans_dir)
                total = len(scan_files)
                
                scans = []
                for file_name in scan_files[skip:skip+limit]:
                    file_path = os.path.join(scans_dir, file_name)
                    with open(file_path, "r") as f:
                        scans.append(json.load(f))
                
                return {
                    "scans": scans,
                    "total": total
                }
            
            return {
                "scans": [],
                "total": 0
            }
    
    @staticmethod
    async def get_scan_status(scan_id: str) -> Optional[ScanResponse]:
        """
        Get the status of a scan.
        
        Args:
            scan_id: The ID of the scan
            
        Returns:
            Optional[ScanResponse]: The scan status if found, None otherwise
        """
        scan = await ScannerService.get_scan(scan_id)
        
        if not scan:
            return None
        
        return ScanResponse(
            scan_id=scan["scan_id"],
            url=scan["url"],
            status=ScanStatus(scan["status"]),
            timestamp=datetime.fromisoformat(scan["timestamp"]),
            scanners_used=scan["scanners_used"],
            progress=scan.get("progress", 0),
            message=scan.get("message"),
            result_id=scan.get("result_id")
        )
    
    @staticmethod
    async def get_scan_result(scan_id: str) -> Optional[ScanResult]:
        """
        Get the result of a scan.
        
        Args:
            scan_id: The ID of the scan
            
        Returns:
            Optional[ScanResult]: The scan result if found, None otherwise
        """
        result_data = await ScannerService.get_result(scan_id)
        
        if not result_data:
            return None
        
        # Convert timestamp from string to datetime
        if isinstance(result_data.get("timestamp"), str):
            result_data["timestamp"] = datetime.fromisoformat(result_data["timestamp"])
        
        return ScanResult(**result_data)
    
    @staticmethod
    async def list_scans(limit: int = 10, skip: int = 0) -> List[ScanResponse]:
        """
        List all scans.
        
        Args:
            limit: Maximum number of scans to return
            skip: Number of scans to skip
            
        Returns:
            List[ScanResponse]: List of scan responses
        """
        result = await ScannerService.get_scans(limit, skip)
        scans = result["scans"]
        
        scan_responses = []
        for scan in scans:
            scan_responses.append(ScanResponse(
                scan_id=scan["scan_id"],
                url=scan["url"],
                status=ScanStatus(scan["status"]),
                timestamp=datetime.fromisoformat(scan["timestamp"]),
                scanners_used=scan["scanners_used"],
                progress=scan.get("progress", 0),
                message=scan.get("message"),
                result_id=scan.get("result_id")
            ))
        
        return scan_responses
    
    @classmethod
    def _update_scan_message(cls, scan_id: str, message: str):
        """
        Update scan message.
        
        Args:
            scan_id: The ID of the scan
            message: The new message
        """
        cls._update_scan_status(scan_id, cls._active_scans[scan_id]["status"], message=message)
    
    @classmethod
    def _update_completed_scanners(cls, scan_id: str, scanner_index: int):
        """
        Update the number of completed scanners and progress.
        
        Args:
            scan_id: The ID of the scan
            scanner_index: The index of the completed scanner
        """
        if scan_id in cls._active_scans:
            completed = cls._active_scans[scan_id].get("completed_scanners", 0) + 1
            total = cls._active_scans[scan_id].get("total_scanners", 1)
            progress = int((completed / total) * 100)
            
            cls._update_scan_status(
                scan_id, 
                cls._active_scans[scan_id]["status"], 
                completed_scanners=completed,
                progress=progress
            )
    
    @classmethod
    def _combine_results(cls, results: List[Dict[str, Any]]) -> ScanResult:
        """
        Combine results from multiple scanners.
        
        Args:
            results: List of vulnerabilities from all scanners
            
        Returns:
            ScanResult: Combined scan result
        """
        # Create a result with empty fields
        combined_result = ScanResult(
            scan_id="",
            url="",
            timestamp=datetime.utcnow(),
            scan_duration=0,
            scanners_used=[],
            vulnerabilities={},
            summary={
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            },
            findings=[]
        )
        
        # Add each vulnerability to the result
        for vuln in results:
            vuln_id = vuln.get("id", str(uuid.uuid4()))
            severity = vuln.get("severity", "info").lower()
            
            # Update vulnerability dictionary
            combined_result.vulnerabilities[vuln_id] = vuln
            
            # Update summary counts
            if severity in combined_result.summary:
                combined_result.summary[severity] += 1
            
            # Add to findings list
            combined_result.findings.append(vuln)
        
        return combined_result 