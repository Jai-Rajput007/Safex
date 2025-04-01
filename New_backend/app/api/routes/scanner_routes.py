from fastapi import APIRouter, HTTPException, Query, Depends
from typing import List, Dict, Any, Optional
from ...models.scan import ScanRequest, ScanResponse, ScanResult, ScannerInfo, ScannerType, ScannerGroup, SCANNER_GROUPS
from ...services.scanner_service import ScannerService

router = APIRouter()

@router.post("/start", response_model=ScanResponse)
async def start_scan(scan_request: ScanRequest):
    """
    Start a new vulnerability scan
    
    Args:
        scan_request: The scan request data
        
    Returns:
        ScanResponse: Initial response with scan ID and status
    """
    try:
        # Start the scan
        scan_response = await ScannerService.start_scan(scan_request)
        return scan_response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error starting scan: {str(e)}")

@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan_status(scan_id: str):
    """
    Get the status of a scan
    
    Args:
        scan_id: The ID of the scan
        
    Returns:
        ScanResponse: The scan status
    """
    try:
        # Get the scan status
        scan_status = await ScannerService.get_scan_status(scan_id)
        if not scan_status:
            raise HTTPException(status_code=404, detail=f"Scan with ID {scan_id} not found")
        return scan_status
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting scan status: {str(e)}")

@router.get("/{scan_id}/result", response_model=ScanResult)
async def get_scan_result(scan_id: str):
    """
    Get the result of a completed scan
    
    Args:
        scan_id: The ID of the scan
        
    Returns:
        ScanResult: The scan result
    """
    try:
        # Get the scan result
        scan_result = await ScannerService.get_scan_result(scan_id)
        if not scan_result:
            raise HTTPException(status_code=404, detail=f"Result for scan with ID {scan_id} not found")
        return scan_result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting scan result: {str(e)}")

@router.get("/scanner-info", response_model=List[ScannerInfo])
async def get_scanner_info():
    """
    Get information about available scanners
    
    Returns:
        List[ScannerInfo]: List of available scanners
    """
    # Return information about all available scanners
    scanners = [
        ScannerInfo(
            id=ScannerType.XSS,
            name="XSS Scanner",
            description="Scans for Cross-Site Scripting vulnerabilities",
            intensity=2,
            category="essential"
        ),
        ScannerInfo(
            id=ScannerType.SQL_INJECTION,
            name="SQL Injection Scanner",
            description="Scans for SQL Injection vulnerabilities",
            intensity=3,
            category="essential"
        ),
        ScannerInfo(
            id=ScannerType.HTTP_METHODS,
            name="HTTP Methods Scanner",
            description="Checks for insecure HTTP methods",
            intensity=1,
            category="common"
        ),
        ScannerInfo(
            id=ScannerType.FILE_UPLOAD,
            name="File Upload Scanner",
            description="Scans for file upload vulnerabilities",
            intensity=4,
            category="advanced"
        )
    ]
    return scanners

@router.get("/list", response_model=List[ScanResponse])
async def list_scans(limit: int = Query(10, ge=1, le=100), skip: int = Query(0, ge=0)):
    """
    List all scans
    
    Args:
        limit: Maximum number of scans to return
        skip: Number of scans to skip
        
    Returns:
        List[ScanResponse]: List of scans
    """
    try:
        # Get all scans
        scans = await ScannerService.list_scans(limit, skip)
        return scans
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error listing scans: {str(e)}") 