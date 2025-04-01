from pydantic import BaseModel, Field, HttpUrl, validator
from typing import List, Dict, Any, Optional, Literal
from datetime import datetime
from enum import Enum
import uuid

class ScannerType(str, Enum):
    """Types of scanners available"""
    BASIC = "basic"
    XSS = "xss"
    SQL_INJECTION = "sql_injection"
    FILE_UPLOAD = "file_upload"
    HTTP_METHODS = "http_methods"
    ALL = "all"

class ScannerGroup(str, Enum):
    """Group categories for scanners"""
    ESSENTIAL = "essential"
    COMMON = "common"
    ADVANCED = "advanced"

# Define standard scanner groups
SCANNER_GROUPS = {
    ScannerGroup.ESSENTIAL: [ScannerType.BASIC, ScannerType.XSS, ScannerType.SQL_INJECTION],
    ScannerGroup.COMMON: [ScannerType.BASIC, ScannerType.XSS, ScannerType.SQL_INJECTION, ScannerType.HTTP_METHODS],
    ScannerGroup.ADVANCED: [ScannerType.BASIC, ScannerType.XSS, ScannerType.SQL_INJECTION, ScannerType.HTTP_METHODS, ScannerType.FILE_UPLOAD]
}

class ScannerInfo(BaseModel):
    """Information about a scanner"""
    id: str
    name: str
    description: str
    intensity: int = Field(..., ge=1, le=4)  # 1-4 scale of scan intensity
    category: Literal["essential", "common", "advanced"]

class ScanRequest(BaseModel):
    """Model for scan request"""
    url: HttpUrl
    scanners: Optional[List[ScannerType]] = None
    scanner_group: Optional[ScannerGroup] = ScannerGroup.ESSENTIAL
    scan_params: Optional[Dict[str, Any]] = None
    
    @validator('scanners', pre=True, always=True)
    def validate_scanners(cls, v, values):
        # If scanners is not provided or is empty, use scanner_group
        if not v and 'scanner_group' in values and values['scanner_group']:
            return SCANNER_GROUPS.get(values['scanner_group'], SCANNER_GROUPS[ScannerGroup.ESSENTIAL])
        return v

class Vulnerability(BaseModel):
    """Model for a vulnerability"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    location: str
    evidence: str
    remediation: str

class ScanResult(BaseModel):
    """Model for scan result"""
    scan_id: str
    url: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    scan_duration: float  # Duration in seconds
    scanners_used: List[str]
    vulnerabilities: Dict[str, Vulnerability] = {}
    summary: Dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }
    findings: List[Vulnerability] = []

class ScanStatus(str, Enum):
    """Status of a scan"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class ScanResponse(BaseModel):
    """Model for scan response"""
    scan_id: str
    url: str
    status: ScanStatus
    timestamp: datetime
    scanners_used: List[str]
    progress: int = 0  # 0-100%
    message: Optional[str] = None
    result_id: Optional[str] = None 