from fastapi import APIRouter
from .scanner_routes import router as scanner_router

# Main API router
router = APIRouter()

# Include scanner router
router.include_router(scanner_router, prefix="/scanner", tags=["scanner"]) 