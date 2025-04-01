import os
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
from typing import Dict, Any

from .api.routes import router as api_router
from .db.database import connect_to_mongo, close_mongo_connection, get_db

# Create FastAPI app
app = FastAPI(
    title="Safex Vulnerability Scanner API",
    description="API for scanning websites for vulnerabilities",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins in development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Event handlers for MongoDB connection
@app.on_event("startup")
async def startup_db_client():
    try:
        db = await connect_to_mongo()
        if not db:
            print("WARNING: Failed to connect to MongoDB. Using in-memory database.")
        else:
            print("Successfully connected to MongoDB.")
        
        db_instance = get_db()
        print("Database initialized successfully.")
    except Exception as e:
        print(f"WARNING: Database initialization issue: {e}")

@app.on_event("shutdown")
async def shutdown_db_client():
    await close_mongo_connection()

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    print(f"Global exception handler caught: {str(exc)}")
    if isinstance(exc, HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"message": exc.detail}
        )
    return JSONResponse(
        status_code=500,
        content={"message": f"An unexpected error occurred: {str(exc)}"}
    )

# Include API router with proper prefix
app.include_router(api_router, prefix="/api/v1")

# Root endpoint
@app.get("/")
async def root():
    return {
        "message": "Welcome to Safex Vulnerability Scanner API",
        "version": "1.0.0",
        "docs": "/docs",
        "redoc": "/redoc",
        "endpoints": {
            "start_scan": "/api/v1/scanner/start",
            "get_scan_status": "/api/v1/scanner/{scan_id}",
            "get_scan_result": "/api/v1/scanner/{scan_id}/result",
            "get_scanner_info": "/api/v1/scanner/scanner-info"
        }
    }

# Health check endpoint
@app.get("/health")
async def health_check():
    try:
        db_instance = get_db()
        return {
            "status": "healthy",
            "database": "connected",
            "api_version": "1.0.0"
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "database": f"error: {str(e)}",
            "api_version": "1.0.0"
        }

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=True,
        log_level="info"
    ) 