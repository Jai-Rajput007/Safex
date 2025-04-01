import os
import uvicorn
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    
    print(f"Starting Safex Vulnerability Scanner API on {host}:{port}")
    print("Documentation available at: http://localhost:{port}/docs")
    
    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=True,
        log_level="info"
    ) 