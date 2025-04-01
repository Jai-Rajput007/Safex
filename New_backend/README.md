# Safex Vulnerability Scanner Backend

This is the backend API service for the Safex Vulnerability Scanner application, which helps identify security vulnerabilities in web applications.

## Features

- XSS (Cross-Site Scripting) scanning
- SQL Injection scanning
- HTTP Methods scanning
- File Upload vulnerability scanning
- MongoDB integration for storing scan results
- Asynchronous processing

## Setup

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Set up environment variables (optional, defaults are provided):

```
MONGODB_URL=mongodb+srv://username:password@cluster.example.net/?retryWrites=true&w=majority
DB_NAME=safex_vulnerability_scanner
PORT=8000
HOST=0.0.0.0
```

3. Run the application:

```bash
python -m app.main
```

Or with uvicorn directly:

```bash
uvicorn app.main:app --reload
```

## API Endpoints

- **GET /**: Root endpoint with API information
- **GET /health**: Health check endpoint
- **POST /api/v1/scanner/start**: Start a new scan
- **GET /api/v1/scanner/{scan_id}**: Get scan status
- **GET /api/v1/scanner/{scan_id}/result**: Get scan results
- **GET /api/v1/scanner/scanner-info**: Get information about available scanners
- **GET /api/v1/scanner/list**: List all scans

## Request Examples

### Start a scan:

```json
POST /api/v1/scanner/start
{
  "url": "https://example.com",
  "scanners": ["xss", "sql_injection"],
  "scanner_group": "essential"
}
```

### Get scan status:

```
GET /api/v1/scanner/123e4567-e89b-12d3-a456-426614174000
```

### Get scan results:

```
GET /api/v1/scanner/123e4567-e89b-12d3-a456-426614174000/result
```

## Development

The application is built with FastAPI and uses async programming patterns throughout. Key components:

- **models/scan.py**: Pydantic models for data validation
- **services/*.py**: Scanner implementations for different vulnerability types
- **api/routes/scanner_routes.py**: API endpoint definitions
- **db/database.py**: Database connection and helpers 