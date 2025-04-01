import os
import motor.motor_asyncio
from typing import Optional, Dict, Any

# MongoDB Configuration
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb+srv://jaisrajputdev:Database@#1234@mycluster.7ay65.mongodb.net/?retryWrites=true&w=majority&appName=MyCluster")
DB_NAME = os.getenv("DB_NAME", "safex_vulnerability_scanner")

# Global database connection object
_mongo_client = None
_db = None

async def connect_to_mongo() -> Optional[motor.motor_asyncio.AsyncIOMotorDatabase]:
    """
    Connect to MongoDB database
    
    Returns:
        Optional[motor.motor_asyncio.AsyncIOMotorDatabase]: Database connection object
    """
    global _mongo_client, _db
    
    try:
        # Create a new client and connect to the server
        _mongo_client = motor.motor_asyncio.AsyncIOMotorClient(MONGODB_URL, serverSelectionTimeoutMS=5000)
        
        # Verify the connection was successful
        await _mongo_client.server_info()
        
        # Access the database
        _db = _mongo_client[DB_NAME]
        
        # Create collections if they don't exist
        if "scans" not in await _db.list_collection_names():
            await _db.create_collection("scans")
        
        if "scan_results" not in await _db.list_collection_names():
            await _db.create_collection("scan_results")
        
        return _db
    
    except Exception as e:
        print(f"Error connecting to MongoDB: {e}")
        return None

async def close_mongo_connection() -> None:
    """Close the MongoDB connection"""
    global _mongo_client
    if _mongo_client:
        _mongo_client.close()

def get_db() -> motor.motor_asyncio.AsyncIOMotorDatabase:
    """
    Get the database connection
    
    Returns:
        motor.motor_asyncio.AsyncIOMotorDatabase: Database connection object
    """
    global _db
    if not _db:
        raise Exception("Database not initialized")
    return _db

async def save_to_db(collection: str, data: Dict[str, Any]) -> str:
    """
    Save data to database
    
    Args:
        collection: Collection name
        data: Data to save
        
    Returns:
        str: ID of inserted document
    """
    try:
        db = get_db()
        result = await db[collection].insert_one(data)
        return str(result.inserted_id)
    except Exception as e:
        print(f"Error saving to database: {e}")
        return ""

async def update_in_db(collection: str, filter_query: Dict[str, Any], update_data: Dict[str, Any]) -> bool:
    """
    Update document in database
    
    Args:
        collection: Collection name
        filter_query: Query to find document
        update_data: Data to update
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        db = get_db()
        result = await db[collection].update_one(filter_query, {"$set": update_data})
        return result.modified_count > 0
    except Exception as e:
        print(f"Error updating in database: {e}")
        return False

async def find_document(collection: str, query: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Find a document in database
    
    Args:
        collection: Collection name
        query: Query to find document
        
    Returns:
        Optional[Dict[str, Any]]: Document if found, None otherwise
    """
    try:
        db = get_db()
        document = await db[collection].find_one(query)
        return document
    except Exception as e:
        print(f"Error finding document in database: {e}")
        return None

async def find_documents(collection: str, query: Dict[str, Any], limit: int = 0, skip: int = 0) -> list:
    """
    Find documents in database
    
    Args:
        collection: Collection name
        query: Query to find documents
        limit: Maximum number of documents to return
        skip: Number of documents to skip
        
    Returns:
        list: List of documents
    """
    try:
        db = get_db()
        cursor = db[collection].find(query).skip(skip)
        if limit > 0:
            cursor = cursor.limit(limit)
        return await cursor.to_list(length=None)
    except Exception as e:
        print(f"Error finding documents in database: {e}")
        return [] 