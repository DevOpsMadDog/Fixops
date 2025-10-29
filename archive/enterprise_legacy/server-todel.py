#!/usr/bin/env python3
"""
FixOps Enterprise Server Entry Point
Compatible with supervisor configuration
"""

# Import the main FastAPI app from the src module
from src.main import app

# This allows uvicorn to find the app as server:app
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001)
