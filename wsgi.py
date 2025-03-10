#!/usr/bin/env python3
import os
import sys

# Add the application directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the Flask application
from app import app

# This file is used by Gunicorn on Render
if __name__ == "__main__":
    app.run() 