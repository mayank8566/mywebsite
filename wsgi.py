#!/usr/bin/env python3
import os
import sys

# Add the application directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the Flask application
from app import app as application

# This allows both running the app through Gunicorn/WSGI and directly
if __name__ == "__main__":
    application.run(host='0.0.0.0', port=5000) 