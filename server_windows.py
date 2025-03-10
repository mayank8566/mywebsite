from waitress import serve
import os
import sys

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the app
from app import app

if __name__ == '__main__':
    print("Starting CosmicTeams server on http://localhost:8000")
    serve(app, host='0.0.0.0', port=8000) 