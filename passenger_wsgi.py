import os
import sys

# Add the application directory to Python path
INTERP = os.path.expanduser("~/path/to/your/venv/bin/python3")
if sys.executable != INTERP:
    os.execl(INTERP, INTERP, *sys.argv)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the Flask application
from app import app as application 