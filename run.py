import os
from app import app

if __name__ == '__main__':
    # Check if we're running on Render
    is_render = os.environ.get('RENDER') == 'true'
    
    if is_render:
        # On Render, let Gunicorn handle the serving
        # This file will be called by python run.py, but won't run the app directly
        # instead, Render will use gunicorn behind the scenes
        pass
    else:
        # In development, run with debug enabled
        app.run(debug=True, host='0.0.0.0') 