import os
import sys
import sqlite3

def test_database_access():
    """Test that the application can access the database"""
    # Get the application root directory
    APP_ROOT = os.path.dirname(os.path.abspath(__file__))
    
    # Check if running on Render
    is_render = os.environ.get('RENDER') == 'true'
    
    # Database configuration - Use the same path as in app.py
    if is_render:
        DB_DIR = os.path.join(APP_ROOT, 'instance', 'data')
    else:
        DB_DIR = os.path.join(APP_ROOT, 'data')
    
    # Create the directory if it doesn't exist
    os.makedirs(DB_DIR, exist_ok=True)
    
    DB_PATH = os.path.join(DB_DIR, 'cosmic_teams.db')
    
    # Try to connect to the database
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Create a test table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS test_table (
            id INTEGER PRIMARY KEY,
            name TEXT
        )
        ''')
        
        # Insert a test record
        cursor.execute('INSERT INTO test_table (name) VALUES (?)', ('test',))
        
        # Commit the changes
        conn.commit()
        
        # Query the test record
        cursor.execute('SELECT * FROM test_table WHERE name = ?', ('test',))
        result = cursor.fetchone()
        
        # Close the connection
        conn.close()
        
        if result:
            print("Database access test passed!")
            return True
        else:
            print("Database access test failed: Could not retrieve test record")
            return False
    
    except Exception as e:
        print(f"Database access test failed: {str(e)}")
        return False

if __name__ == '__main__':
    success = test_database_access()
    sys.exit(0 if success else 1) 