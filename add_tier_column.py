import sqlite3
import os

DB_PATH = 'database.db'

def add_tier_column():
    """Add tier column to the users table"""
    if not os.path.exists(DB_PATH):
        print(f"Database file {DB_PATH} not found.")
        return False
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # Check if tier column already exists
        cursor.execute("PRAGMA table_info(users)")
        columns = cursor.fetchall()
        column_names = [column[1] for column in columns]
        
        if 'tier' not in column_names:
            print("Adding tier column to users table...")
            cursor.execute("ALTER TABLE users ADD COLUMN tier TEXT DEFAULT 'none'")
            conn.commit()
            print("Migration completed successfully.")
        else:
            print("tier column already exists in the users table.")
        
        return True
    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
        return False
    finally:
        conn.close()

if __name__ == "__main__":
    if add_tier_column():
        print("Database updated successfully.")
    else:
        print("Failed to update database.") 