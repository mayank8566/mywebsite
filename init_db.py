import sqlite3
import os
import hashlib
import secrets
from datetime import datetime

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
SCHEMA_PATH = 'schema.sql'

def hash_password(password):
    """Hash a password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def init_db():
    """Initialize the database with the schema and default data"""
    # Check if database already exists
    if os.path.exists(DB_PATH):
        print(f"Database file {DB_PATH} already exists. Creating backup...")
        backup_name = f"{DB_PATH}.backup.{datetime.now().strftime('%Y%m%d%H%M%S')}"
        os.rename(DB_PATH, backup_name)
        print(f"Backup created: {backup_name}")
    
    # Create a new database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Read and execute the schema SQL file
    with open(SCHEMA_PATH, 'r') as schema_file:
        schema_sql = schema_file.read()
        cursor.executescript(schema_sql)
    
    print("Database schema created successfully.")
    
    # Create admin user
    admin_username = "admin"
    admin_password = "admin123"  # This should be changed in production
    admin_email = "admin@galaxyminecraft.com"
    
    hashed_password = hash_password(admin_password)
    
    cursor.execute(
        "INSERT INTO users (username, email, password, is_admin, can_create_team, galaxy_rank) VALUES (?, ?, ?, ?, ?, ?)",
        (admin_username, admin_email, hashed_password, 1, 1, "Galaxy Administrator")
    )
    
    print("Admin user created successfully.")
    
    # Create some default achievements
    achievements = [
        ("First Contact", "Join your first team", "achievement_team.png", 10, "user"),
        ("Team Leader", "Create a new team", "achievement_leader.png", 20, "user"),
        ("Stellar Communicator", "Send 10 messages", "achievement_mail.png", 15, "user"),
        ("Cosmic Builder", "Participate in a building competition", "achievement_builder.png", 25, "user"),
        ("Galactic Dominance", "Win a team competition", "achievement_trophy.png", 50, "team"),
        ("Constellation", "Have at least 5 members in your team", "achievement_members.png", 30, "team")
    ]
    
    for achievement in achievements:
        cursor.execute(
            "INSERT INTO achievements (name, description, icon, points, achievement_type) VALUES (?, ?, ?, ?, ?)",
            achievement
        )
    
    print("Default achievements created successfully.")
    
    # Create a sample galaxy event
    cursor.execute(
        """
        INSERT INTO galaxy_events (name, description, start_date, end_date, event_type, points_multiplier, banner_image)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "Meteor Shower Weekend", 
            "Double star points for all activities during this cosmic event!",
            datetime.now().strftime("%Y-%m-%d 00:00:00"),
            datetime.now().strftime("%Y-%m-%d 23:59:59"),
            "meteor_shower",
            2.0,
            "meteor_shower_banner.jpg"
        )
    )
    
    print("Sample galaxy event created successfully.")
    
    # Commit changes and close connection
    conn.commit()
    conn.close()
    
    print(f"Database initialization complete. Database file: {DB_PATH}")

if __name__ == "__main__":
    init_db()
    print("You can now run your Flask application with the new database.") 