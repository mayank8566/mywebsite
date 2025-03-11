import os
import sqlite3
import shutil
import time
import json
import zipfile
import logging
from datetime import datetime
import schedule
import threading
import hashlib

# Get the application root directory
APP_ROOT = os.path.dirname(os.path.abspath(__file__))

# Check if running on Render
is_render = os.environ.get('RENDER') == 'true'

# Setup logging
# Use instance directory for logs
log_dir = os.path.join(APP_ROOT, 'instance', 'logs')
os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(log_dir, 'backup.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('backup_system')

# Configuration
# Use the same DB_PATH as in app.py
if is_render:
    DB_DIR = os.path.join(APP_ROOT, 'instance', 'data')
else:
    DB_DIR = os.path.join(APP_ROOT, 'data')

DB_PATH = os.path.join(DB_DIR, 'cosmic_teams.db')

# Use instance directory for backups
BACKUP_DIR = os.path.join(APP_ROOT, 'instance', 'backups')

MAX_DAILY_BACKUPS = 7     # Keep last 7 daily backups
MAX_WEEKLY_BACKUPS = 4    # Keep last 4 weekly backups
MAX_MONTHLY_BACKUPS = 12  # Keep last 12 monthly backups

# Ensure backup directories exist
if not os.path.exists(BACKUP_DIR):
    os.makedirs(BACKUP_DIR)
    os.makedirs(os.path.join(BACKUP_DIR, 'daily'))
    os.makedirs(os.path.join(BACKUP_DIR, 'weekly'))
    os.makedirs(os.path.join(BACKUP_DIR, 'monthly'))
    os.makedirs(os.path.join(BACKUP_DIR, 'manual'))

def calculate_file_hash(file_path):
    """Calculate SHA256 hash of a file to verify integrity"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def create_backup(backup_type='manual', with_schema=True):
    """Create a database backup with metadata and validation"""
    try:
        # Ensure source database exists
        if not os.path.exists(DB_PATH):
            logger.error(f"Database file {DB_PATH} does not exist")
            return False, "Database file not found"
        
        # Determine target directory and filename
        now = datetime.now()
        timestamp = now.strftime("%Y%m%d_%H%M%S")
        
        backup_subdir = os.path.join(BACKUP_DIR, backup_type)
        if not os.path.exists(backup_subdir):
            os.makedirs(backup_subdir)
            
        backup_filename = f"{backup_type}_backup_{timestamp}.zip"
        backup_path = os.path.join(backup_subdir, backup_filename)
        
        # Create a temporary copy of the database to back up
        temp_db_path = os.path.join(BACKUP_DIR, f"temp_{timestamp}.db")
        shutil.copy2(DB_PATH, temp_db_path)
        
        # Create metadata
        metadata = {
            "backup_type": backup_type,
            "timestamp": timestamp,
            "created_at": now.strftime("%Y-%m-%d %H:%M:%S"),
            "database_size": os.path.getsize(DB_PATH),
            "backup_hash": calculate_file_hash(temp_db_path)
        }
        
        # Add schema information if requested
        if with_schema:
            schema_data = {}
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()
            
            # Get all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            
            for table in tables:
                table_name = table[0]
                if table_name.startswith('sqlite_'):
                    continue  # Skip sqlite internal tables
                    
                # Get table schema
                cursor.execute(f"PRAGMA table_info({table_name})")
                columns = cursor.fetchall()
                
                # Get row count
                cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
                row_count = cursor.fetchone()[0]
                
                schema_data[table_name] = {
                    "columns": [{"name": col[1], "type": col[2]} for col in columns],
                    "row_count": row_count
                }
            
            conn.close()
            metadata["schema"] = schema_data
        
        # Create a zip file containing the database and metadata
        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Add the database file
            zipf.write(temp_db_path, os.path.basename(DB_PATH))
            
            # Add metadata file
            metadata_path = os.path.join(BACKUP_DIR, f"metadata_{timestamp}.json")
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=4)
            zipf.write(metadata_path, "backup_metadata.json")
            
            # Clean up temp files
            os.remove(metadata_path)
        
        # Cleanup
        os.remove(temp_db_path)
        
        # Verify backup integrity
        if os.path.exists(backup_path):
            backup_size = os.path.getsize(backup_path)
            logger.info(f"Backup created successfully: {backup_path} ({backup_size} bytes)")
            
            # Rotate old backups
            rotate_backups(backup_type)
            
            return True, backup_path
        else:
            logger.error("Backup file was not created")
            return False, "Backup creation failed"
            
    except Exception as e:
        logger.error(f"Backup failed: {str(e)}")
        return False, str(e)

def rotate_backups(backup_type):
    """Remove old backups to save space"""
    if backup_type == 'manual':
        return  # Don't rotate manual backups
        
    backup_subdir = os.path.join(BACKUP_DIR, backup_type)
    backups = [f for f in os.listdir(backup_subdir) if f.endswith('.zip')]
    backups.sort(reverse=True)  # Newest first
    
    max_backups = {
        'daily': MAX_DAILY_BACKUPS,
        'weekly': MAX_WEEKLY_BACKUPS,
        'monthly': MAX_MONTHLY_BACKUPS
    }.get(backup_type, 5)
    
    # Remove excess backups
    if len(backups) > max_backups:
        for old_backup in backups[max_backups:]:
            try:
                os.remove(os.path.join(backup_subdir, old_backup))
                logger.info(f"Removed old backup: {old_backup}")
            except Exception as e:
                logger.error(f"Failed to remove old backup {old_backup}: {str(e)}")

def restore_backup(backup_path):
    """Restore database from a backup file"""
    try:
        # Verify the backup file exists
        if not os.path.exists(backup_path):
            return False, "Backup file not found"
            
        # Create a backup of the current database before restoration
        create_backup(backup_type='pre_restore')
        
        # Extract the backup
        temp_dir = os.path.join(BACKUP_DIR, f"temp_restore_{int(time.time())}")
        os.makedirs(temp_dir, exist_ok=True)
        
        with zipfile.ZipFile(backup_path, 'r') as zipf:
            zipf.extractall(temp_dir)
        
        # Verify metadata
        metadata_path = os.path.join(temp_dir, "backup_metadata.json")
        if os.path.exists(metadata_path):
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
                logger.info(f"Restoring backup created at: {metadata.get('created_at')}")
        
        # Replace the current database with the backup
        extracted_db = os.path.join(temp_dir, os.path.basename(DB_PATH))
        if os.path.exists(extracted_db):
            # Stop the application if possible (this depends on your deployment)
            
            # Replace the database
            if os.path.exists(DB_PATH):
                os.remove(DB_PATH)
            shutil.copy2(extracted_db, DB_PATH)
            
            # Cleanup
            shutil.rmtree(temp_dir)
            
            logger.info(f"Database restored successfully from {backup_path}")
            return True, "Database restored successfully"
        else:
            return False, "Database file not found in backup"
    
    except Exception as e:
        logger.error(f"Restore failed: {str(e)}")
        return False, str(e)

def list_backups():
    """List all available backups with metadata"""
    backups = []
    
    for backup_type in ['daily', 'weekly', 'monthly', 'manual', 'pre_restore']:
        backup_subdir = os.path.join(BACKUP_DIR, backup_type)
        if not os.path.exists(backup_subdir):
            continue
            
        for filename in os.listdir(backup_subdir):
            if filename.endswith('.zip'):
                backup_path = os.path.join(backup_subdir, filename)
                
                # Extract metadata
                try:
                    with zipfile.ZipFile(backup_path, 'r') as zipf:
                        if "backup_metadata.json" in zipf.namelist():
                            with zipf.open("backup_metadata.json") as f:
                                metadata_content = f.read().decode('utf-8')
                                metadata = json.loads(metadata_content)
                                
                                backups.append({
                                    "filename": filename,
                                    "path": backup_path,
                                    "type": backup_type,
                                    "created_at": metadata.get("created_at"),
                                    "size": os.path.getsize(backup_path),
                                    "database_size": metadata.get("database_size")
                                })
                        else:
                            # Metadata not found, use file stats
                            created_time = os.path.getctime(backup_path)
                            backups.append({
                                "filename": filename,
                                "path": backup_path,
                                "type": backup_type,
                                "created_at": datetime.fromtimestamp(created_time).strftime("%Y-%m-%d %H:%M:%S"),
                                "size": os.path.getsize(backup_path),
                                "database_size": "Unknown"
                            })
                except Exception as e:
                    logger.error(f"Failed to extract metadata from {filename}: {str(e)}")
                    # Still add the backup to the list even if metadata extraction fails
                    created_time = os.path.getctime(backup_path)
                    backups.append({
                        "filename": filename,
                        "path": backup_path,
                        "type": backup_type,
                        "created_at": datetime.fromtimestamp(created_time).strftime("%Y-%m-%d %H:%M:%S"),
                        "size": os.path.getsize(backup_path),
                        "database_size": "Unknown"
                    })
    
    # Sort by creation time (newest first)
    backups.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return backups

def run_scheduled_backups():
    """Function to run scheduled backups"""
    logger.info("Running scheduled backup job")
    
    # Get current date info
    now = datetime.now()
    day_of_week = now.weekday()  # 0 is Monday, 6 is Sunday
    day_of_month = now.day
    
    # Determine backup type
    if day_of_month == 1:
        # First day of month - run monthly backup
        success, path = create_backup("monthly")
        logger.info(f"Monthly backup {'succeeded' if success else 'failed'}: {path}")
    elif day_of_week == 0:
        # Monday - run weekly backup
        success, path = create_backup("weekly")
        logger.info(f"Weekly backup {'succeeded' if success else 'failed'}: {path}")
    else:
        # Any other day - run daily backup
        success, path = create_backup("daily")
        logger.info(f"Daily backup {'succeeded' if success else 'failed'}: {path}")

# Setup scheduled jobs
def start_scheduler():
    """Start the scheduler thread to run automatic backups"""
    schedule.every().day.at("03:00").do(run_scheduled_backups)  # Run daily at 3 AM
    
    logger.info("Starting backup scheduler thread")
    
    def run_scheduler():
        while True:
            schedule.run_pending()
            time.sleep(60)
    
    # Start scheduler in a separate thread
    scheduler_thread = threading.Thread(target=run_scheduler)
    scheduler_thread.daemon = True
    scheduler_thread.start()

# Command-line interface for manual operation
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Database Backup System")
    parser.add_argument("action", choices=["backup", "restore", "list", "start_scheduler"],
                        help="Action to perform")
    parser.add_argument("--type", choices=["daily", "weekly", "monthly", "manual"],
                        default="manual", help="Backup type (for backup action)")
    parser.add_argument("--path", help="Backup file path (for restore action)")
    
    args = parser.parse_args()
    
    if args.action == "backup":
        success, path = create_backup(args.type)
        if success:
            print(f"Backup created successfully: {path}")
        else:
            print(f"Backup failed: {path}")
            
    elif args.action == "restore":
        if not args.path:
            print("Error: --path is required for restore action")
        else:
            success, message = restore_backup(args.path)
            print(message)
            
    elif args.action == "list":
        backups = list_backups()
        print(f"Found {len(backups)} backups:")
        for idx, backup in enumerate(backups, 1):
            print(f"{idx}. {backup['filename']} ({backup['type']})")
            print(f"   Created: {backup['created_at']}")
            print(f"   Size: {backup['size'] // 1024} KB")
            print(f"   DB Size: {backup.get('database_size', 'Unknown') // 1024 if isinstance(backup.get('database_size'), int) else 'Unknown'} KB")
            print()
            
    elif args.action == "start_scheduler":
        print("Starting backup scheduler in the background")
        start_scheduler()
        # Keep the main thread alive
        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            print("Scheduler stopped") 