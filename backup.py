#!/usr/bin/env python
"""
Database Backup Utility

This script provides a command-line interface for managing database backups.
"""
import os
import sys
import argparse
from datetime import datetime

# Check if db_backup module exists
try:
    import db_backup
except ImportError:
    print("Error: db_backup module not found. Make sure the file is in the same directory.")
    sys.exit(1)

def print_header():
    """Print script header"""
    print("\n" + "=" * 60)
    print(" COSMIC TEAMS DATABASE BACKUP UTILITY ".center(60, "="))
    print("=" * 60 + "\n")

def print_success(message):
    """Print success message"""
    print(f"\033[92m✓ SUCCESS:\033[0m {message}")

def print_error(message):
    """Print error message"""
    print(f"\033[91m✗ ERROR:\033[0m {message}")

def print_info(message):
    """Print info message"""
    print(f"\033[94mℹ INFO:\033[0m {message}")

def create_backup(args):
    """Create a new backup"""
    print_info(f"Creating {args.type} backup...")
    
    success, result = db_backup.create_backup(args.type)
    
    if success:
        print_success(f"Backup created: {os.path.basename(result)}")
        print_info(f"Full path: {result}")
        print_info(f"Size: {os.path.getsize(result) // 1024} KB")
    else:
        print_error(f"Backup failed: {result}")
        return 1
    
    return 0

def list_backups(args):
    """List all available backups"""
    backups = db_backup.list_backups()
    
    if not backups:
        print_info("No backups found.")
        return 0
    
    print_info(f"Found {len(backups)} backups:\n")
    
    # Print table header
    print(f"{'ID':<3} | {'Type':<8} | {'Created At':<19} | {'Size':<10} | {'Filename'}")
    print("-" * 80)
    
    # Print table rows
    for idx, backup in enumerate(backups, 1):
        size_kb = backup.get('size', 0) // 1024
        print(f"{idx:<3} | {backup['type']:<8} | {backup.get('created_at', 'Unknown'):<19} | {size_kb:<8} KB | {backup['filename']}")
    
    print("\n" + "-" * 80)
    print_info("To restore a backup, use: python backup.py restore --id <ID>")
    
    return 0

def restore_backup(args):
    """Restore a backup"""
    if not args.id and not args.path:
        print_error("Either --id or --path must be specified")
        return 1
    
    if args.id:
        backups = db_backup.list_backups()
        if not backups:
            print_error("No backups found")
            return 1
        
        try:
            backup_id = int(args.id) - 1  # Convert to 0-based index
            if backup_id < 0 or backup_id >= len(backups):
                print_error(f"Invalid backup ID. Use a value between 1 and {len(backups)}")
                return 1
            
            backup_path = backups[backup_id]['path']
        except ValueError:
            print_error("Backup ID must be a number")
            return 1
    else:
        backup_path = args.path
        if not os.path.exists(backup_path):
            print_error(f"Backup file not found: {backup_path}")
            return 1
    
    print_info(f"Preparing to restore from: {os.path.basename(backup_path)}")
    print_info("This will REPLACE the current database with the backup.")
    print_info("A safety backup of the current database will be created.")
    
    if not args.yes:
        confirmation = input("\nAre you sure you want to proceed? [y/N]: ").lower()
        if confirmation != 'y':
            print_info("Restoration canceled")
            return 0
    
    print_info("Restoring database...")
    success, message = db_backup.restore_backup(backup_path)
    
    if success:
        print_success(f"Database restored successfully from {os.path.basename(backup_path)}")
    else:
        print_error(f"Restore failed: {message}")
        return 1
    
    return 0

def start_scheduler(args):
    """Start the backup scheduler"""
    print_info("Starting backup scheduler...")
    print_info("The scheduler will run in the background and create backups according to the schedule:")
    print_info("  - Daily backups: Every day at 3:00 AM")
    print_info("  - Weekly backups: Every Monday at 3:00 AM")
    print_info("  - Monthly backups: First day of each month at 3:00 AM")
    
    try:
        db_backup.start_scheduler()
        print_success("Scheduler started. Press Ctrl+C to stop.")
        
        try:
            # Keep the script running
            while True:
                import time
                time.sleep(60)
        except KeyboardInterrupt:
            print_info("Scheduler stopped")
    except Exception as e:
        print_error(f"Failed to start scheduler: {str(e)}")
        return 1
    
    return 0

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Cosmic Teams Database Backup Utility")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Create backup command
    create_parser = subparsers.add_parser("create", help="Create a new backup")
    create_parser.add_argument("--type", choices=["daily", "weekly", "monthly", "manual"],
                              default="manual", help="Backup type (default: manual)")
    
    # List backups command
    list_parser = subparsers.add_parser("list", help="List available backups")
    
    # Restore backup command
    restore_parser = subparsers.add_parser("restore", help="Restore a backup")
    restore_parser.add_argument("--id", help="Backup ID from the list command")
    restore_parser.add_argument("--path", help="Direct path to backup file")
    restore_parser.add_argument("--yes", "-y", action="store_true", 
                               help="Skip confirmation prompt")
    
    # Start scheduler command
    scheduler_parser = subparsers.add_parser("scheduler", help="Start the backup scheduler")
    
    args = parser.parse_args()
    
    # Print header
    print_header()
    
    # Execute the appropriate command
    if args.command == "create":
        return create_backup(args)
    elif args.command == "list":
        return list_backups(args)
    elif args.command == "restore":
        return restore_backup(args)
    elif args.command == "scheduler":
        return start_scheduler(args)
    else:
        parser.print_help()
        return 0

if __name__ == "__main__":
    sys.exit(main()) 