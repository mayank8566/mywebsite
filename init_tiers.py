#!/usr/bin/env python
"""
Tier System Initialization Script

This script initializes the tier system tables and migrates existing user tier data.
"""
import os
import sys
import sqlite3
from datetime import datetime

try:
    from tier_manager import TierManager
except ImportError:
    print("Error: tier_manager module not found.")
    print("Make sure tier_manager.py is in the same directory as this script.")
    sys.exit(1)

def main():
    """Main entry point for the initialization script"""
    print("\n" + "=" * 60)
    print(" COSMIC TEAMS TIER SYSTEM INITIALIZATION ".center(60, "="))
    print("=" * 60 + "\n")
    
    print("Step 1: Initializing tier system tables...")
    try:
        TierManager.initialize_tables()
        print("✅ Tables initialized successfully!")
    except Exception as e:
        print(f"❌ Error initializing tables: {str(e)}")
        return 1
    
    print("\nStep 2: Migrating existing user tier data...")
    try:
        TierManager.migrate_existing_user_tiers()
        print("✅ User tier data migrated successfully!")
    except Exception as e:
        print(f"❌ Error migrating tier data: {str(e)}")
        return 1
    
    print("\n✨ Tier system initialization complete! ✨")
    print("\nYou can now use the enhanced tier system in your application.")
    print("Features include:")
    print("  - Separate tables for tier definitions and user skills")
    print("  - Better organization and query capabilities")
    print("  - Extended metadata for skills and tiers")
    print("  - Backward compatibility with the existing system")
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 