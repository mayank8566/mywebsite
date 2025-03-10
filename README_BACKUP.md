# Cosmic Teams Backup System

This document describes the backup system implemented for Cosmic Teams to prevent data loss and provide a robust recovery mechanism.

## Overview

The backup system automatically creates scheduled backups of the database and provides tools for administrators to create manual backups and restore from previous backups when needed.

## Features

- **Automated Scheduled Backups**:
  - Daily backups: Created every day at 3:00 AM, kept for 7 days
  - Weekly backups: Created every Monday at 3:00 AM, kept for 4 weeks
  - Monthly backups: Created on the 1st of each month at 3:00 AM, kept for 12 months

- **Manual Backups**:
  - Administrators can create manual backups at any time through the web interface
  - Manual backups are kept indefinitely and never automatically deleted

- **Backup Metadata**:
  - Each backup includes comprehensive metadata:
    - Creation timestamp
    - Backup type
    - Database size
    - SHA256 hash for integrity verification
    - Database schema information

- **Restore Capabilities**:
  - Restore from any backup via the admin interface
  - A safety backup is automatically created before restoration
  - Command-line restore capabilities for emergency recovery

- **Multiple Access Methods**:
  - Web UI for administrators
  - Command-line interface for system administrators
  - API for programmatic access

## Installation

The backup system is integrated with the main Cosmic Teams application. To ensure it works correctly:

1. Make sure all dependencies are installed:
   ```
   pip install -r requirements.txt
   ```

2. The `schedule` package is required for the backup scheduler to work. It should be included in the requirements.txt.

3. The backup system will automatically create the necessary directories for storing backups.

## Usage

### Web Interface

1. Log in as an administrator
2. Navigate to Admin > Database Backup
3. From this page, you can:
   - Create new backups
   - View all existing backups
   - Restore from a previous backup

### Command Line

The backup system includes a command-line utility (`backup.py`) for performing backup operations:

```
# Create a backup
python backup.py create [--type manual|daily|weekly|monthly]

# List all available backups
python backup.py list

# Restore from a backup
python backup.py restore --id <ID>
# or
python backup.py restore --path <path/to/backup.zip>

# Start the backup scheduler
python backup.py scheduler
```

### API

The backup system is accessible programmatically through the `db_backup` module:

```python
import db_backup

# Create a backup
success, path = db_backup.create_backup('manual')

# List backups
backups = db_backup.list_backups()

# Restore from a backup
success, message = db_backup.restore_backup('/path/to/backup.zip')

# Start the scheduler
db_backup.start_scheduler()
```

## Backup Storage

Backups are stored in the `backups/` directory, organized into subdirectories by type:

- `backups/daily/` - Daily backups
- `backups/weekly/` - Weekly backups
- `backups/monthly/` - Monthly backups
- `backups/manual/` - Manual backups
- `backups/pre_restore/` - Safety backups created before restoration

Each backup is a zip file containing:
- The database file
- A metadata.json file with information about the backup

## Best Practices

1. **Regular Verification**: Regularly verify that backups are being created as expected.

2. **Test Restoration**: Periodically test the restoration process to ensure backups are valid.

3. **Off-site Copies**: Consider copying important backups to an off-site location or cloud storage for disaster recovery.

4. **Document Restoration Procedures**: Make sure all administrators know how to restore from backups.

5. **Monitor Space**: Monitor the disk space used by backups to prevent filling up the server.

## Troubleshooting

If you encounter issues with the backup system:

1. Check the log file at `logs/backup.log` for error messages
2. Verify that the application has write permissions to the `backups/` directory
3. Ensure that the `schedule` package is installed
4. Restart the application to reinitialize the backup scheduler

## Backup Format

Each backup is a zip file containing:

1. **Database File**: A copy of the SQLite database
2. **Metadata File**: A JSON file with information about the backup:
   ```json
   {
     "backup_type": "manual",
     "timestamp": "20231016_120000",
     "created_at": "2023-10-16 12:00:00",
     "database_size": 1048576,
     "backup_hash": "sha256_hash_of_db_file",
     "schema": {
       "table_name": {
         "columns": [
           {"name": "column_name", "type": "column_type"}
         ],
         "row_count": 100
       }
     }
   }
   ```

## Security Considerations

1. Backups contain all database data, including sensitive information. Ensure that backup files are stored securely.
2. Set appropriate file permissions on the backup directory to prevent unauthorized access.
3. Consider encrypting backups if they contain particularly sensitive information.
4. Implement proper access controls for the admin backup interface. 