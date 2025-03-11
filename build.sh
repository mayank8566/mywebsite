#!/usr/bin/env bash
# Exit on error
set -o errexit

# Create instance directory and subdirectories
mkdir -p instance/data
mkdir -p instance/logs
mkdir -p instance/uploads/profile_pics
mkdir -p instance/uploads/profile_music
mkdir -p instance/uploads/team_logos
mkdir -p instance/backups/daily
mkdir -p instance/backups/weekly
mkdir -p instance/backups/monthly
mkdir -p instance/backups/manual

# Set permissions
chmod -R 755 instance

# Print directory structure for debugging
echo "Directory structure:"
find instance -type d | sort

# Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Run database test to verify setup
python test_app.py

echo "Build completed successfully!" 