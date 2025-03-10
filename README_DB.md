# Galaxy Minecraft Database System

This document explains the database system for the Galaxy Minecraft website, including how to set it up and use it in your application.

## Overview

The Galaxy Minecraft database is built using SQLite with a comprehensive schema designed for a galaxy-themed Minecraft community website. The database includes tables for:

- Users with galaxy ranks and star points
- Teams with galaxy-themed attributes
- Team memberships and roles
- In-app messaging system
- Competitions and team participation
- Achievements for both users and teams
- Galaxy events with special bonuses
- Activity logging for users and teams
- Site-wide settings

## Setup Instructions

### 1. Initialize the Database

To create the database with the complete schema, run:

```bash
python init_db.py
```

This will:
- Create a new database file named `galaxy_minecraft.db`
- Create all necessary tables with proper relationships
- Add indexes for optimal performance
- Create an admin user (username: admin, password: admin123)
- Add default achievements
- Create a sample galaxy event

### 2. Database Utilities

The `db_utils.py` module provides a comprehensive set of functions to interact with the database. Import this module in your application code to use these functions:

```python
import db_utils

# Example: Get top teams
top_teams = db_utils.get_top_teams(limit=5)

# Example: Award an achievement to a user
db_utils.award_achievement(user_id=1, achievement_name="First Contact")
```

## Database Schema

### Users Table

The users table stores user information with galaxy-themed attributes:

- Basic user data (username, email, password)
- Admin status and permissions
- Profile information (bio, location, website)
- Galaxy rank and star points
- Minecraft skill tiers (nethpot, uhc, cpvp, sword, smp)

### Teams Table

The teams table stores team information with galaxy-themed attributes:

- Basic team data (name, description, logo)
- Team points and creation date
- Contact information (email, discord, website)
- Galaxy-themed fields (galaxy_name, constellation_type, star_color)

### Team Members Table

Links users to teams with roles and contribution tracking:

- Team and user relationship
- Leader status
- Role within the team
- Contribution points
- Join date

### Mail System

Provides in-app messaging between users:

- Sender and recipient
- Subject and content
- Read status
- Mail type (message, team_invite, etc.)
- Related entity ID (for special mail types)

### Competitions

Tracks competitions and team participation:

- Competition details (name, dates, rules)
- Team registrations
- Team scores and rankings

### Achievements

Tracks achievements for users and teams:

- Achievement definitions
- User achievement records
- Team achievement records

### Galaxy Events

Special timed events with bonuses:

- Event details (name, dates, type)
- Points multiplier
- Banner image

### Activity Logging

Tracks user and team activities:

- User activity log
- Team activity log

### Settings

Site-wide settings with different data types:

- String settings
- Integer settings
- Boolean settings

## Using the Database Utilities

### User Management

```python
# Get user by ID
user = db_utils.get_user(user_id)

# Get user by username
user = db_utils.get_user_by_username(username)

# Get all users
users = db_utils.get_all_users()

# Update user login time
db_utils.update_user_login(user_id)

# Add star points to a user (automatically updates galaxy rank)
db_utils.add_star_points(user_id, points)
```

### Team Management

```python
# Get team by ID
team = db_utils.get_team(team_id)

# Get top teams
top_teams = db_utils.get_top_teams(limit=5)

# Get user's teams
user_teams = db_utils.get_user_teams(user_id)

# Get team members
members = db_utils.get_team_members(team_id)
```

### Mail System

```python
# Get user's mail
mail = db_utils.get_user_mail(user_id)

# Get unread mail count
unread_count = db_utils.get_unread_mail_count(user_id)

# Send mail
mail_id = db_utils.send_mail(sender_id, recipient_id, subject, content)
```

### Competitions

```python
# Get active competitions
competitions = db_utils.get_active_competitions()

# Get teams in a competition
teams = db_utils.get_competition_teams(competition_id)
```

### Achievements

```python
# Get user achievements
achievements = db_utils.get_user_achievements(user_id)

# Get team achievements
achievements = db_utils.get_team_achievements(team_id)

# Award an achievement
db_utils.award_achievement(user_id=user_id, achievement_name="Achievement Name")
db_utils.award_achievement(team_id=team_id, achievement_name="Team Achievement Name")
```

### Activity Logging

```python
# Log user activity
db_utils.log_user_activity(user_id, "login", "User logged in")

# Log team activity
db_utils.log_team_activity(team_id, user_id, "member_added", "New member added to team")
```

### Settings

```python
# Get a setting
site_name = db_utils.get_setting("site_name", default="Galaxy Minecraft")

# Update a setting
db_utils.update_setting("site_name", "New Galaxy Minecraft")
```

### Galaxy Events

```python
# Get active galaxy events
events = db_utils.get_active_galaxy_events()

# Get current points multiplier
multiplier = db_utils.get_current_points_multiplier()
```

## Security Considerations

- All database queries use parameterized statements to prevent SQL injection
- Passwords are hashed using SHA-256 (consider using a stronger algorithm like bcrypt in production)
- Foreign key constraints ensure data integrity

## Performance Optimization

- Indexes are created on frequently queried columns
- Queries are optimized for common operations
- Connection pooling is not needed for SQLite, but connections are properly closed

## Extending the Database

To add new tables or columns:

1. Update the `schema.sql` file with your changes
2. Create a migration script or modify `init_db.py` to handle the changes
3. Add new utility functions to `db_utils.py` as needed

## Troubleshooting

If you encounter database issues:

1. Check that the database file exists and has the correct permissions
2. Verify that all required tables are created
3. Check for SQLite errors in your application logs
4. Use the SQLite command-line tool to inspect the database directly:
   ```bash
   sqlite3 galaxy_minecraft.db
   .tables
   .schema users
   ```

## Production Considerations

For a production environment:

1. Consider using a more robust database like PostgreSQL or MySQL
2. Implement proper backup procedures
3. Use a stronger password hashing algorithm
4. Implement connection pooling if needed
5. Add more comprehensive error handling and logging 