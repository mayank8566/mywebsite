# CosmicTeams

A galaxy-themed web application for managing teams with beautiful animations and interactive features.

## Features

- User registration and authentication
- Personal profile pages with profile music
- Team creation and management
- Internal messaging system
- Skill tier system for Minecraft players
- Beautiful galaxy-themed animations and UI
- Admin dashboard

## Deployment on Render

This application is configured for automatic deployment on Render.

### Important Note About Database Storage

The application stores the database in a local folder called `data`. On Render's free tier, this directory is **ephemeral**, which means:

1. Data will be preserved between application restarts within the same deployment
2. Data will be **LOST** when a new deployment is made

To preserve your data between deployments on Render:

1. Use the application's built-in backup feature in the Admin Dashboard
2. Download your backups regularly
3. After a new deployment, use the restore feature to upload your latest backup

### How to deploy

1. Fork this repository to your GitHub account
2. Create a new Web Service on Render:
   - Connect your GitHub account
   - Select the forked repository
   - Render will automatically detect the `render.yaml` configuration
   - Click "Create Web Service"

### Continuous Deployment

The application is set up to automatically deploy whenever you push changes to the main branch of your GitHub repository:

1. Make changes to your code locally
2. Commit the changes to your local repository
3. Push the changes to your GitHub repository
4. Render will automatically detect the changes and redeploy your application

### Database Management

To keep your data safe across deployments:

- **Always create a backup before pushing code changes**
- **Download your backup files to your local machine**
- **After a new deployment, restore from your latest backup**

The Admin Dashboard includes a Database Management section where you can:
- Create database backups
- Restore the database from backups

### Recent Database Schema Changes

The application has been updated to handle team leadership differently:
- Previously, the teams table had a `leader_id` column
- Now, leadership is determined by the `is_leader` flag in the team_members table
- This change makes the database structure more flexible and avoids schema issues

If you're experiencing database errors after deployment:
1. Make sure you're using the latest code
2. Try initializing a fresh database (Admin > Reinitialize Database)
3. If you have a backup from before these changes, you may need to create a new database and manually recreate your data

## Local Development

To run the application locally:

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Run the application: `python run.py`

The application will be available at `http://localhost:5000`

## Troubleshooting

### Common Issues

1. **404 Not Found**: Make sure Nginx is configured correctly and the symbolic link exists.
2. **502 Bad Gateway**: Check if Gunicorn is running properly with `systemctl status cosmic_teams`.
3. **Database Errors**: Run `/admin/reinit-db` as an admin user to reinitialize the database.

### Logs

- Application logs: `/opt/cosmic_teams/logs/cosmic_teams.log`
- Gunicorn logs: `journalctl -u cosmic_teams`
- Nginx logs: `/var/log/nginx/access.log` and `/var/log/nginx/error.log`

## License

This project is licensed under the MIT License - see the LICENSE file for details. 