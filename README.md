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

This application is configured for automatic deployment on Render with persistent database storage.

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

### Database Persistence

The application uses a persistent disk on Render to store the SQLite database. This ensures that your data is preserved between deployments. 

The admin dashboard includes a Database Management section where you can:
- Create database backups
- Restore the database from backups

It's recommended to create regular backups, especially before major changes or deployments.

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