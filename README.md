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

## Production Deployment

### Option 1: Automated Deployment (Linux Only)

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/cosmic_teams.git
   cd cosmic_teams
   ```

2. Run the deployment script (requires root privileges):
   ```bash
   sudo ./deploy.sh
   ```

3. Configure your domain name in the Nginx configuration:
   ```bash
   sudo nano /etc/nginx/sites-available/cosmic_teams
   ```

4. Restart Nginx:
   ```bash
   sudo systemctl restart nginx
   ```

### Option 2: Manual Deployment

#### Prerequisites

- Python 3.8 or higher
- pip
- virtualenv or venv
- Nginx
- Gunicorn

#### Installation Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/cosmic_teams.git
   cd cosmic_teams
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Initialize the database:
   ```bash
   python -c "from app import init_db; init_db()"
   ```

5. Configure the systemd service:
   - Copy `cosmic_teams.service` to `/etc/systemd/system/`
   - Edit paths if needed to match your installation directory
   - Enable and start the service:
     ```bash
     sudo systemctl enable cosmic_teams
     sudo systemctl start cosmic_teams
     ```

6. Configure Nginx:
   - Copy `cosmic_teams_nginx.conf` to `/etc/nginx/sites-available/cosmic_teams`
   - Update the server_name to your domain
   - Create a symbolic link:
     ```bash
     sudo ln -s /etc/nginx/sites-available/cosmic_teams /etc/nginx/sites-enabled/
     ```
   - Restart Nginx:
     ```bash
     sudo systemctl restart nginx
     ```

7. (Optional) Set up SSL with Let's Encrypt:
   ```bash
   sudo apt-get install certbot python3-certbot-nginx
   sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
   ```

## Development Setup

For local development:

1. Clone the repository
2. Set up a virtual environment and install dependencies from `requirements.txt`
3. Run the application:
   ```bash
   python app.py
   ```
4. Visit http://localhost:5000 in your browser

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