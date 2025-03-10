#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}CosmicTeams Deployment Script${NC}"
echo "This script will set up CosmicTeams for production"
echo

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root or with sudo${NC}" 
   exit 1
fi

# Install system dependencies
echo -e "${YELLOW}Installing system dependencies...${NC}"
apt-get update
apt-get install -y python3 python3-pip python3-venv nginx

# Create installation directory
echo -e "${YELLOW}Creating installation directory...${NC}"
INSTALL_DIR="/opt/cosmic_teams"
mkdir -p $INSTALL_DIR
cp -r . $INSTALL_DIR
cd $INSTALL_DIR

# Create virtual environment
echo -e "${YELLOW}Setting up Python virtual environment...${NC}"
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo -e "${YELLOW}Installing Python dependencies...${NC}"
pip install --upgrade pip
pip install -r requirements.txt

# Initialize database
echo -e "${YELLOW}Initializing database...${NC}"
python3 -c "from app import init_db; init_db()"

# Set up directory permissions
echo -e "${YELLOW}Setting up directory permissions...${NC}"
chown -R www-data:www-data $INSTALL_DIR
chmod -R 755 $INSTALL_DIR
mkdir -p $INSTALL_DIR/logs
chown -R www-data:www-data $INSTALL_DIR/logs

# Set up systemd service
echo -e "${YELLOW}Setting up systemd service...${NC}"
cp $INSTALL_DIR/cosmic_teams.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable cosmic_teams
systemctl start cosmic_teams

# Set up Nginx
echo -e "${YELLOW}Setting up Nginx...${NC}"
cp $INSTALL_DIR/cosmic_teams_nginx.conf /etc/nginx/sites-available/cosmic_teams
ln -sf /etc/nginx/sites-available/cosmic_teams /etc/nginx/sites-enabled/
systemctl restart nginx

echo -e "${GREEN}Deployment complete!${NC}"
echo "The CosmicTeams application should now be running."
echo "Please edit /etc/nginx/sites-available/cosmic_teams to configure your domain name."
echo "Then restart Nginx with: systemctl restart nginx"
echo
echo -e "${YELLOW}To view the application logs:${NC}"
echo "journalctl -u cosmic_teams"
echo
echo -e "${YELLOW}To view Nginx logs:${NC}"
echo "tail -f /var/log/nginx/access.log"
echo "tail -f /var/log/nginx/error.log" 