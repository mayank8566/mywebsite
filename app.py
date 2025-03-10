from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import sqlite3
import os
import hashlib
import secrets
from functools import wraps
import base64
from datetime import datetime, timedelta
import logging
from logging.handlers import RotatingFileHandler

# Initialize Flask app
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Generate a random secret key

# Configure session to be more persistent
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # Sessions last for 7 days
app.config['SESSION_PERMANENT'] = True

# Database setup
DB_PATH = 'database.db'
UPLOAD_FOLDER = 'static/uploads/profile_pics'
UPLOAD_FOLDER_MUSIC = 'static/uploads/profile_music'
UPLOAD_FOLDER_TEAM_LOGOS = 'static/uploads/team_logos'

# Create upload directories if they don't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
if not os.path.exists(UPLOAD_FOLDER_MUSIC):
    os.makedirs(UPLOAD_FOLDER_MUSIC, exist_ok=True)
if not os.path.exists(UPLOAD_FOLDER_TEAM_LOGOS):
    os.makedirs(UPLOAD_FOLDER_TEAM_LOGOS, exist_ok=True)

# Set up logging for production
if not app.debug:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/cosmic_teams.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('CosmicTeams startup')

# Admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"  # This will be hashed before storage

# Helper functions
def hash_password(password):
    """Hash a password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def init_db():
    """Initialize database and tables"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create users table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        full_name TEXT,
        bio TEXT,
        location TEXT,
        website TEXT,
        profile_pic TEXT,
        profile_music TEXT,
        is_admin INTEGER DEFAULT 0,
        tier TEXT,
        nethpot_tier TEXT,
        nethpot_notes TEXT,
        uhc_tier TEXT,
        uhc_notes TEXT,
        cpvp_tier TEXT,
        cpvp_notes TEXT,
        sword_tier TEXT,
        sword_notes TEXT,
        smp_tier TEXT,
        smp_notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        can_create_team INTEGER DEFAULT 0,
        is_banned INTEGER DEFAULT 0,
        ban_reason TEXT
    )
    ''')
    
    # Create teams table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS teams (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        description TEXT,
        logo TEXT,
        rules TEXT,
        email TEXT,
        discord TEXT,
        website TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        points INTEGER DEFAULT 0
    )
    ''')
    
    # Create team_members table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS team_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        team_id INTEGER,
        user_id INTEGER,
        is_leader INTEGER DEFAULT 0,
        role TEXT DEFAULT 'member',
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (team_id) REFERENCES teams (id),
        FOREIGN KEY (user_id) REFERENCES users (id),
        UNIQUE(team_id, user_id)
    )
    ''')
    
    # Check if role column exists in team_members table
    try:
        cursor.execute("SELECT role FROM team_members LIMIT 1")
    except:
        # Add role column if it doesn't exist
        cursor.execute("ALTER TABLE team_members ADD COLUMN role TEXT DEFAULT 'member'")
    
    # Check if profile_music column exists in users table
    try:
        cursor.execute("SELECT profile_music FROM users LIMIT 1")
    except:
        # Add profile_music column if it doesn't exist
        cursor.execute("ALTER TABLE users ADD COLUMN profile_music TEXT")
        print("Added profile_music column to users table")
    
    # Check if updated_at column exists in users table
    try:
        cursor.execute("SELECT updated_at FROM users LIMIT 1")
    except:
        # Add updated_at column if it doesn't exist
        # SQLite doesn't allow DEFAULT CURRENT_TIMESTAMP when adding a column
        cursor.execute("ALTER TABLE users ADD COLUMN updated_at TIMESTAMP")
        # Update all existing rows to set updated_at to current time
        cursor.execute("UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL")
        print("Added updated_at column to users table")
    
    conn.commit()
    conn.close()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Generate a random secret key

# Configure session to be more persistent
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # Sessions last for 7 days
app.config['SESSION_PERMANENT'] = True

# Initialize database on startup
init_db()

def login_required(f):
    """Decorator to require login for certain routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin privileges for certain routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],))
        user = cursor.fetchone()
        conn.close()
        
        if not user or user[0] != 1:
            flash('You do not have permission to access this page', 'error')
            return redirect(url_for('index'))
        
        return f(*args, **kwargs)
    return decorated_function

def get_user(user_id):
    """Get user data from database"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # This enables column access by name
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    
    conn.close()
    
    return user

def get_all_users():
    """Get all users from database"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, username, email, full_name, is_admin, profile_pic,
               tier, nethpot_tier, uhc_tier, cpvp_tier, sword_tier, smp_tier
        FROM users ORDER BY username
    ''')
    users = cursor.fetchall()
    
    conn.close()
    
    return users

def save_profile_pic(file_data, username):
    """Save profile picture to filesystem and return the path"""
    if not file_data:
        return None
    
    # Ensure upload directory exists
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    
    # Create a unique filename
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = f"{username}_{timestamp}.jpg"
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    
    # Save the file
    file_data.save(file_path)
    
    # Return the relative path for storage in the database
    return f'uploads/profile_pics/{filename}'

def save_team_logo(file_data, team_name):
    """Save team logo to filesystem and return the path"""
    if not file_data:
        return None
    
    # Ensure upload directory exists
    team_logo_folder = 'static/uploads/team_logos'
    if not os.path.exists(team_logo_folder):
        os.makedirs(team_logo_folder, exist_ok=True)
    
    # Create a unique filename
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = f"{team_name.lower().replace(' ', '_')}_{timestamp}.jpg"
    file_path = os.path.join(team_logo_folder, filename)
    
    # Save the file
    file_data.save(file_path)
    
    # Return the relative path for storage in the database
    return f'uploads/team_logos/{filename}'

def get_user_team(user_id):
    """Get the team a user belongs to"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Use Row factory to access columns by name
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT t.*, 
               (SELECT COUNT(*) FROM team_members WHERE team_id = t.id) as member_count
        FROM teams t
        JOIN team_members tm ON t.id = tm.team_id
        WHERE tm.user_id = ?
    ''', (user_id,))
    
    team = cursor.fetchone()
    
    # Convert to dictionary if result exists
    result = dict(team) if team else None
    
    conn.close()
    
    return result

def get_team(team_id):
    """Get team by ID"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Use Row factory to access columns by name
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM teams WHERE id = ?', (team_id,))
    team = cursor.fetchone()
    
    # Convert to dictionary if result exists
    result = dict(team) if team else None
    
    conn.close()
    
    return result

def get_team_members(team_id):
    """Get all members of a team"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT u.id, u.username, u.email, u.full_name, u.profile_pic, 
               tm.joined_at, tm.is_leader
        FROM users u
        JOIN team_members tm ON u.id = tm.user_id
        WHERE tm.team_id = ?
        ORDER BY tm.is_leader DESC, u.username
    ''', (team_id,))
    
    members = cursor.fetchall()
    
    # Convert to list of dictionaries
    result = [dict(member) for member in members]
    
    conn.close()
    
    return result

def get_user_mail(user_id, mail_type=None, is_read=None, limit=20):
    """Get mail for a user with optional filters"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    query = '''
        SELECT m.*, 
               s.username as sender_username, s.profile_pic as sender_pic,
               r.username as recipient_username, r.profile_pic as recipient_pic
        FROM mail m
        JOIN users s ON m.sender_id = s.id
        JOIN users r ON m.recipient_id = r.id
        WHERE m.recipient_id = ?
    '''
    params = [user_id]
    
    if mail_type:
        query += ' AND m.mail_type = ?'
        params.append(mail_type)
    
    if is_read is not None:
        query += ' AND m.is_read = ?'
        params.append(1 if is_read else 0)
    
    query += ' ORDER BY m.sent_at DESC LIMIT ?'
    params.append(limit)
    
    cursor.execute(query, params)
    mail = cursor.fetchall()
    
    conn.close()
    return mail

def send_team_invitation(sender_id, recipient_id, team_id):
    """Send a team invitation to a user via in-app mail and email notification"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get sender info
    cursor.execute('SELECT username FROM users WHERE id = ?', (sender_id,))
    sender = cursor.fetchone()
    
    # Get recipient info
    cursor.execute('SELECT username, email FROM users WHERE id = ?', (recipient_id,))
    recipient = cursor.fetchone()
    
    # Get team info
    cursor.execute('SELECT name, description FROM teams WHERE id = ?', (team_id,))
    team = cursor.fetchone()
    
    if not sender or not recipient or not team:
        conn.close()
        return False
    
    # Create mail subject and content
    subject = f"Team Invitation: {team['name']}"
    content = f"""
    Hello {recipient['username']},
    
    You have been invited to join the team "{team['name']}" by {sender['username']}.
    
    Team Description:
    {team['description']}
    
    To accept or decline this invitation, please check your in-app mail.
    
    Best regards,
    The TeamSync Team
    """
    
    # Send in-app mail
    cursor.execute('''
        INSERT INTO mail (sender_id, recipient_id, subject, content, mail_type, related_id)
        VALUES (?, ?, ?, ?, 'team_invite', ?)
    ''', (sender_id, recipient_id, subject, content, team_id))
    
    mail_id = cursor.lastrowid
    
    conn.commit()
    conn.close()
    
    # Send email notification (in a real app, you would use an email service like SendGrid, Mailgun, etc.)
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        
        # In a real application, these would be environment variables
        SMTP_SERVER = "smtp.example.com"
        SMTP_PORT = 587
        SMTP_USERNAME = "notifications@teamsync.com"
        SMTP_PASSWORD = "your_password"
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = f"TeamSync <{SMTP_USERNAME}>"
        msg['To'] = recipient['email']
        msg['Subject'] = subject
        
        # Create HTML version of the message
        html_content = f"""
        <html>
        <head>
            <style>
                body {{ font-family: 'Arial', sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: #2c3e50; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 20px; background-color: #f9f9f9; }}
                .team-info {{ background-color: #fff; padding: 15px; border-radius: 5px; margin: 20px 0; }}
                .button {{ display: inline-block; padding: 10px 20px; background-color: #3498db; color: white; text-decoration: none; border-radius: 5px; }}
                .footer {{ text-align: center; margin-top: 20px; font-size: 0.8em; color: #777; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Team Invitation</h1>
                </div>
                <div class="content">
                    <p>Hello {recipient['username']},</p>
                    <p>You have been invited to join the team <strong>"{team['name']}"</strong> by <strong>{sender['username']}</strong>.</p>
                    
                    <div class="team-info">
                        <h3>Team Description:</h3>
                        <p>{team['description']}</p>
                    </div>
                    
                    <p>To accept or decline this invitation, please log in to your TeamSync account and check your in-app mail.</p>
                    
                    <p><a href="http://localhost:5000/mail" class="button">View Invitation</a></p>
                </div>
                <div class="footer">
                    <p>This is an automated message from TeamSync. Please do not reply to this email.</p>
                    <p>&copy; 2023 TeamSync. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Attach HTML content
        msg.attach(MIMEText(html_content, 'html'))
        
        # Connect to SMTP server and send email
        # Commented out to prevent actual email sending in this example
        """
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        """
        
        # For demonstration purposes, just print the email content
        print(f"Email would be sent to {recipient['email']} with subject: {subject}")
        
    except Exception as e:
        print(f"Error sending email: {e}")
    
    return mail_id

def get_unread_mail_count(user_id):
    """Get count of unread mail for a user"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM mail WHERE recipient_id = ? AND is_read = 0', (user_id,))
    count = cursor.fetchone()[0]
    
    conn.close()
    return count

def send_mail(sender_id, recipient_id, subject, content, mail_type='message', related_id=None):
    """Send a mail message from one user to another"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO mail (sender_id, recipient_id, subject, content, mail_type, related_id)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (sender_id, recipient_id, subject, content, mail_type, related_id))
    
    mail_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return mail_id

# Routes
@app.route('/')
def index():
    """Home page - redirect to main page"""
    return redirect(url_for('main'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login to the application"""
    if session.get('user_id'):
        return redirect(url_for('main'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember_me = request.form.get('remember_me') == 'on'
        
        if not username or not password:
            flash('Please provide both username and password', 'error')
            return render_template('login.html')
        
        # Hash the password for comparison
        hashed_password = hash_password(password)
        
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Check if user exists and password matches
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        
        # Check if user is banned
        if user and 'is_banned' in user.keys() and user['is_banned'] == 1:
            # Check if there's a ban reason in the database
            cursor.execute('SELECT ban_reason FROM users WHERE id = ? AND is_banned = 1', (user['id'],))
            ban_result = cursor.fetchone()
            ban_reason = ban_result['ban_reason'] if ban_result and 'ban_reason' in ban_result.keys() else 'Violation of community guidelines'
            
            conn.close()
            # Return template with ban message and reason
            return render_template('login.html', show_ban_popup=True, ban_username=user['username'], ban_reason=ban_reason)
            
        if user and user['password'] == hashed_password:
            # Set user session
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            
            # Set session to be permanent if remember_me is checked
            if remember_me:
                session.permanent = True
                app.permanent_session_lifetime = timedelta(days=30)  # Keep session for 30 days
            else:
                session.permanent = False
                app.permanent_session_lifetime = timedelta(days=1)  # Default session lifetime
                
            flash('Login successful!', 'success')
            
            # Get the next URL or default to main
            next_url = request.args.get('next', url_for('main'))
            return redirect(next_url)
        else:
            flash('Invalid username or password', 'error')
            
        conn.close()
    
    # Check if there are ban parameters in the URL
    show_ban_popup = request.args.get('show_ban_popup') == 'true'
    ban_username = request.args.get('ban_username', '')
    ban_reason = request.args.get('ban_reason', 'Violation of community guidelines')
    
    return render_template('login.html', 
                          show_ban_popup=show_ban_popup, 
                          ban_username=ban_username, 
                          ban_reason=ban_reason)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate input
        if not username or not email or not password or not confirm_password:
            flash('Please fill in all fields', 'error')
            return render_template('login.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('login.html')
        
        # Check if username or email already exists
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
        existing_user = cursor.fetchone()
        
        if existing_user:
            conn.close()
            flash('Username or email already exists', 'error')
            return render_template('login.html')
        
        # Insert new user
        hashed_password = hash_password(password)
        
        try:
            cursor.execute('''
            INSERT INTO users (username, email, password, profile_pic, bio, is_admin, can_create_team)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (username, email, hashed_password, 'default_avatar.png', 'New user', 0, 0))
            conn.commit()
            
            # Get the new user ID
            cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            
            conn.close()
            
            # Log in the new user
            session['user_id'] = user['id']
            session['username'] = username
            session['is_admin'] = 0
            session['can_create_team'] = 0
            
            flash('Registration successful!', 'success')
            return redirect(url_for('main'))
            
        except sqlite3.Error as e:
            conn.close()
            flash(f'Registration failed: {str(e)}', 'error')
            return render_template('login.html')
    
    # GET request - render login page with registration form
    return render_template('login.html')

@app.route('/main')
def main():
    """Render the main page with galaxy theme"""
    # Get user permissions
    can_create_team = False
    if session.get('user_id'):
        can_create_team = session.get('can_create_team', False)
    
    # Get top teams
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
    SELECT t.id, t.name, t.description, t.logo, t.points, COUNT(tm.user_id) as member_count, 
           u.username as leader_name
    FROM teams t
    LEFT JOIN team_members tm ON t.id = tm.team_id
    LEFT JOIN users u ON t.leader_id = u.id
    GROUP BY t.id
    ORDER BY t.points DESC
    LIMIT 6
    ''')
    
    top_teams = cursor.fetchall()
    
    conn.close()
    
    return render_template('main.html', top_teams=top_teams, can_create_team=can_create_team)

@app.route('/logout')
def logout():
    """Log out the user"""
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Redirect dashboard to profile page"""
    return redirect(url_for('profile'))

@app.route('/profile')
@login_required
def profile():
    """User profile page"""
    user_id = session.get('user_id')
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get user details
    cursor.execute('''
        SELECT id, username, email, password, is_admin, profile_pic, profile_music, bio, location, website, full_name, 
               tier, nethpot_tier, nethpot_notes, uhc_tier, uhc_notes, cpvp_tier, cpvp_notes, 
               sword_tier, sword_notes, smp_tier, smp_notes, can_create_team
        FROM users
        WHERE id = ?
    ''', (user_id,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        flash('User not found', 'error')
        return redirect(url_for('index'))
    
    # Get user's team information
    user_team = None
    is_team_leader = False
    
    cursor.execute('''
        SELECT t.id, t.name, t.description, t.logo, t.points, tm.is_leader,
               (SELECT COUNT(*) FROM team_members WHERE team_id = t.id) as member_count
        FROM teams t
        JOIN team_members tm ON t.id = tm.team_id
        WHERE tm.user_id = ?
    ''', (user_id,))
    team_data = cursor.fetchone()
    
    if team_data:
        user_team = dict(team_data)
        is_team_leader = team_data['is_leader'] == 1
    
    conn.close()
    
    message = session.pop('message', None)
    message_type = session.pop('message_type', 'info')
    
    return render_template('profile.html', 
                          user=user, 
                          user_team=user_team,
                          is_team_leader=is_team_leader,
                          message=message, 
                          message_type=message_type)

@app.route('/profile/update', methods=['POST'])
@login_required
def profile_update():
    """Update user profile information"""
    user_id = session.get('user_id')
    
    # Get form data
    full_name = request.form.get('full_name', '')
    bio = request.form.get('bio', '')
    location = request.form.get('location', '')
    website = request.form.get('website', '')
    tier = request.form.get('tier', 'none')
    
    # Get file uploads
    profile_pic_file = request.files.get('profile_pic')
    profile_music_file = request.files.get('profile_music')
    
    # Database connection
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # Get current user data
        cursor.execute('SELECT username, profile_pic, profile_music FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if not user:
            raise ValueError("User not found")
        
        username, current_pic, current_music = user
        
        # Process profile picture if uploaded
        profile_pic_path = current_pic
        if profile_pic_file and profile_pic_file.filename:
            try:
                profile_pic_path = save_profile_pic(profile_pic_file, username)
            except Exception as e:
                flash(f"Error saving profile picture: {str(e)}", "error")
        
        # Process profile music if uploaded
        profile_music_path = current_music
        if profile_music_file and profile_music_file.filename:
            try:
                profile_music_path = save_profile_music(profile_music_file, username)
            except Exception as e:
                flash(f"Error saving profile music: {str(e)}", "error")
        
        # Update user in database
        cursor.execute('''
            UPDATE users 
            SET full_name = ?, bio = ?, location = ?, website = ?, 
                profile_pic = ?, profile_music = ?, tier = ?, updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        ''', (full_name, bio, location, website, profile_pic_path, profile_music_path, tier, user_id))
        
        # Update Minecraft-specific tier information
        update_tier(cursor, user_id, "nethpot_tier", request.form.get("nethpot_tier"))
        update_tier(cursor, user_id, "nethpot_notes", request.form.get("nethpot_notes"))
        update_tier(cursor, user_id, "uhc_tier", request.form.get("uhc_tier"))
        update_tier(cursor, user_id, "uhc_notes", request.form.get("uhc_notes"))
        update_tier(cursor, user_id, "cpvp_tier", request.form.get("cpvp_tier"))
        update_tier(cursor, user_id, "cpvp_notes", request.form.get("cpvp_notes"))
        update_tier(cursor, user_id, "sword_tier", request.form.get("sword_tier"))
        update_tier(cursor, user_id, "sword_notes", request.form.get("sword_notes"))
        update_tier(cursor, user_id, "smp_tier", request.form.get("smp_tier"))
        update_tier(cursor, user_id, "smp_notes", request.form.get("smp_notes"))
        
        conn.commit()
        flash("Profile updated successfully!", "success")
        
    except Exception as e:
        conn.rollback()
        flash(f"Error updating profile: {str(e)}", "error")
    
    conn.close()
    return redirect(url_for('profile'))

@app.route('/profile/change-password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    # Validate input
    if not current_password or not new_password or not confirm_password:
        flash('All fields are required', 'error')
        return redirect(url_for('profile'))
    
    if new_password != confirm_password:
        flash('New passwords do not match', 'error')
        return redirect(url_for('profile'))
    
    # Check current password
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT password FROM users WHERE id = ?', (session.get('user_id'),))
    user = cursor.fetchone()
    
    if not user or user[0] != hash_password(current_password):
        conn.close()
        flash('Current password is incorrect', 'error')
        return redirect(url_for('profile'))
    
    # Update password
    try:
        hashed_password = hash_password(new_password)
        cursor.execute(
            'UPDATE users SET password = ? WHERE id = ?',
            (hashed_password, session.get('user_id'))
        )
        conn.commit()
        flash('Password changed successfully', 'success')
    except Exception as e:
        flash(f'Failed to change password: {str(e)}', 'error')
    
    conn.close()
    return redirect(url_for('profile'))

@app.route('/admin')
@admin_required
def admin_dashboard():
    """Admin dashboard page"""
    users = get_all_users()
    return render_template('admin.html', users=users)

@app.route('/admin/user/<int:user_id>')
@admin_required
def admin_view_user(user_id):
    """Admin view user details"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get user details
    cursor.execute('''
        SELECT id, username, email, is_admin, profile_pic, bio, location, website, full_name, can_create_team
        FROM users
        WHERE id = ?
    ''', (user_id,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        flash('User not found', 'error')
        return redirect(url_for('admin_dashboard'))
    
    # Get user's team information
    cursor.execute('''
        SELECT t.id, t.name, tm.is_leader
        FROM teams t
        JOIN team_members tm ON t.id = tm.team_id
        WHERE tm.user_id = ?
    ''', (user_id,))
    team_data = cursor.fetchone()
    
    user_team = None
    is_team_leader = False
    
    if team_data:
        user_team = {
            'id': team_data['id'],
            'name': team_data['name']
        }
        is_team_leader = team_data['is_leader'] == 1
    
    # Get all teams for the team leader assignment section
    cursor.execute('''
        SELECT t.id, t.name, t.description, t.points,
               (SELECT COUNT(*) FROM team_members WHERE team_id = t.id) as member_count
        FROM teams t
        ORDER BY t.name
    ''')
    all_teams = cursor.fetchall()
    
    conn.close()
    
    return render_template('admin_view_user.html', 
                          user=user, 
                          user_team=user_team, 
                          is_team_leader=is_team_leader,
                          all_teams=all_teams)

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    """Admin delete user"""
    # Don't allow deleting the admin user
    if user_id == session.get('user_id'):
        flash('You cannot delete your own admin account', 'error')
        return redirect(url_for('admin_dashboard'))
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get user profile pic path before deleting
    cursor.execute('SELECT profile_pic FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    
    try:
        # Delete user
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        
        # Delete profile picture if exists
        if user and user[0]:
            pic_path = os.path.join('static', user[0])
            if os.path.exists(pic_path):
                os.remove(pic_path)
        
        flash('User deleted successfully', 'success')
    except Exception as e:
        flash(f'Failed to delete user: {str(e)}', 'error')
    
    conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/user/<int:user_id>/toggle-admin', methods=['POST'])
@admin_required
def admin_toggle_admin(user_id):
    """Toggle admin status for a user"""
    # Don't allow removing admin status from yourself
    if user_id == session.get('user_id'):
        flash('You cannot remove your own admin status', 'error')
        return redirect(url_for('admin_dashboard'))
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get current admin status
    cursor.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        flash('User not found', 'error')
        return redirect(url_for('admin_dashboard'))
    
    # Toggle admin status
    new_status = 0 if user[0] == 1 else 1
    
    try:
        cursor.execute('UPDATE users SET is_admin = ? WHERE id = ?', (new_status, user_id))
        conn.commit()
        flash(f'User admin status updated successfully', 'success')
    except Exception as e:
        flash(f'Failed to update user admin status: {str(e)}', 'error')
    
    conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/user/<int:user_id>/toggle-team-creation', methods=['POST'])
@admin_required
def admin_toggle_team_creation(user_id):
    """Toggle a user's ability to create teams"""
    if user_id == session.get('user_id'):
        flash('You cannot modify your own team creation permissions', 'error')
        return redirect(url_for('admin_view_user', user_id=user_id))
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get current status
    cursor.execute("SELECT username, can_create_team FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        flash('User not found', 'error')
        return redirect(url_for('admin_dashboard'))
    
    username = user[0]
    current_status = user[1]
    
    # Toggle status
    new_status = 0 if current_status else 1
    cursor.execute("UPDATE users SET can_create_team = ? WHERE id = ?", (new_status, user_id))
    
    conn.commit()
    conn.close()
    
    action = "granted" if new_status else "revoked"
    flash(f'Team creation permission {action} for user {username}', 'success')
    
    return redirect(url_for('admin_view_user', user_id=user_id))

@app.route('/api/check-username', methods=['POST'])
def check_username():
    """API endpoint to check if a username is available"""
    username = request.json.get('username')
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    existing_user = cursor.fetchone()
    
    conn.close()
    
    return jsonify({'available': not existing_user})

@app.route('/api/check-email', methods=['POST'])
def check_email():
    """API endpoint to check if an email is available"""
    email = request.json.get('email')
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
    existing_email = cursor.fetchone()
    
    conn.close()
    
    return jsonify({'available': not existing_email})

# Team Routes
@app.route('/teams')
def teams():
    """View all teams"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get all teams with member count and leader name
    cursor.execute('''
        SELECT t.id, t.name, t.description, t.logo, t.points, t.leader_id, t.created_at,
               u.username as leader_name,
               (SELECT COUNT(*) FROM team_members WHERE team_id = t.id) as member_count
        FROM teams t
        LEFT JOIN users u ON t.leader_id = u.id
        ORDER BY t.points DESC
    ''')
    
    all_teams = cursor.fetchall()
    
    # Convert teams to list of dicts and get member IDs for each team
    teams_list = []
    for team in all_teams:
        team_dict = dict(team)
        
        # Get all members of this team
        cursor.execute('SELECT user_id FROM team_members WHERE team_id = ?', (team['id'],))
        members = cursor.fetchall()
        team_dict['member_ids'] = [member[0] for member in members]
        
        teams_list.append(team_dict)
    
    # Check if user can create teams
    can_create_team = False
    if session.get('user_id'):
        cursor.execute('SELECT can_create_team FROM users WHERE id = ?', (session.get('user_id'),))
        result = cursor.fetchone()
        can_create_team = result and result['can_create_team'] == 1
    
    # Get unread mail count for the user
    unread_mail_count = 0
    if session.get('user_id'):
        unread_mail_count = get_unread_mail_count(session.get('user_id'))
    
    conn.close()
    
    return render_template('teams.html', 
                          teams=teams_list,
                          can_create_team=can_create_team,
                          unread_mail_count=unread_mail_count)

@app.route('/teams/create', methods=['GET', 'POST'])
@login_required
def create_team():
    """Create a new team (admin or authorized users only)"""
    # Get user information
    user_id = session.get('user_id')
    if not user_id:
        flash('You must be logged in to create a team', 'error')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # Check if user is admin or has permission to create teams
        cursor.execute("SELECT is_admin, can_create_team FROM users WHERE id = ?", (user_id,))
        user_data = cursor.fetchone()
        
        if not user_data:
            conn.close()
            flash('User not found', 'error')
            return redirect(url_for('teams'))
        
        if not user_data['is_admin'] and not user_data['can_create_team']:
            conn.close()
            flash('You do not have permission to create teams', 'error')
            return redirect(url_for('teams'))
        
        # Check if user is already a leader of another team
        cursor.execute('''
            SELECT t.id, t.name FROM teams t
            JOIN team_members tm ON t.id = tm.team_id
            WHERE tm.user_id = ? AND tm.is_leader = 1
        ''', (user_id,))
        existing_team = cursor.fetchone()
        
        if existing_team and not user_data['is_admin']:  # Not admin
            conn.close()
            flash(f'You are already a leader of team "{existing_team["name"]}". You can only lead one team at a time.', 'error')
            return redirect(url_for('view_team', team_id=existing_team["id"]))
        
        if request.method == 'POST':
            try:
                team_name = request.form.get('team_name')
                description = request.form.get('description')
                team_logo = request.files.get('team_logo')
                
                if not team_name or not description:
                    flash('Team name and description are required', 'error')
                    return redirect(url_for('create_team'))
                
                # Check if team name already exists
                cursor.execute('SELECT id FROM teams WHERE name = ?', (team_name,))
                if cursor.fetchone():
                    conn.close()
                    flash('Team name already exists', 'error')
                    return redirect(url_for('create_team'))
                
                # Save team logo if provided
                logo_path = None
                if team_logo and team_logo.filename:
                    logo_path = save_team_logo(team_logo, team_name)
                
                # Create the team
                cursor.execute('''
                    INSERT INTO teams (name, description, logo, points)
                    VALUES (?, ?, ?, ?)
                ''', (team_name, description, logo_path, 0))
                
                team_id = cursor.lastrowid
                
                # Add the current user as the team leader
                cursor.execute('''
                    INSERT INTO team_members (team_id, user_id, is_leader)
                    VALUES (?, ?, 1)
                ''', (team_id, user_id))
                
                conn.commit()
                
                # Update session to reflect changes
                session.modified = True
                
                flash('Team created successfully! You are now the team leader.', 'success')
                return redirect(url_for('view_team', team_id=team_id))
            except Exception as e:
                conn.rollback()
                flash(f'Error creating team: {str(e)}', 'error')
                return redirect(url_for('create_team'))
        
        conn.close()
        return render_template('create_team.html')
    
    except Exception as e:
        conn.close()
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('teams'))

@app.route('/teams/<int:team_id>')
@login_required
def view_team(team_id):
    """View team details"""
    user_id = session.get('user_id')
    if not user_id:
        flash('You must be logged in to view team details', 'error')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # Get team details
        cursor.execute('''
            SELECT t.* 
            FROM teams t
            WHERE t.id = ?
        ''', (team_id,))
        team = cursor.fetchone()
        
        if not team:
            conn.close()
            flash('Team not found', 'error')
            return redirect(url_for('teams'))
        
        # Get team members
        cursor.execute('''
            SELECT u.id, u.username, u.profile_pic, u.full_name, tm.is_leader
            FROM users u
            JOIN team_members tm ON u.id = tm.user_id
            WHERE tm.team_id = ?
            ORDER BY tm.is_leader DESC, u.username
        ''', (team_id,))
        members_result = cursor.fetchall()
        
        # Convert members to list of dictionaries
        members = [dict(member) for member in members_result]
        
        # Check if user is a team leader
        cursor.execute('''
            SELECT is_leader FROM team_members 
            WHERE team_id = ? AND user_id = ?
        ''', (team_id, user_id))
        member_data = cursor.fetchone()
        is_leader = member_data and member_data['is_leader'] == 1
        
        # Check if user is admin
        is_admin = session.get('is_admin', False)
        
        # Check if user is a member of this team
        is_member = member_data is not None
        
        # Get member count
        cursor.execute('SELECT COUNT(*) as count FROM team_members WHERE team_id = ?', (team_id,))
        member_count = cursor.fetchone()['count']
        
        # Add member count to team data
        team_dict = dict(team)
        team_dict['member_count'] = member_count
        
        # Log the leadership status for debugging
        print(f"User {user_id} is_leader: {is_leader}, is_admin: {is_admin}, is_member: {is_member}")
        
        conn.close()
        
        return render_template('view_team.html', 
                              team=team_dict, 
                              members=members, 
                              is_leader=is_leader,
                              is_admin=is_admin,
                              is_member=is_member)
    
    except Exception as e:
        conn.close()
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('teams'))

@app.route('/teams/<int:team_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_team(team_id):
    """Edit team details (leader or admin only)"""
    team = get_team(team_id)
    if not team:
        flash('Team not found', 'error')
        return redirect(url_for('teams'))
    
    # Check if user is team leader or admin
    is_leader = team[6] == session.get('user_id')  # team[6] is leader_id
    is_admin = session.get('is_admin', False)
    
    if not (is_leader or is_admin):
        flash('You do not have permission to edit this team', 'error')
        return redirect(url_for('view_team', team_id=team_id))
    
    if request.method == 'POST':
        team_name = request.form.get('team_name')
        description = request.form.get('description')
        points = request.form.get('points')
        team_logo = request.files.get('team_logo')
        
        if not team_name:
            flash('Team name is required', 'error')
            return redirect(url_for('edit_team', team_id=team_id))
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if team name already exists (for another team)
        cursor.execute('SELECT id FROM teams WHERE name = ? AND id != ?', (team_name, team_id))
        if cursor.fetchone():
            conn.close()
            flash('Team name already exists', 'error')
            return redirect(url_for('edit_team', team_id=team_id))
        
        # Save team logo if provided
        logo_path = team[3]  # Keep existing logo path
        if team_logo and team_logo.filename:
            logo_path = save_team_logo(team_logo, team_name)
        
        # Update the team
        cursor.execute('''
            UPDATE teams
            SET name = ?, description = ?, logo = ?, points = ?
            WHERE id = ?
        ''', (team_name, description, logo_path, points, team_id))
        
        conn.commit()
        conn.close()
        
        flash('Team updated successfully', 'success')
        return redirect(url_for('view_team', team_id=team_id))
    
    # Convert team tuple to dict for easier template access
    team_dict = {
        'id': team[0],
        'name': team[1],
        'description': team[2],
        'logo': team[3],
        'points': team[4],
        'created_at': team[5],
        'leader_id': team[6]
    }
    
    return render_template('edit_team.html', team=team_dict, is_admin=is_admin)

@app.route('/teams/<int:team_id>/invite', methods=['GET', 'POST'])
@login_required
def invite_to_team(team_id):
    """Invite a user to join a team (team leaders only)"""
    user_id = session.get('user_id')
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Check if team exists
    cursor.execute('SELECT * FROM teams WHERE id = ?', (team_id,))
    team = cursor.fetchone()
    
    if not team:
        conn.close()
        flash('Team not found', 'error')
        return redirect(url_for('teams'))
    
    # Check if user is a team leader
    cursor.execute('''
        SELECT is_leader FROM team_members 
        WHERE team_id = ? AND user_id = ? AND is_leader = 1
    ''', (team_id, user_id))
    is_leader = cursor.fetchone() is not None
    
    # Only team leaders can invite users
    if not is_leader and not session.get('is_admin'):
        conn.close()
        flash('Only team leaders can invite users to join the team', 'error')
        return redirect(url_for('view_team', team_id=team_id))
    
    if request.method == 'POST':
        # Get user_id from form (from search results)
        recipient_id = request.form.get('user_id')
        
        if not recipient_id:
            conn.close()
            flash('User ID is required', 'error')
            return redirect(url_for('search_users_for_team', team_id=team_id))
        
        # Check if user exists
        cursor.execute('SELECT username FROM users WHERE id = ?', (recipient_id,))
        user_to_invite = cursor.fetchone()
        
        if not user_to_invite:
            conn.close()
            flash('User not found', 'error')
            return redirect(url_for('search_users_for_team', team_id=team_id))
        
        username = user_to_invite['username']
        
        # Check if user is already in the team
        cursor.execute('SELECT id FROM team_members WHERE team_id = ? AND user_id = ?', (team_id, recipient_id))
        if cursor.fetchone():
            conn.close()
            flash(f'User {username} is already a member of this team', 'error')
            return redirect(url_for('search_users_for_team', team_id=team_id))
        
        # Check if invitation already sent
        cursor.execute('''
            SELECT id FROM mail 
            WHERE sender_id = ? AND recipient_id = ? AND mail_type = 'team_invite' AND related_id = ?
            AND id NOT IN (
                SELECT mail_id FROM team_invite_responses WHERE mail_id = mail.id
            )
        ''', (user_id, recipient_id, team_id))
        
        if cursor.fetchone():
            conn.close()
            flash(f'An invitation has already been sent to {username}', 'info')
            return redirect(url_for('search_users_for_team', team_id=team_id))
        
        # Send team invitation
        send_team_invitation(user_id, recipient_id, team_id)
        
        conn.close()
        flash(f'Invitation sent to {username}', 'success')
        return redirect(url_for('search_users_for_team', team_id=team_id))
    
    # If GET request, redirect to search page
    conn.close()
    return redirect(url_for('search_users_for_team', team_id=team_id))

@app.route('/teams/<int:team_id>/leave', methods=['POST'])
@login_required
def leave_team(team_id):
    """Leave a team (members only, not for leaders)"""
    team = get_team(team_id)
    if not team:
        flash('Team not found', 'error')
        return redirect(url_for('teams'))
    
    user_id = session.get('user_id')
    
    # Leaders can't leave their team
    if team[6] == user_id:  # team[6] is leader_id
        flash('Team leaders cannot leave their team. Transfer leadership first or delete the team.', 'error')
        return redirect(url_for('view_team', team_id=team_id))
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Remove user from team
    cursor.execute('DELETE FROM team_members WHERE team_id = ? AND user_id = ?', (team_id, user_id))
    conn.commit()
    conn.close()
    
    flash('You have left the team', 'success')
    return redirect(url_for('teams'))

@app.route('/teams/<int:team_id>/remove/<int:user_id>', methods=['POST'])
@login_required
def remove_from_team(team_id, user_id):
    """Remove a user from a team (leader or admin only)"""
    team = get_team(team_id)
    if not team:
        flash('Team not found', 'error')
        return redirect(url_for('teams'))
    
    # Check if user is team leader or admin
    is_leader = team[6] == session.get('user_id')  # team[6] is leader_id
    is_admin = session.get('is_admin', False)
    
    if not (is_leader or is_admin):
        flash('You do not have permission to remove members', 'error')
        return redirect(url_for('view_team', team_id=team_id))
    
    # Leaders can't be removed
    if user_id == team[6]:
        flash('Team leaders cannot be removed', 'error')
        return redirect(url_for('view_team', team_id=team_id))
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Remove user from team
    cursor.execute('DELETE FROM team_members WHERE team_id = ? AND user_id = ?', (team_id, user_id))
    conn.commit()
    conn.close()
    
    flash('Member removed from team', 'success')
    return redirect(url_for('view_team', team_id=team_id))

@app.route('/teams/<int:team_id>/delete', methods=['POST'])
@login_required
def delete_team(team_id):
    """Delete a team"""
    user_id = session.get('user_id')
    is_admin = session.get('is_admin', 0)
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # Check if user is the team leader or an admin
        cursor.execute('''
            SELECT is_leader FROM team_members 
            WHERE team_id = ? AND user_id = ?
        ''', (team_id, user_id))
        
        is_leader_result = cursor.fetchone()
        is_leader = is_leader_result and is_leader_result['is_leader'] == 1
        
        if not (is_leader or is_admin):
            conn.close()
            flash('You do not have permission to delete this team', 'error')
            return redirect(url_for('view_team', team_id=team_id))
        
        # Get team name for the flash message
        cursor.execute('SELECT name FROM teams WHERE id = ?', (team_id,))
        team = cursor.fetchone()
        if not team:
            conn.close()
            flash('Team not found', 'error')
            return redirect(url_for('teams'))
        
        team_name = team['name']
        
        # Check if the team_invitations table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='team_invitations'")
        team_invitations_exists = cursor.fetchone() is not None
        
        # Check if mail table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='mail'")
        mail_table_exists = cursor.fetchone() is not None
        
        # Get the mail table structure if it exists
        mail_columns = []
        if mail_table_exists:
            cursor.execute("PRAGMA table_info(mail)")
            mail_columns = [col['name'] for col in cursor.fetchall()]
        
        # Delete all related records in proper order to maintain database integrity
        
        # 1. Delete team invitations and related mails if tables exist
        if mail_table_exists:
            # Delete team invitation mails - only use basic query without JSON extraction
            cursor.execute('DELETE FROM mail WHERE mail_type = ? AND related_id = ?', 
                          ('team_invite', team_id))
        
        if team_invitations_exists:
            # Delete team invitations
            cursor.execute('DELETE FROM team_invitations WHERE team_id = ?', (team_id,))
        
        # 2. Delete team members
        cursor.execute('DELETE FROM team_members WHERE team_id = ?', (team_id,))
        
        # 3. Delete team
        cursor.execute('DELETE FROM teams WHERE id = ?', (team_id,))
        
        conn.commit()
        flash(f'Team "{team_name}" has been deleted successfully', 'success')
        
    except Exception as e:
        conn.rollback()
        flash(f'Error deleting team: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('teams'))

# Mail Routes
@app.route('/mail')
@login_required
def mail_inbox():
    """User's mail inbox"""
    user_id = session.get('user_id')
    
    # Get all mail for the user
    mail = get_user_mail(user_id)
    
    return render_template('mail_inbox.html', mail=mail)

@app.route('/mail/sent')
@login_required
def mail_sent():
    """User's sent mail"""
    user_id = session.get('user_id')
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT m.*, 
               s.username as sender_username, s.profile_pic as sender_pic,
               r.username as recipient_username, r.profile_pic as recipient_pic
        FROM mail m
        JOIN users s ON m.sender_id = s.id
        JOIN users r ON m.recipient_id = r.id
        WHERE m.sender_id = ?
        ORDER BY m.sent_at DESC LIMIT 20
    ''', (user_id,))
    
    sent_mail = cursor.fetchall()
    conn.close()
    
    return render_template('mail_sent.html', mail=sent_mail)

@app.route('/mail/compose', methods=['GET', 'POST'])
@login_required
def mail_compose():
    """Compose a new mail message"""
    if request.method == 'POST':
        recipient_username = request.form.get('recipient')
        subject = request.form.get('subject')
        content = request.form.get('content')
        
        if not recipient_username or not subject or not content:
            flash('All fields are required', 'error')
            return redirect(url_for('mail_compose'))
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Find the recipient
        cursor.execute('SELECT id FROM users WHERE username = ?', (recipient_username,))
        recipient = cursor.fetchone()
        
        if not recipient:
            conn.close()
            flash('Recipient not found', 'error')
            return redirect(url_for('mail_compose'))
        
        recipient_id = recipient[0]
        conn.close()
        
        # Send the mail
        send_mail(session.get('user_id'), recipient_id, subject, content)
        
        flash('Message sent successfully', 'success')
        return redirect(url_for('mail_inbox'))
    
    # Pre-fill recipient if provided in query string
    recipient = request.args.get('to', '')
    subject = request.args.get('subject', '')
    
    return render_template('mail_compose.html', recipient=recipient, subject=subject)

@app.route('/mail/<int:mail_id>')
@login_required
def view_mail(mail_id):
    """View a single mail message"""
    user_id = session.get('user_id')
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get the mail and check if user is sender or recipient
    cursor.execute('''
        SELECT m.*, 
               s.username as sender_username, s.profile_pic as sender_pic,
               r.username as recipient_username, r.profile_pic as recipient_pic
        FROM mail m
        JOIN users s ON m.sender_id = s.id
        JOIN users r ON m.recipient_id = r.id
        WHERE m.id = ? AND (m.sender_id = ? OR m.recipient_id = ?)
    ''', (mail_id, user_id, user_id))
    
    mail = cursor.fetchone()
    
    if not mail:
        conn.close()
        flash('Message not found or you do not have permission to view it', 'error')
        return redirect(url_for('mail_inbox'))
    
    # Mark as read if user is recipient
    if mail['recipient_id'] == user_id and mail['is_read'] == 0:
        cursor.execute('UPDATE mail SET is_read = 1 WHERE id = ?', (mail_id,))
        conn.commit()
    
    conn.close()
    
    return render_template('view_mail.html', mail=mail)

@app.route('/mail/<int:mail_id>/delete', methods=['POST'])
@login_required
def delete_mail(mail_id):
    """Delete a mail message"""
    user_id = session.get('user_id')
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check if user is sender or recipient
    cursor.execute('''
        SELECT id FROM mail 
        WHERE id = ? AND (sender_id = ? OR recipient_id = ?)
    ''', (mail_id, user_id, user_id))
    
    if not cursor.fetchone():
        conn.close()
        flash('Message not found or you do not have permission to delete it', 'error')
        return redirect(url_for('mail_inbox'))
    
    # Delete the mail
    cursor.execute('DELETE FROM mail WHERE id = ?', (mail_id,))
    conn.commit()
    conn.close()
    
    flash('Message deleted successfully', 'success')
    return redirect(url_for('mail_inbox'))

@app.route('/mail/team-invite/<int:mail_id>/accept', methods=['POST'])
@login_required
def accept_team_invite(mail_id):
    """Accept a team invitation"""
    user_id = session.get('user_id')
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get the invitation
    cursor.execute('''
        SELECT * FROM mail 
        WHERE id = ? AND recipient_id = ? AND mail_type = 'team_invite'
    ''', (mail_id, user_id))
    
    invite = cursor.fetchone()
    
    if not invite:
        conn.close()
        flash('Invitation not found or already processed', 'error')
        return redirect(url_for('mail_inbox'))
    
    team_id = invite[7]  # related_id column
    
    # Check if user is already in a team
    cursor.execute('SELECT team_id FROM team_members WHERE user_id = ?', (user_id,))
    if cursor.fetchone():
        conn.close()
        flash('You are already a member of a team', 'error')
        return redirect(url_for('mail_inbox'))
    
    # Add user to the team
    cursor.execute('INSERT INTO team_members (team_id, user_id) VALUES (?, ?)', (team_id, user_id))
    
    # Mark invitation as read
    cursor.execute('UPDATE mail SET is_read = 1 WHERE id = ?', (mail_id,))
    
    # Record the response in team_invite_responses
    cursor.execute('INSERT INTO team_invite_responses (mail_id, response) VALUES (?, ?)', 
                  (mail_id, 'accepted'))
    
    conn.commit()
    conn.close()
    
    flash('You have joined the team', 'success')
    return redirect(url_for('view_team', team_id=team_id))

@app.route('/mail/team-invite/<int:mail_id>/decline', methods=['POST'])
@login_required
def decline_team_invite(mail_id):
    """Decline a team invitation"""
    user_id = session.get('user_id')
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get the invitation
    cursor.execute('''
        SELECT * FROM mail 
        WHERE id = ? AND recipient_id = ? AND mail_type = 'team_invite'
    ''', (mail_id, user_id))
    
    invite = cursor.fetchone()
    
    if not invite:
        conn.close()
        flash('Invitation not found or already processed', 'error')
        return redirect(url_for('mail_inbox'))
    
    # Mark invitation as read
    cursor.execute('UPDATE mail SET is_read = 1 WHERE id = ?', (mail_id,))
    
    # Record the response in team_invite_responses
    cursor.execute('INSERT INTO team_invite_responses (mail_id, response) VALUES (?, ?)', 
                  (mail_id, 'declined'))
    
    conn.commit()
    conn.close()
    
    flash('You have declined the team invitation', 'success')
    return redirect(url_for('mail_inbox'))

# Update base context to include unread mail count
@app.context_processor
def inject_unread_mail_count():
    """Add unread mail count to all templates"""
    if 'user_id' in session:
        return {'unread_mail_count': get_unread_mail_count(session.get('user_id'))}
    return {'unread_mail_count': 0}

# Custom error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

@app.route('/admin/user/<int:user_id>/make-team-leader/<int:team_id>', methods=['POST'])
@admin_required
def admin_make_team_leader(user_id, team_id):
    """Make a user a team leader for a specific team"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check if user exists
    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        flash('User not found', 'error')
        return redirect(url_for('admin_dashboard'))
    
    username = user[0]
    
    # Check if team exists
    cursor.execute("SELECT name FROM teams WHERE id = ?", (team_id,))
    team = cursor.fetchone()
    
    if not team:
        conn.close()
        flash('Team not found', 'error')
        return redirect(url_for('admin_view_user', user_id=user_id))
    
    team_name = team[0]
    
    # Check if user is a member of the team
    cursor.execute("SELECT id FROM team_members WHERE team_id = ? AND user_id = ?", (team_id, user_id))
    is_member = cursor.fetchone()
    
    if not is_member:
        # Add user to the team as a leader
        cursor.execute("INSERT INTO team_members (team_id, user_id, is_leader) VALUES (?, ?, 1)", (team_id, user_id))
        action = "added to"
    else:
        # Update user to be a leader
        cursor.execute("UPDATE team_members SET is_leader = 1 WHERE team_id = ? AND user_id = ?", (team_id, user_id))
        action = "updated as leader in"
    
    # Remove leader status from other members of this team
    cursor.execute("UPDATE team_members SET is_leader = 0 WHERE team_id = ? AND user_id != ?", (team_id, user_id))
    
    conn.commit()
    conn.close()
    
    flash(f'User {username} has been {action} team {team_name} as leader', 'success')
    return redirect(url_for('admin_view_user', user_id=user_id))

@app.route('/teams/<int:team_id>/search_users', methods=['GET', 'POST'])
@login_required
def search_users_for_team(team_id):
    """Search for users to invite to a team"""
    try:
        user_id = session.get('user_id')
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Check if team exists
        cursor.execute('SELECT * FROM teams WHERE id = ?', (team_id,))
        team = cursor.fetchone()
        
        if not team:
            conn.close()
            flash('Team not found', 'error')
            return redirect(url_for('teams'))

        # Check if user is a team leader or admin
        cursor.execute('''
            SELECT is_leader FROM team_members
            WHERE team_id = ? AND user_id = ? AND is_leader = 1
        ''', (team_id, user_id))
        is_leader = cursor.fetchone() is not None

        if not is_leader and not session.get('is_admin'):
            conn.close()
            flash('Only team leaders can invite users to join the team', 'error')
            return redirect(url_for('view_team', team_id=team_id))

        search_results = []
        search_term = ''
        recently_invited = []

        if request.method == 'POST':
            # Check if inviting by exact username
            exact_username = request.form.get('exact_username')
            if exact_username:
                # Find user by exact username
                cursor.execute('''
                    SELECT id, username, email, full_name, profile_pic FROM users
                    WHERE username = ? AND id NOT IN (
                        SELECT user_id FROM team_members WHERE team_id = ?
                    )
                ''', (exact_username, team_id))
                user_to_invite = cursor.fetchone()

                if not user_to_invite:
                    flash(f'User "{exact_username}" not found or is already in a team', 'error')
                else:
                    recipient_id = user_to_invite['id']

                    # Check if invitation already sent
                    cursor.execute('''
                        SELECT id FROM mail
                        WHERE sender_id = ? AND recipient_id = ? AND mail_type = 'team_invite' AND related_id = ?
                        AND id NOT IN (
                            SELECT mail_id FROM team_invite_responses WHERE mail_id = mail.id
                        )
                    ''', (user_id, recipient_id, team_id))

                    if cursor.fetchone():
                        flash(f'An invitation has already been sent to {user_to_invite["username"]}', 'info')
                    else:
                        # Send team invitation
                        mail_id = send_team_invitation(user_id, recipient_id, team_id)
                        if mail_id:
                            flash(f'Invitation sent to {user_to_invite["username"]}', 'success')
                            recently_invited.append(int(recipient_id))
                        else:
                            flash(f'Failed to send invitation to {user_to_invite["username"]}', 'error')
            elif 'search_term' in request.form:
                # Handle existing search functionality
                search_term = request.form.get('search_term', '')
                user_id_to_invite = request.form.get('user_id')

                if search_term:
                    # Search for users by username
                    cursor.execute('''
                        SELECT id, username, email, full_name, profile_pic FROM users
                        WHERE username LIKE ? AND id NOT IN (
                            SELECT user_id FROM team_members WHERE team_id = ?
                        )
                        LIMIT 20
                    ''', (f'%{search_term}%', team_id))
                    search_results = cursor.fetchall()

                if user_id_to_invite:
                    # Get user details
                    cursor.execute('SELECT id, username FROM users WHERE id = ?', (user_id_to_invite,))
                    user_to_invite = cursor.fetchone()

                    if user_to_invite:
                        recipient_id = user_to_invite['id']

                        # Check if invitation already sent
                        cursor.execute('''
                            SELECT id FROM mail
                            WHERE sender_id = ? AND recipient_id = ? AND mail_type = 'team_invite' AND related_id = ?
                            AND id NOT IN (
                                SELECT mail_id FROM team_invite_responses WHERE mail_id = mail.id
                            )
                        ''', (user_id, recipient_id, team_id))

                        if cursor.fetchone():
                            flash(f'An invitation has already been sent to {user_to_invite["username"]}', 'info')
                        else:
                            # Send team invitation
                            mail_id = send_team_invitation(user_id, recipient_id, team_id)
                            if mail_id:
                                flash(f'Invitation sent to {user_to_invite["username"]}', 'success')
                                recently_invited.append(int(recipient_id))
                            else:
                                flash(f'Failed to send invitation to {user_to_invite["username"]}', 'error')
        
        # Get recently invited users for display
        if recently_invited:
            placeholders = ','.join(['?'] * len(recently_invited))
            cursor.execute(f'''
                SELECT u.id, u.username, u.profile_pic, u.full_name
                FROM users u
                WHERE u.id IN ({placeholders})
            ''', recently_invited)
            recently_invited_users = cursor.fetchall()
        else:
            recently_invited_users = []

        conn.close()

        return render_template('search_users.html',
                             team=team,
                             search_results=search_results,
                             search_term=search_term,
                             recently_invited_users=recently_invited_users)

    except Exception as e:
        conn.close()
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('view_team', team_id=team_id))

@app.route('/teams/<int:team_id>/disband', methods=['POST'])
@login_required
def disband_team(team_id):
    """Disband a team (team leader only)"""
    user_id = session.get('user_id')
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Check if team exists
    cursor.execute('SELECT * FROM teams WHERE id = ?', (team_id,))
    team = cursor.fetchone()
    
    if not team:
        conn.close()
        flash('Team not found', 'error')
        return redirect(url_for('teams'))
    
    # Check if user is a team leader
    cursor.execute('''
        SELECT is_leader FROM team_members 
        WHERE team_id = ? AND user_id = ? AND is_leader = 1
    ''', (team_id, user_id))
    is_leader = cursor.fetchone() is not None
    
    # Only team leaders can disband teams (or admins)
    if not is_leader and not session.get('is_admin'):
        conn.close()
        flash('Only team leaders can disband their team', 'error')
        return redirect(url_for('view_team', team_id=team_id))
    
    # Get team members to notify them
    cursor.execute('''
        SELECT u.id, u.username 
        FROM users u
        JOIN team_members tm ON u.id = tm.user_id
        WHERE tm.team_id = ? AND u.id != ?
    ''', (team_id, user_id))
    members = cursor.fetchall()
    
    # Get team name for notification
    team_name = team['name']
    
    # Delete all team members
    cursor.execute('DELETE FROM team_members WHERE team_id = ?', (team_id,))
    
    # Delete the team
    cursor.execute('DELETE FROM teams WHERE id = ?', (team_id,))
    
    # Notify all members that the team has been disbanded
    for member in members:
        send_mail(
            sender_id=user_id,
            recipient_id=member['id'],
            subject=f"Team {team_name} has been disbanded",
            content=f"The team '{team_name}' has been disbanded by the team leader.",
            mail_type='system_notification'
        )
    
    conn.commit()
    conn.close()
    
    flash(f'Team "{team_name}" has been disbanded and all members have been notified.', 'success')
    return redirect(url_for('teams'))

@app.route('/teams/<int:team_id>/settings', methods=['GET', 'POST'])
@login_required
def team_settings(team_id):
    """Team settings page (team leaders only)"""
    user_id = session.get('user_id')
    if not user_id:
        flash('You must be logged in to access team settings', 'error')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # Check if team exists
        cursor.execute('SELECT * FROM teams WHERE id = ?', (team_id,))
        team = cursor.fetchone()
        
        if not team:
            conn.close()
            flash('Team not found', 'error')
            return redirect(url_for('teams'))
        
        # Check if user is a team leader
        cursor.execute('''
            SELECT is_leader FROM team_members 
            WHERE team_id = ? AND user_id = ?
        ''', (team_id, user_id))
        member_data = cursor.fetchone()
        is_leader = member_data and member_data['is_leader'] == 1
        
        # Only team leaders can access team settings (or admins)
        if not is_leader and not session.get('is_admin'):
            conn.close()
            flash('Only team leaders can access team settings', 'error')
            return redirect(url_for('view_team', team_id=team_id))
        
        # Log the leadership status for debugging
        print(f"Team settings - User {user_id} is_leader: {is_leader}, is_admin: {session.get('is_admin')}")
        
        if request.method == 'POST':
            try:
                team_name = request.form.get('team_name')
                description = request.form.get('description')
                team_logo = request.files.get('team_logo')
                team_email = request.form.get('team_email')
                team_discord = request.form.get('team_discord')
                team_website = request.form.get('team_website')
                team_rules = request.form.get('team_rules')
                team_points = request.form.get('team_points', '0')
                
                # Convert points to integer with validation
                try:
                    team_points = int(team_points)
                    if team_points < 0:
                        team_points = 0
                except ValueError:
                    team_points = 0
                
                if not team_name or not description:
                    flash('Team name and description are required', 'error')
                    return redirect(url_for('team_settings', team_id=team_id))
                
                # Check if team name already exists (if changed)
                if team_name != team['name']:
                    cursor.execute('SELECT id FROM teams WHERE name = ? AND id != ?', (team_name, team_id))
                    if cursor.fetchone():
                        conn.close()
                        flash('Team name already exists', 'error')
                        return redirect(url_for('team_settings', team_id=team_id))
                
                # Save team logo if provided
                logo_path = team['logo']
                if team_logo and team_logo.filename:
                    logo_path = save_team_logo(team_logo, team_name)
                
                # Update team settings
                cursor.execute('''
                    UPDATE teams 
                    SET name = ?, description = ?, logo = ?, 
                        email = ?, discord = ?, website = ?, rules = ?, points = ?
                    WHERE id = ?
                ''', (team_name, description, logo_path, team_email, team_discord, team_website, team_rules, team_points, team_id))
                
                conn.commit()
                flash('Team settings updated successfully', 'success')
                return redirect(url_for('view_team', team_id=team_id))
            except Exception as e:
                conn.rollback()
                flash(f'Error updating team settings: {str(e)}', 'error')
                return redirect(url_for('team_settings', team_id=team_id))
        
        # Get team settings for the form
        cursor.execute('''
            SELECT t.*, 
                   (SELECT COUNT(*) FROM team_members WHERE team_id = ?) as member_count
            FROM teams t
            WHERE t.id = ?
        ''', (team_id, team_id))
        team_data = cursor.fetchone()
        
        if not team_data:
            conn.close()
            flash('Team data not found', 'error')
            return redirect(url_for('teams'))
        
        conn.close()
        return render_template('team_settings.html', team=team_data)
    
    except Exception as e:
        conn.close()
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('teams'))

@app.template_filter('nl2br')
def nl2br(value):
    """Convert newlines to HTML line breaks."""
    if value:
        return value.replace('\n', '<br>')
    return ''

@app.route('/teams/<int:team_id>/kick/<int:user_id>', methods=['POST'])
@login_required
def kick_team_member(team_id, user_id):
    """Kick a member from a team (leader only)"""
    current_user_id = session.get('user_id')
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # Check if current user is the team leader
        cursor.execute('''
            SELECT is_leader FROM team_members 
            WHERE team_id = ? AND user_id = ?
        ''', (team_id, current_user_id))
        
        leader_result = cursor.fetchone()
        is_leader = leader_result and leader_result['is_leader'] == 1
        
        # Check if current user is an admin
        is_admin = session.get('is_admin', 0)
        
        if not (is_leader or is_admin):
            conn.close()
            flash('You do not have permission to kick team members', 'error')
            return redirect(url_for('view_team', team_id=team_id))
        
        # Check if user to kick is in the team
        cursor.execute('''
            SELECT * FROM team_members
            WHERE team_id = ? AND user_id = ?
        ''', (team_id, user_id))
        
        member = cursor.fetchone()
        if not member:
            conn.close()
            flash('User is not a member of this team', 'error')
            return redirect(url_for('view_team', team_id=team_id))
        
        # Check if user to kick is not the leader
        if member['is_leader'] == 1:
            conn.close()
            flash('Cannot kick the team leader', 'error')
            return redirect(url_for('view_team', team_id=team_id))
        
        # Remove user from team
        cursor.execute('DELETE FROM team_members WHERE team_id = ? AND user_id = ?', (team_id, user_id))
        
        # Get kicked user's username for the log
        cursor.execute('SELECT username FROM users WHERE id = ?', (user_id,))
        kicked_user = cursor.fetchone()
        kicked_username = kicked_user['username'] if kicked_user else f"User {user_id}"
        
        # Get team name
        cursor.execute('SELECT name FROM teams WHERE id = ?', (team_id,))
        team = cursor.fetchone()
        team_name = team['name'] if team else f"Team {team_id}"
        
        # Log the action - removed team_activity reference
        # Instead, just log to system logs if needed
        
        conn.commit()
        flash(f'User {kicked_username} has been removed from the team', 'success')
        
    except Exception as e:
        conn.rollback()
        flash(f'Error removing user: {str(e)}', 'error')
    
    conn.close()
    return redirect(url_for('view_team', team_id=team_id))

@app.route('/user/<int:user_id>')
def view_user(user_id):
    """View another user's profile"""
    # Check if user is trying to view their own profile
    if session.get('user_id') == user_id:
        return redirect(url_for('profile'))

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Get user details (excluding sensitive information)
    cursor.execute('''
        SELECT id, username, profile_pic, profile_music, bio, location, website, full_name,
               tier, nethpot_tier, nethpot_notes, uhc_tier, uhc_notes, cpvp_tier, cpvp_notes,
               sword_tier, sword_notes, smp_tier, smp_notes
        FROM users
        WHERE id = ?
    ''', (user_id,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        flash('User not found', 'error')
        return redirect(url_for('teams'))

    # Get user's team information
    user_team = get_user_team(user_id)

    return render_template('view_user.html', user=user, user_team=user_team,
                          unread_mail_count=get_unread_mail_count(session.get('user_id')))

@app.route('/teams/<int:team_id>/promote/<int:user_id>', methods=['POST'])
@login_required
def promote_member(team_id, user_id):
    """Promote a team member to co-leader (leader only)"""
    current_user_id = session.get('user_id')
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # Check if current user is the team leader
        cursor.execute('''
            SELECT is_leader FROM team_members 
            WHERE team_id = ? AND user_id = ?
        ''', (team_id, current_user_id))
        
        leader_result = cursor.fetchone()
        is_leader = leader_result and leader_result['is_leader'] == 1
        
        if not is_leader:
            conn.close()
            flash('Only team leaders can promote members', 'error')
            return redirect(url_for('view_team', team_id=team_id))
        
        # Check if user to promote is in the team
        cursor.execute('''
            SELECT * FROM team_members
            WHERE team_id = ? AND user_id = ?
        ''', (team_id, user_id))
        
        member = cursor.fetchone()
        if not member:
            conn.close()
            flash('User is not a member of this team', 'error')
            return redirect(url_for('view_team', team_id=team_id))
        
        # Check if user to promote is not already a leader
        if member['is_leader'] == 1:
            conn.close()
            flash('This user is already the team leader', 'error')
            return redirect(url_for('view_team', team_id=team_id))

        # Get the current role
        current_role = member['role']
        
        # Toggle between member and co-leader
        new_role = 'member' if current_role == 'co-leader' else 'co-leader'
        
        # Update the user's role
        cursor.execute('''
            UPDATE team_members
            SET role = ?
            WHERE team_id = ? AND user_id = ?
        ''', (new_role, team_id, user_id))
        
        # Get promoted user's username for the notification
        cursor.execute('SELECT username FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        username = user['username'] if user else f"User {user_id}"
        
        conn.commit()
        action = 'demoted from co-leader to member' if new_role == 'member' else 'promoted to co-leader'
        flash(f'{username} has been {action}', 'success')
        
    except Exception as e:
        conn.rollback()
        flash(f'Error updating member role: {str(e)}', 'error')
    
    conn.close()
    return redirect(url_for('view_team', team_id=team_id))

@app.route('/about')
def about():
    """About page with owner information"""
    return render_template('about.html', unread_mail_count=get_unread_mail_count(session.get('user_id', 0)))

@app.route('/admin/user/<int:user_id>/toggle-ban', methods=['POST'])
@admin_required
def admin_toggle_ban(user_id):
    """Toggle user ban status (admin only)"""
    # Check if user is trying to ban themselves
    if session.get('user_id') == user_id:
        flash('You cannot ban yourself', 'error')
        return redirect(url_for('admin_view_user', user_id=user_id))
    
    # Get ban reason if provided
    ban_reason = request.form.get('ban_reason', 'Violation of community guidelines')
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # Check if the is_banned column exists
        cursor.execute("PRAGMA table_info(users)")
        columns = cursor.fetchall()
        if not any(column['name'] == 'is_banned' for column in columns):
            # Add the is_banned column if it doesn't exist
            cursor.execute("ALTER TABLE users ADD COLUMN is_banned INTEGER DEFAULT 0")
            conn.commit()
        
        # Check if the ban_reason column exists
        if not any(column['name'] == 'ban_reason' for column in columns):
            # Add the ban_reason column if it doesn't exist
            cursor.execute("ALTER TABLE users ADD COLUMN ban_reason TEXT")
            conn.commit()
        
        # Get current ban status
        cursor.execute('SELECT username, is_banned FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            flash('User not found', 'error')
            conn.close()
            return redirect(url_for('admin_dashboard'))
        
        # Toggle ban status
        new_status = 0 if user['is_banned'] == 1 else 1
        
        # Update user's ban status and reason
        if new_status == 1:
            cursor.execute('UPDATE users SET is_banned = ?, ban_reason = ? WHERE id = ?', 
                          (new_status, ban_reason, user_id))
        else:
            cursor.execute('UPDATE users SET is_banned = ?, ban_reason = NULL WHERE id = ?', 
                          (new_status, user_id))
        
        # If banning, log the user out
        if new_status == 1:
            # First check if sessions table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sessions'")
            sessions_table_exists = cursor.fetchone() is not None
            
            if not sessions_table_exists:
                # Create the sessions table if it doesn't exist
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS sessions (
                        session_id TEXT PRIMARY KEY,
                        user_id INTEGER,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users(id)
                    )
                ''')
                conn.commit()
            
            # Now we can safely delete from the sessions table
            try:
                cursor.execute('DELETE FROM sessions WHERE user_id = ?', (user_id,))
            except sqlite3.Error:
                # If there's still an error, we'll just continue without deleting sessions
                pass
        
        conn.commit()
        
        action = 'banned' if new_status == 1 else 'unbanned'
        flash(f'User {user["username"]} has been {action}', 'success')
        
    except Exception as e:
        conn.rollback()
        flash(f'Error toggling ban status: {str(e)}', 'error')
    
    conn.close()
    return redirect(url_for('admin_view_user', user_id=user_id))

def save_profile_music(file_data, username):
    """Save a user's profile music and return the path"""
    if not file_data:
        return None
    
    # Create directory if it doesn't exist
    music_folder = 'static/uploads/profile_music'
    if not os.path.exists(music_folder):
        os.makedirs(music_folder, exist_ok=True)
    
    # Get file extension
    filename = file_data.filename
    ext = os.path.splitext(filename)[1].lower()
    
    # Check if valid audio format
    allowed_extensions = ['.mp3', '.wav', '.ogg', '.m4a']
    if ext not in allowed_extensions:
        raise ValueError(f"Unsupported audio format. Allowed formats: {', '.join(allowed_extensions)}")
    
    # Create a unique filename using the username and timestamp
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    secure_filename = f"{username.lower().replace(' ', '_')}_{timestamp}{ext}"
    file_path = os.path.join(music_folder, secure_filename)
    
    # Save the file
    file_data.save(file_path)
    
    # Return the relative path
    return os.path.join('uploads/profile_music', secure_filename)

def update_tier(cursor, user_id, field_name, value):
    """Helper function to update a specific tier field for a user"""
    if value is not None:
        cursor.execute(
            f'UPDATE users SET {field_name} = ? WHERE id = ?',
            (value, user_id)
        )

@app.route('/admin/reinit-db')
@admin_required
def reinit_db():
    """Route to manually reinitialize the database"""
    init_db()
    flash('Database reinitialized successfully', 'success')
    return redirect(url_for('admin_dashboard'))

# Initialize database on startup
with app.app_context():
    init_db()

# Run the application
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False) 