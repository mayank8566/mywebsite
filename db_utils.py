import sqlite3
from datetime import datetime
import os

# Get the application root directory
APP_ROOT = os.path.dirname(os.path.abspath(__file__))

# Check if running on Render
is_render = os.environ.get('RENDER') == 'true'

# Database configuration - Use the same path as in app.py
if is_render:
    DB_DIR = os.path.join(APP_ROOT, 'instance', 'data')
else:
    DB_DIR = os.path.join(APP_ROOT, 'data')

# Create the directory if it doesn't exist
os.makedirs(DB_DIR, exist_ok=True)

DB_PATH = os.path.join(DB_DIR, 'cosmic_teams.db')

def get_db_connection():
    """Create a database connection and return the connection and cursor"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # This enables column access by name
    return conn

def close_connection(conn):
    """Close the database connection"""
    if conn:
        conn.close()

# User-related functions
def get_user(user_id):
    """Get user data by ID"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    
    close_connection(conn)
    return user

def get_user_by_username(username):
    """Get user data by username"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    
    close_connection(conn)
    return user

def get_all_users(order_by='username', limit=None):
    """Get all users with optional ordering and limit"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = f'''
        SELECT id, username, email, full_name, is_admin, profile_pic,
               galaxy_rank, star_points, registration_date,
               nethpot_tier, uhc_tier, cpvp_tier, sword_tier, smp_tier
        FROM users ORDER BY {order_by}
    '''
    
    if limit:
        query += f' LIMIT {limit}'
    
    cursor.execute(query)
    users = cursor.fetchall()
    
    close_connection(conn)
    return users

def update_user_login(user_id):
    """Update user's last login time"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        'UPDATE users SET last_login = ? WHERE id = ?',
        (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user_id)
    )
    
    conn.commit()
    close_connection(conn)

def add_star_points(user_id, points):
    """Add star points to a user and update their galaxy rank"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get current star points
    cursor.execute('SELECT star_points FROM users WHERE id = ?', (user_id,))
    result = cursor.fetchone()
    
    if not result:
        close_connection(conn)
        return False
    
    current_points = result['star_points']
    new_points = current_points + points
    
    # Determine new galaxy rank based on points
    new_rank = "Novice Explorer"
    if new_points >= 1000:
        new_rank = "Galaxy Master"
    elif new_points >= 500:
        new_rank = "Star Commander"
    elif new_points >= 250:
        new_rank = "Nebula Navigator"
    elif new_points >= 100:
        new_rank = "Cosmic Voyager"
    elif new_points >= 50:
        new_rank = "Space Explorer"
    
    # Update user
    cursor.execute(
        'UPDATE users SET star_points = ?, galaxy_rank = ? WHERE id = ?',
        (new_points, new_rank, user_id)
    )
    
    conn.commit()
    close_connection(conn)
    return True

# Team-related functions
def get_team(team_id):
    """Get team data by ID"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM teams WHERE id = ?', (team_id,))
    team = cursor.fetchone()
    
    close_connection(conn)
    return team

def get_top_teams(limit=5):
    """Get top teams by points"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = '''
        SELECT t.*, COUNT(tm.id) as member_count, u.username as leader_name
        FROM teams t
        LEFT JOIN team_members tm ON t.id = tm.team_id
        LEFT JOIN team_members leader ON t.id = leader.team_id AND leader.is_leader = 1
        LEFT JOIN users u ON leader.user_id = u.id
        GROUP BY t.id
        ORDER BY t.points DESC
        LIMIT ?
    '''
    
    cursor.execute(query, (limit,))
    teams = cursor.fetchall()
    
    close_connection(conn)
    return teams

def get_user_teams(user_id):
    """Get all teams a user belongs to"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = '''
        SELECT t.*, tm.is_leader, tm.role
        FROM teams t
        JOIN team_members tm ON t.id = tm.team_id
        WHERE tm.user_id = ?
    '''
    
    cursor.execute(query, (user_id,))
    teams = cursor.fetchall()
    
    close_connection(conn)
    return teams

def get_team_members(team_id):
    """Get all members of a team with their roles"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = '''
        SELECT u.id, u.username, u.profile_pic, u.galaxy_rank, u.star_points,
               tm.is_leader, tm.role, tm.joined_at, tm.contribution_points
        FROM users u
        JOIN team_members tm ON u.id = tm.user_id
        WHERE tm.team_id = ?
        ORDER BY tm.is_leader DESC, tm.contribution_points DESC
    '''
    
    cursor.execute(query, (team_id,))
    members = cursor.fetchall()
    
    close_connection(conn)
    return members

# Mail-related functions
def get_user_mail(user_id, mail_type=None, is_read=None, limit=20):
    """Get mail for a user with optional filters"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = '''
        SELECT m.*, sender.username as sender_name, recipient.username as recipient_name
        FROM mail m
        LEFT JOIN users sender ON m.sender_id = sender.id
        JOIN users recipient ON m.recipient_id = recipient.id
        WHERE m.recipient_id = ?
    '''
    
    params = [user_id]
    
    if mail_type:
        query += ' AND m.mail_type = ?'
        params.append(mail_type)
    
    if is_read is not None:
        query += ' AND m.is_read = ?'
        params.append(1 if is_read else 0)
    
    query += ' ORDER BY m.sent_at DESC'
    
    if limit:
        query += ' LIMIT ?'
        params.append(limit)
    
    cursor.execute(query, params)
    mail = cursor.fetchall()
    
    close_connection(conn)
    return mail

def get_unread_mail_count(user_id):
    """Get count of unread mail for a user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        'SELECT COUNT(*) as count FROM mail WHERE recipient_id = ? AND is_read = 0',
        (user_id,)
    )
    result = cursor.fetchone()
    
    close_connection(conn)
    return result['count'] if result else 0

def send_mail(sender_id, recipient_id, subject, content, mail_type='message', related_id=None):
    """Send a mail message from one user to another"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        '''
        INSERT INTO mail (sender_id, recipient_id, subject, content, mail_type, related_id, sent_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''',
        (sender_id, recipient_id, subject, content, mail_type, related_id, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    )
    
    mail_id = cursor.lastrowid
    conn.commit()
    close_connection(conn)
    
    return mail_id

# Competition-related functions
def get_active_competitions():
    """Get all active competitions"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    query = '''
        SELECT c.*, COUNT(ct.id) as team_count
        FROM competitions c
        LEFT JOIN competition_teams ct ON c.id = ct.competition_id
        WHERE c.start_date <= ? AND c.end_date >= ?
        GROUP BY c.id
    '''
    
    cursor.execute(query, (now, now))
    competitions = cursor.fetchall()
    
    close_connection(conn)
    return competitions

def get_competition_teams(competition_id):
    """Get all teams participating in a competition"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = '''
        SELECT t.*, ct.score, ct.rank, ct.registration_date
        FROM teams t
        JOIN competition_teams ct ON t.id = ct.team_id
        WHERE ct.competition_id = ?
        ORDER BY ct.score DESC, ct.rank
    '''
    
    cursor.execute(query, (competition_id,))
    teams = cursor.fetchall()
    
    close_connection(conn)
    return teams

# Achievement-related functions
def get_user_achievements(user_id):
    """Get all achievements earned by a user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = '''
        SELECT a.*, ua.date_earned
        FROM achievements a
        JOIN user_achievements ua ON a.id = ua.achievement_id
        WHERE ua.user_id = ? AND a.achievement_type = 'user'
    '''
    
    cursor.execute(query, (user_id,))
    achievements = cursor.fetchall()
    
    close_connection(conn)
    return achievements

def get_team_achievements(team_id):
    """Get all achievements earned by a team"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = '''
        SELECT a.*, ta.date_earned
        FROM achievements a
        JOIN team_achievements ta ON a.id = ta.achievement_id
        WHERE ta.team_id = ? AND a.achievement_type = 'team'
    '''
    
    cursor.execute(query, (team_id,))
    achievements = cursor.fetchall()
    
    close_connection(conn)
    return achievements

def award_achievement(user_id=None, team_id=None, achievement_name=None):
    """Award an achievement to a user or team"""
    if not achievement_name or (user_id is None and team_id is None):
        return False
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get the achievement ID
    cursor.execute('SELECT id, achievement_type, points FROM achievements WHERE name = ?', (achievement_name,))
    achievement = cursor.fetchone()
    
    if not achievement:
        close_connection(conn)
        return False
    
    achievement_id = achievement['id']
    achievement_type = achievement['achievement_type']
    points = achievement['points']
    
    if achievement_type == 'user' and user_id:
        # Check if user already has this achievement
        cursor.execute(
            'SELECT id FROM user_achievements WHERE user_id = ? AND achievement_id = ?',
            (user_id, achievement_id)
        )
        existing = cursor.fetchone()
        
        if not existing:
            # Award the achievement
            cursor.execute(
                'INSERT INTO user_achievements (user_id, achievement_id, date_earned) VALUES (?, ?, ?)',
                (user_id, achievement_id, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            )
            
            # Add star points to the user
            add_star_points(user_id, points)
            
            # Log the activity
            log_user_activity(user_id, 'achievement_earned', f"Earned achievement: {achievement_name}", achievement_id)
            
            conn.commit()
            close_connection(conn)
            return True
    
    elif achievement_type == 'team' and team_id:
        # Check if team already has this achievement
        cursor.execute(
            'SELECT id FROM team_achievements WHERE team_id = ? AND achievement_id = ?',
            (team_id, achievement_id)
        )
        existing = cursor.fetchone()
        
        if not existing:
            # Award the achievement
            cursor.execute(
                'INSERT INTO team_achievements (team_id, achievement_id, date_earned) VALUES (?, ?, ?)',
                (team_id, achievement_id, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            )
            
            # Add points to the team
            cursor.execute(
                'UPDATE teams SET points = points + ? WHERE id = ?',
                (points, team_id)
            )
            
            # Log the activity
            log_team_activity(team_id, None, 'achievement_earned', f"Team earned achievement: {achievement_name}", achievement_id)
            
            conn.commit()
            close_connection(conn)
            return True
    
    close_connection(conn)
    return False

# Activity logging functions
def log_user_activity(user_id, activity_type, description=None, related_id=None):
    """Log a user activity"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        '''
        INSERT INTO user_activity (user_id, activity_type, description, related_id, timestamp)
        VALUES (?, ?, ?, ?, ?)
        ''',
        (user_id, activity_type, description, related_id, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    )
    
    conn.commit()
    close_connection(conn)

def log_team_activity(team_id, user_id, activity_type, description=None, related_id=None):
    """Log a team activity"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        '''
        INSERT INTO team_activity (team_id, user_id, activity_type, description, related_id, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        ''',
        (team_id, user_id, activity_type, description, related_id, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    )
    
    conn.commit()
    close_connection(conn)

# Settings functions
def get_setting(setting_key, default=None):
    """Get a setting value by key"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT setting_value, setting_type FROM settings WHERE setting_key = ?', (setting_key,))
    setting = cursor.fetchone()
    
    close_connection(conn)
    
    if not setting:
        return default
    
    value = setting['setting_value']
    setting_type = setting['setting_type']
    
    # Convert value based on type
    if setting_type == 'integer':
        return int(value)
    elif setting_type == 'boolean':
        return value.lower() == 'true'
    else:
        return value

def update_setting(setting_key, setting_value):
    """Update a setting value"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Convert value to string for storage
    if isinstance(setting_value, bool):
        setting_value = 'true' if setting_value else 'false'
    else:
        setting_value = str(setting_value)
    
    cursor.execute(
        'UPDATE settings SET setting_value = ? WHERE setting_key = ?',
        (setting_value, setting_key)
    )
    
    conn.commit()
    close_connection(conn)

# Galaxy events functions
def get_active_galaxy_events():
    """Get all currently active galaxy events"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    cursor.execute(
        'SELECT * FROM galaxy_events WHERE start_date <= ? AND end_date >= ?',
        (now, now)
    )
    events = cursor.fetchall()
    
    close_connection(conn)
    return events

def get_current_points_multiplier():
    """Get the current points multiplier from active events"""
    events = get_active_galaxy_events()
    
    if not events:
        return 1.0
    
    # Use the highest multiplier if multiple events are active
    return max(event['points_multiplier'] for event in events) 