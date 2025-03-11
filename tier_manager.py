import sqlite3
from datetime import datetime
import os

# Use the same path determination as app.py
is_render = os.environ.get('RENDER') == 'true'
if is_render:
    # Use a directory within the project that we have permission to access
    DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'data')
else:
    DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')

# Create the directory if it doesn't exist
os.makedirs(DB_DIR, exist_ok=True)

DB_PATH = os.path.join(DB_DIR, 'cosmic_teams.db')

class TierManager:
    """Class to manage user skill tiers"""
    
    @staticmethod
    def get_db_connection():
        """Get a database connection with row factory"""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    
    @staticmethod
    def initialize_tables():
        """Ensure all necessary tables exist and are populated with default values"""
        conn = TierManager.get_db_connection()
        cursor = conn.cursor()
        
        # Check if tables exist, create them if they don't
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='tiers'")
        if not cursor.fetchone():
            # Create tiers table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tiers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tier_name TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    description TEXT,
                    color_class TEXT NOT NULL,
                    category TEXT NOT NULL,
                    level INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Insert default tiers
            tiers = [
                ('LT1', 'Lower Tier 1', 'Beginner', 'lt1', 'LT', 1),
                ('LT2', 'Lower Tier 2', 'Novice', 'lt2', 'LT', 2),
                ('LT3', 'Lower Tier 3', 'Intermediate', 'lt3', 'LT', 3),
                ('LT4', 'Lower Tier 4', 'Proficient', 'lt4', 'LT', 4),
                ('LT5', 'Lower Tier 5', 'Advanced', 'lt5', 'LT', 5),
                ('HT1', 'Higher Tier 1', 'Expert', 'ht1', 'HT', 1),
                ('HT2', 'Higher Tier 2', 'Master', 'ht2', 'HT', 2),
                ('HT3', 'Higher Tier 3', 'Elite', 'ht3', 'HT', 3),
                ('HT4', 'Higher Tier 4', 'Professional', 'ht4', 'HT', 4),
                ('HT5', 'Higher Tier 5', 'Legendary', 'ht5', 'HT', 5)
            ]
            cursor.executemany(
                'INSERT INTO tiers (tier_name, display_name, description, color_class, category, level) VALUES (?, ?, ?, ?, ?, ?)',
                tiers
            )
        
        # Check if skill_types table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='skill_types'")
        if not cursor.fetchone():
            # Create skill_types table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS skill_types (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    skill_code TEXT NOT NULL UNIQUE,
                    skill_name TEXT NOT NULL,
                    description TEXT,
                    icon_path TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Insert default skill types
            skill_types = [
                ('npot', 'Nether Pot', 'Nether portal techniques and strategies', 'img/neth-op.svg'),
                ('uhc', 'Ultra Hardcore', 'Ultra Hardcore PVP skills', 'img/uhc.svg'),
                ('cpvp', 'Crystal PVP', 'End crystal combat techniques', 'img/cpvp.svg'),
                ('sword', 'Sword Combat', 'Sword fighting techniques', 'img/sword.svg'),
                ('axe', 'Axe Combat', 'Axe combat techniques', 'img/axe.svg'),
                ('smp', 'Survival Multiplayer', 'General survival multiplayer skills', 'img/smp.svg')
            ]
            cursor.executemany(
                'INSERT INTO skill_types (skill_code, skill_name, description, icon_path) VALUES (?, ?, ?, ?)',
                skill_types
            )
        
        # Check if user_skills table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user_skills'")
        if not cursor.fetchone():
            # Create user_skills table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_skills (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    skill_type_id INTEGER NOT NULL,
                    tier_id INTEGER,
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (skill_type_id) REFERENCES skill_types(id) ON DELETE CASCADE,
                    FOREIGN KEY (tier_id) REFERENCES tiers(id) ON DELETE SET NULL,
                    UNIQUE(user_id, skill_type_id)
                )
            ''')
        
        conn.commit()
        conn.close()
    
    @staticmethod
    def migrate_existing_user_tiers():
        """Migrate existing user tier data to the new table structure"""
        conn = TierManager.get_db_connection()
        cursor = conn.cursor()
        
        # Get all users with tier data
        cursor.execute('''
            SELECT id, npot_tier, uhc_tier, cpvp_tier, sword_tier, axe_tier, smp_tier 
            FROM users
        ''')
        users = cursor.fetchall()
        
        # Get skill type IDs
        cursor.execute('SELECT id, skill_code FROM skill_types')
        skill_types = {row['skill_code']: row['id'] for row in cursor.fetchall()}
        
        # Get tier IDs
        cursor.execute('SELECT id, tier_name FROM tiers')
        tiers = {row['tier_name']: row['id'] for row in cursor.fetchall()}
        
        # Migrate each user's tier data
        for user in users:
            user_id = user['id']
            
            skill_mappings = [
                ('npot', user['npot_tier']),
                ('uhc', user['uhc_tier']),
                ('cpvp', user['cpvp_tier']),
                ('sword', user['sword_tier']),
                ('axe', user['axe_tier']),
                ('smp', user['smp_tier'])
            ]
            
            for skill_code, tier_name in skill_mappings:
                if tier_name and skill_code in skill_types and tier_name in tiers:
                    # Check if entry already exists
                    cursor.execute('''
                        SELECT id FROM user_skills 
                        WHERE user_id = ? AND skill_type_id = ?
                    ''', (user_id, skill_types[skill_code]))
                    
                    if cursor.fetchone():
                        # Update existing entry
                        cursor.execute('''
                            UPDATE user_skills 
                            SET tier_id = ?, updated_at = ? 
                            WHERE user_id = ? AND skill_type_id = ?
                        ''', (tiers[tier_name], datetime.now(), user_id, skill_types[skill_code]))
                    else:
                        # Insert new entry
                        cursor.execute('''
                            INSERT INTO user_skills (user_id, skill_type_id, tier_id)
                            VALUES (?, ?, ?)
                        ''', (user_id, skill_types[skill_code], tiers[tier_name]))
        
        conn.commit()
        conn.close()
    
    @staticmethod
    def get_user_skills(user_id):
        """Get all skills and tiers for a user"""
        conn = TierManager.get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                us.id, 
                st.skill_code, 
                st.skill_name, 
                st.description AS skill_description, 
                st.icon_path,
                t.tier_name, 
                t.display_name AS tier_display_name, 
                t.description AS tier_description, 
                t.color_class,
                t.category,
                t.level,
                us.notes
            FROM user_skills us
            JOIN skill_types st ON us.skill_type_id = st.id
            LEFT JOIN tiers t ON us.tier_id = t.id
            WHERE us.user_id = ?
        ''', (user_id,))
        
        skills = cursor.fetchall()
        
        # Get all skill types to fill in missing skills
        cursor.execute('SELECT * FROM skill_types')
        all_skill_types = cursor.fetchall()
        
        # Convert skills to dict for easy lookup
        skills_dict = {skill['skill_code']: dict(skill) for skill in skills}
        
        # Fill in missing skills with unranked status
        result = []
        for skill_type in all_skill_types:
            skill_code = skill_type['skill_code']
            if skill_code in skills_dict:
                result.append(skills_dict[skill_code])
            else:
                result.append({
                    'id': None,
                    'skill_code': skill_code,
                    'skill_name': skill_type['skill_name'],
                    'skill_description': skill_type['description'],
                    'icon_path': skill_type['icon_path'],
                    'tier_name': None,
                    'tier_display_name': 'Unranked',
                    'color_class': 'unranked',
                    'notes': None
                })
        
        conn.close()
        return result
    
    @staticmethod
    def update_user_skill(user_id, skill_code, tier_name=None, notes=None):
        """Update a user's skill tier"""
        conn = TierManager.get_db_connection()
        cursor = conn.cursor()
        
        # Get skill type ID
        cursor.execute('SELECT id FROM skill_types WHERE skill_code = ?', (skill_code,))
        skill_type = cursor.fetchone()
        if not skill_type:
            conn.close()
            return False, f"Skill type {skill_code} not found"
        
        skill_type_id = skill_type['id']
        
        # Get tier ID if provided
        tier_id = None
        if tier_name:
            cursor.execute('SELECT id FROM tiers WHERE tier_name = ?', (tier_name,))
            tier = cursor.fetchone()
            if not tier:
                conn.close()
                return False, f"Tier {tier_name} not found"
            tier_id = tier['id']
        
        # Check if entry already exists
        cursor.execute('''
            SELECT id FROM user_skills 
            WHERE user_id = ? AND skill_type_id = ?
        ''', (user_id, skill_type_id))
        
        existing = cursor.fetchone()
        
        if existing:
            # Update existing entry
            cursor.execute('''
                UPDATE user_skills 
                SET tier_id = ?, notes = ?, updated_at = ? 
                WHERE id = ?
            ''', (tier_id, notes, datetime.now(), existing['id']))
        else:
            # Insert new entry
            cursor.execute('''
                INSERT INTO user_skills (user_id, skill_type_id, tier_id, notes)
                VALUES (?, ?, ?, ?)
            ''', (user_id, skill_type_id, tier_id, notes))
        
        conn.commit()
        conn.close()
        return True, "Skill updated successfully"
    
    @staticmethod
    def update_user_skills_from_form(user_id, form_data):
        """Update multiple user skills from form data"""
        skill_codes = ['npot', 'uhc', 'cpvp', 'sword', 'axe', 'smp']
        results = []
        
        for skill_code in skill_codes:
            tier_name = form_data.get(f'{skill_code}_tier', '').strip().upper()
            notes = form_data.get(f'{skill_code}_notes', '')
            
            # Validate tier name format
            if tier_name and not (tier_name.startswith(('LT', 'HT')) and len(tier_name) == 3 and tier_name[2].isdigit() and '1' <= tier_name[2] <= '5'):
                tier_name = None
            
            success, message = TierManager.update_user_skill(user_id, skill_code, tier_name, notes)
            results.append((success, message))
        
        return results
    
    @staticmethod
    def get_all_tiers():
        """Get all tier definitions"""
        conn = TierManager.get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM tiers ORDER BY category, level')
        tiers = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        return tiers
    
    @staticmethod
    def get_all_skill_types():
        """Get all skill type definitions"""
        conn = TierManager.get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM skill_types ORDER BY skill_name')
        skill_types = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        return skill_types
        
    @staticmethod
    def get_skill_leaderboard(skill_code, limit=10):
        """Get top users for a specific skill based on tier level"""
        conn = TierManager.get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                u.id AS user_id,
                u.username,
                u.profile_pic,
                t.tier_name,
                t.display_name AS tier_display_name,
                t.color_class,
                t.category,
                t.level,
                st.skill_name,
                st.skill_code
            FROM user_skills us
            JOIN users u ON us.user_id = u.id
            JOIN skill_types st ON us.skill_type_id = st.id
            JOIN tiers t ON us.tier_id = t.id
            WHERE st.skill_code = ?
            ORDER BY 
                CASE 
                    WHEN t.category = 'HT' THEN t.level + 5
                    ELSE t.level
                END DESC,
                u.username
            LIMIT ?
        ''', (skill_code, limit))
        
        leaderboard = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return leaderboard
        
    @staticmethod
    def get_all_leaderboards(limit=5):
        """Get leaderboards for all skills"""
        skill_types = TierManager.get_all_skill_types()
        result = {}
        
        for skill in skill_types:
            result[skill['skill_code']] = {
                'skill_name': skill['skill_name'],
                'skill_code': skill['skill_code'],
                'description': skill['description'],
                'icon_path': skill['icon_path'],
                'leaderboard': TierManager.get_skill_leaderboard(skill['skill_code'], limit)
            }
            
        return result
        
    @staticmethod
    def get_tier_counts():
        """Get counts of users at each tier level for each skill"""
        conn = TierManager.get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                st.skill_code,
                st.skill_name,
                t.tier_name,
                COUNT(us.user_id) as user_count
            FROM user_skills us
            JOIN skill_types st ON us.skill_type_id = st.id
            JOIN tiers t ON us.tier_id = t.id
            GROUP BY st.skill_code, t.tier_name
            ORDER BY st.skill_name, t.category, t.level
        ''')
        
        rows = cursor.fetchall()
        conn.close()
        
        # Format the results into a nested dictionary
        result = {}
        for row in rows:
            skill_code = row['skill_code']
            if skill_code not in result:
                result[skill_code] = {
                    'skill_name': row['skill_name'],
                    'tiers': {}
                }
            
            result[skill_code]['tiers'][row['tier_name']] = row['user_count']
            
        return result
    
    @staticmethod
    def get_user_tier_rank(user_id, skill_code):
        """Get a user's rank for a specific skill"""
        conn = TierManager.get_db_connection()
        cursor = conn.cursor()
        
        # First get the user's tier
        cursor.execute('''
            SELECT 
                t.tier_name,
                t.category,
                t.level
            FROM user_skills us
            JOIN skill_types st ON us.skill_type_id = st.id
            JOIN tiers t ON us.tier_id = t.id
            WHERE us.user_id = ? AND st.skill_code = ?
        ''', (user_id, skill_code))
        
        user_tier = cursor.fetchone()
        
        if not user_tier:
            conn.close()
            return None
        
        # Now count how many users are at the same tier or higher
        cursor.execute('''
            SELECT COUNT(*) as rank_position
            FROM (
                SELECT 
                    us.user_id,
                    CASE 
                        WHEN t.category = 'HT' THEN t.level + 5
                        ELSE t.level
                    END as tier_value
                FROM user_skills us
                JOIN skill_types st ON us.skill_type_id = st.id
                JOIN tiers t ON us.tier_id = t.id
                WHERE st.skill_code = ?
            ) ranked_users
            WHERE tier_value >= (
                SELECT 
                    CASE 
                        WHEN t.category = 'HT' THEN t.level + 5
                        ELSE t.level
                    END as tier_value
                FROM user_skills us
                JOIN skill_types st ON us.skill_type_id = st.id
                JOIN tiers t ON us.tier_id = t.id
                WHERE us.user_id = ? AND st.skill_code = ?
            )
        ''', (skill_code, user_id, skill_code))
        
        rank = cursor.fetchone()
        
        # Get total number of ranked users for this skill
        cursor.execute('''
            SELECT COUNT(*) as total
            FROM user_skills us
            JOIN skill_types st ON us.skill_type_id = st.id
            WHERE st.skill_code = ? AND us.tier_id IS NOT NULL
        ''', (skill_code,))
        
        total = cursor.fetchone()
        
        conn.close()
        
        return {
            'tier_name': user_tier['tier_name'],
            'rank': rank['rank_position'] if rank else None,
            'total': total['total'] if total else 0,
            'percentile': round(((total['total'] - rank['rank_position']) / total['total']) * 100) if rank and total and total['total'] > 0 else 0
        }
        
    @staticmethod
    def get_tier_progression_path():
        """Get the progression path of tiers"""
        conn = TierManager.get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM tiers ORDER BY category, level')
        tiers = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        # Organize tiers into paths
        lower_path = [tier for tier in tiers if tier['category'] == 'LT']
        higher_path = [tier for tier in tiers if tier['category'] == 'HT']
        
        return {
            'lower_path': lower_path,
            'higher_path': higher_path,
            'all_tiers': tiers
        }
        
    @staticmethod
    def get_tier_recommendations(user_id):
        """Get tier-based skill recommendations for a user"""
        user_skills = TierManager.get_user_skills(user_id)
        
        # Convert to dictionary for easier access
        skills_dict = {skill['skill_code']: skill for skill in user_skills if skill.get('tier_name')}
        
        recommendations = []
        
        # Simple recommendation logic based on related skills
        skill_relations = {
            'npot': ['cpvp', 'smp'],  # NPOT related to CPVP and SMP
            'cpvp': ['npot', 'sword'],  # CPVP related to NPOT and SWORD
            'sword': ['axe', 'cpvp'],  # SWORD related to AXE and CPVP
            'axe': ['sword', 'smp'],  # AXE related to SWORD and SMP
            'smp': ['axe', 'npot'],  # SMP related to AXE and NPOT
            'uhc': ['sword', 'axe']   # UHC related to SWORD and AXE
        }
        
        for skill_code, related_skills in skill_relations.items():
            if skill_code in skills_dict:
                current_skill = skills_dict[skill_code]
                current_tier = current_skill.get('tier_name')
                
                if current_tier:
                    category = current_tier[:2]
                    level = int(current_tier[2])
                    
                    # Recommend next tier for this skill
                    if category == 'LT' and level < 5:
                        recommendations.append({
                            'skill_code': skill_code,
                            'skill_name': current_skill['skill_name'],
                            'current_tier': current_tier,
                            'recommended_tier': f"LT{level+1}",
                            'reason': f"You're making progress in {current_skill['skill_name']}! Try to reach the next level."
                        })
                    elif category == 'LT' and level == 5:
                        recommendations.append({
                            'skill_code': skill_code,
                            'skill_name': current_skill['skill_name'],
                            'current_tier': current_tier,
                            'recommended_tier': "HT1",
                            'reason': f"You've mastered the basic levels of {current_skill['skill_name']}! Ready to advance to higher tiers?"
                        })
                    elif category == 'HT' and level < 5:
                        recommendations.append({
                            'skill_code': skill_code,
                            'skill_name': current_skill['skill_name'],
                            'current_tier': current_tier,
                            'recommended_tier': f"HT{level+1}",
                            'reason': f"Keep pushing your {current_skill['skill_name']} skills to reach the elite level!"
                        })
                    
                    # Recommend related skills if they're lower level
                    for related_code in related_skills:
                        if related_code in skills_dict:
                            related_skill = skills_dict[related_code]
                            related_tier = related_skill.get('tier_name')
                            
                            if related_tier:
                                r_category = related_tier[:2]
                                r_level = int(related_tier[2])
                                
                                # If current skill is higher tier than related skill
                                if (category == 'HT' and r_category == 'LT') or \
                                   (category == r_category and level > r_level + 1):
                                    recommendations.append({
                                        'skill_code': related_code,
                                        'skill_name': related_skill['skill_name'],
                                        'current_tier': related_tier,
                                        'recommended_tier': f"{r_category}{min(r_level+2, 5)}" if r_level < 4 else f"{'HT' if r_category == 'LT' else 'HT'}{1 if r_category == 'LT' else min(r_level+1, 5)}",
                                        'reason': f"Your {current_skill['skill_name']} skills could help improve your {related_skill['skill_name']} abilities!"
                                    })
                            else:
                                # No tier for related skill yet, recommend starting
                                recommendations.append({
                                    'skill_code': related_code,
                                    'skill_name': related_skill['skill_name'],
                                    'current_tier': "Unranked",
                                    'recommended_tier': "LT1",
                                    'reason': f"Your {current_skill['skill_name']} skills would give you a head start in {related_skill['skill_name']}!"
                                })
        
        # Limit to top 3 recommendations to avoid overwhelming the user
        return recommendations[:3]

# Initialize if running directly
if __name__ == "__main__":
    TierManager.initialize_tables()
    TierManager.migrate_existing_user_tiers()
    print("Tier system initialized and migrated successfully!") 