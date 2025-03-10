-- Galaxy-themed Minecraft Website Database Schema
-- This schema includes all necessary tables with proper relationships and indexes for optimal performance

-- Users Table - Stores user information
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0,
    profile_pic TEXT,
    bio TEXT,
    location TEXT,
    website TEXT,
    full_name TEXT,
    registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    can_create_team INTEGER DEFAULT 0,
    
    -- Galaxy theme specific fields
    galaxy_rank TEXT DEFAULT 'Novice Explorer',
    star_points INTEGER DEFAULT 0,
    
    -- User's preferred tier
    tier TEXT DEFAULT 'none',
    
    -- Minecraft skill tiers
    nethpot_tier TEXT,
    nethpot_notes TEXT,
    uhc_tier TEXT,
    uhc_notes TEXT,
    cpvp_tier TEXT,
    cpvp_notes TEXT,
    sword_tier TEXT,
    sword_notes TEXT,
    smp_tier TEXT,
    smp_notes TEXT
);

-- Create indexes for frequently queried fields
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_star_points ON users(star_points);

-- Teams Table - Stores team information
CREATE TABLE IF NOT EXISTS teams (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    logo TEXT,
    points INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    email TEXT,
    discord TEXT,
    website TEXT,
    rules TEXT,
    
    -- Galaxy theme specific fields
    galaxy_name TEXT DEFAULT 'New Galaxy',
    constellation_type TEXT DEFAULT 'Spiral',
    star_color TEXT DEFAULT '#FFFFFF',
    team_banner_bg TEXT DEFAULT 'nebula-default.jpg'
);

-- Create indexes for team queries
CREATE INDEX IF NOT EXISTS idx_teams_name ON teams(name);
CREATE INDEX IF NOT EXISTS idx_teams_points ON teams(points DESC);

-- Team Members Table - Relationship between users and teams
CREATE TABLE IF NOT EXISTS team_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    is_leader INTEGER DEFAULT 0,
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    role TEXT DEFAULT 'Member',
    contribution_points INTEGER DEFAULT 0,
    FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(team_id, user_id)
);

-- Create indexes for team member queries
CREATE INDEX IF NOT EXISTS idx_team_members_team_id ON team_members(team_id);
CREATE INDEX IF NOT EXISTS idx_team_members_user_id ON team_members(user_id);
CREATE INDEX IF NOT EXISTS idx_team_members_is_leader ON team_members(is_leader);

-- Mail System Table - For in-app messaging
CREATE TABLE IF NOT EXISTS mail (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER,
    recipient_id INTEGER NOT NULL,
    subject TEXT NOT NULL,
    content TEXT,
    is_read INTEGER DEFAULT 0,
    mail_type TEXT DEFAULT 'message',
    related_id INTEGER,
    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes for mail queries
CREATE INDEX IF NOT EXISTS idx_mail_sender_id ON mail(sender_id);
CREATE INDEX IF NOT EXISTS idx_mail_recipient_id ON mail(recipient_id);
CREATE INDEX IF NOT EXISTS idx_mail_is_read ON mail(is_read);
CREATE INDEX IF NOT EXISTS idx_mail_sent_at ON mail(sent_at DESC);

-- Competitions Table - For team competitions
CREATE TABLE IF NOT EXISTS competitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    start_date TIMESTAMP NOT NULL,
    end_date TIMESTAMP NOT NULL,
    status TEXT DEFAULT 'upcoming', -- upcoming, active, completed
    max_teams INTEGER DEFAULT 0, -- 0 means unlimited
    banner_image TEXT,
    rules TEXT,
    prize_description TEXT
);

-- Competition Teams Table - Teams participating in competitions
CREATE TABLE IF NOT EXISTS competition_teams (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    competition_id INTEGER NOT NULL,
    team_id INTEGER NOT NULL,
    registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    score INTEGER DEFAULT 0,
    rank INTEGER,
    FOREIGN KEY (competition_id) REFERENCES competitions(id) ON DELETE CASCADE,
    FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE,
    UNIQUE(competition_id, team_id)
);

-- Create indexes for competition queries
CREATE INDEX IF NOT EXISTS idx_competition_teams_comp_id ON competition_teams(competition_id);
CREATE INDEX IF NOT EXISTS idx_competition_teams_team_id ON competition_teams(team_id);
CREATE INDEX IF NOT EXISTS idx_competition_teams_score ON competition_teams(score DESC);

-- Achievements Table - For user and team achievements
CREATE TABLE IF NOT EXISTS achievements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    icon TEXT,
    points INTEGER DEFAULT 10,
    achievement_type TEXT DEFAULT 'user' -- user or team
);

-- User Achievements Table - Tracks which users have which achievements
CREATE TABLE IF NOT EXISTS user_achievements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    achievement_id INTEGER NOT NULL,
    date_earned TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (achievement_id) REFERENCES achievements(id) ON DELETE CASCADE,
    UNIQUE(user_id, achievement_id)
);

-- Team Achievements Table - Tracks which teams have which achievements
CREATE TABLE IF NOT EXISTS team_achievements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id INTEGER NOT NULL,
    achievement_id INTEGER NOT NULL,
    date_earned TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE,
    FOREIGN KEY (achievement_id) REFERENCES achievements(id) ON DELETE CASCADE,
    UNIQUE(team_id, achievement_id)
);

-- Galaxy Events Table - For special events in the galaxy theme
CREATE TABLE IF NOT EXISTS galaxy_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    start_date TIMESTAMP NOT NULL,
    end_date TIMESTAMP NOT NULL,
    event_type TEXT DEFAULT 'meteor_shower', -- meteor_shower, supernova, black_hole, etc.
    points_multiplier FLOAT DEFAULT 1.0,
    banner_image TEXT
);

-- User Activity Log - For tracking user actions
CREATE TABLE IF NOT EXISTS user_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    activity_type TEXT NOT NULL,
    description TEXT,
    related_id INTEGER, -- Can reference various entities based on activity_type
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create index for user activity queries
CREATE INDEX IF NOT EXISTS idx_user_activity_user_id ON user_activity(user_id);
CREATE INDEX IF NOT EXISTS idx_user_activity_timestamp ON user_activity(timestamp DESC);

-- Team Activity Log - For tracking team actions
CREATE TABLE IF NOT EXISTS team_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id INTEGER NOT NULL,
    user_id INTEGER, -- User who performed the action
    activity_type TEXT NOT NULL,
    description TEXT,
    related_id INTEGER,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Create index for team activity queries
CREATE INDEX IF NOT EXISTS idx_team_activity_team_id ON team_activity(team_id);
CREATE INDEX IF NOT EXISTS idx_team_activity_timestamp ON team_activity(timestamp DESC);

-- Settings Table - For site-wide settings
CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    setting_key TEXT UNIQUE NOT NULL,
    setting_value TEXT,
    setting_type TEXT DEFAULT 'string', -- string, integer, boolean, json
    description TEXT
);

-- Insert default settings
INSERT OR IGNORE INTO settings (setting_key, setting_value, setting_type, description)
VALUES 
('site_name', 'Galaxy Minecraft', 'string', 'Name of the website'),
('theme_color', '#1a1a2e', 'string', 'Primary theme color'),
('accent_color', '#7b2cbf', 'string', 'Accent color for buttons and highlights'),
('allow_registrations', 'true', 'boolean', 'Whether new user registrations are allowed'),
('max_team_size', '10', 'integer', 'Maximum number of members allowed in a team'),
('featured_teams_count', '3', 'integer', 'Number of featured teams to display on homepage');

-- Add the Tiers table
CREATE TABLE IF NOT EXISTS tiers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tier_name TEXT NOT NULL,  -- e.g., LT1, HT5
    display_name TEXT NOT NULL,  -- e.g., "Lower Tier 1", "Higher Tier 5"
    description TEXT,
    color_class TEXT NOT NULL,  -- CSS class for styling
    category TEXT NOT NULL,  -- LT or HT
    level INTEGER NOT NULL,  -- 1-5
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add the SkillTypes table
CREATE TABLE IF NOT EXISTS skill_types (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    skill_code TEXT NOT NULL UNIQUE,  -- e.g., npot, uhc, cpvp
    skill_name TEXT NOT NULL,  -- e.g., "Nether Pot", "Ultra Hardcore"
    description TEXT,
    icon_path TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add the UserSkills table to track user skills and tiers
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
);

-- Insert default tiers
INSERT OR IGNORE INTO tiers (tier_name, display_name, description, color_class, category, level) VALUES
('LT1', 'Lower Tier 1', 'Beginner', 'lt1', 'LT', 1),
('LT2', 'Lower Tier 2', 'Novice', 'lt2', 'LT', 2),
('LT3', 'Lower Tier 3', 'Intermediate', 'lt3', 'LT', 3),
('LT4', 'Lower Tier 4', 'Proficient', 'lt4', 'LT', 4),
('LT5', 'Lower Tier 5', 'Advanced', 'lt5', 'LT', 5),
('HT1', 'Higher Tier 1', 'Expert', 'ht1', 'HT', 1),
('HT2', 'Higher Tier 2', 'Master', 'ht2', 'HT', 2),
('HT3', 'Higher Tier 3', 'Elite', 'ht3', 'HT', 3),
('HT4', 'Higher Tier 4', 'Professional', 'ht4', 'HT', 4),
('HT5', 'Higher Tier 5', 'Legendary', 'ht5', 'HT', 5);

-- Insert default skill types
INSERT OR IGNORE INTO skill_types (skill_code, skill_name, description, icon_path) VALUES
('npot', 'Nether Pot', 'Nether portal techniques and strategies', 'img/neth-op.svg'),
('uhc', 'Ultra Hardcore', 'Ultra Hardcore PVP skills', 'img/uhc.svg'),
('cpvp', 'Crystal PVP', 'End crystal combat techniques', 'img/cpvp.svg'),
('sword', 'Sword Combat', 'Sword fighting techniques', 'img/sword.svg'),
('axe', 'Axe Combat', 'Axe combat techniques', 'img/axe.svg'),
('smp', 'Survival Multiplayer', 'General survival multiplayer skills', 'img/smp.svg'); 