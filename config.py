import os
import secrets
from datetime import timedelta

class Config:
    """Base configuration with shared settings"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(16)
    SESSION_TYPE = 'filesystem'
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    SESSION_PERMANENT = True
    
    # Database settings
    DATABASE = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'database.db')
    
    # Upload folders
    UPLOAD_FOLDER_PROFILE_PICS = 'static/uploads/profile_pics'
    UPLOAD_FOLDER_PROFILE_MUSIC = 'static/uploads/profile_music'
    UPLOAD_FOLDER_TEAM_LOGOS = 'static/uploads/team_logos'
    
    # Admin credentials - should be changed in production
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME') or "admin"
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD') or "admin123"
    
    # Ensure upload directories exist
    @staticmethod
    def init_app(app):
        os.makedirs(Config.UPLOAD_FOLDER_PROFILE_PICS, exist_ok=True)
        os.makedirs(Config.UPLOAD_FOLDER_PROFILE_MUSIC, exist_ok=True)
        os.makedirs(Config.UPLOAD_FOLDER_TEAM_LOGOS, exist_ok=True)

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        
        # Production-specific setup
        # Set up logging to file
        import logging
        from logging.handlers import RotatingFileHandler
        
        if not os.path.exists('logs'):
            os.mkdir('logs')
            
        file_handler = RotatingFileHandler('logs/cosmic_teams.log', 
                                          maxBytes=10240, 
                                          backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('CosmicTeams startup')

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
} 