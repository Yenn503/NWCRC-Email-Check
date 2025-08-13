import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Application configuration"""
    
    # HaveIBeenPwned API Configuration
    HIBP_API_KEY = os.environ.get('HIBP_API_KEY')
    
    # Rate limiting
    RATE_LIMIT_PER_MINUTE = int(os.environ.get('RATE_LIMIT_PER_MINUTE', 10))
    # Optional: check HIBP pastes (can slow scanning, doubles API calls)
    CHECK_PASTES = os.environ.get('CHECK_PASTES', 'true').lower() == 'true'
    
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    # Host/Port (default to 0.0.0.0:8000 to avoid macOS ControlCenter on 5000)
    HOST = os.environ.get('HOST', '0.0.0.0')
    # Respect PORT if set (e.g., cloud), else APP_PORT, else default 8000
    PORT = int(os.environ.get('PORT', os.environ.get('APP_PORT', 8000)))
    
    # File upload settings
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    UPLOAD_FOLDER = 'uploads'
    EXPORT_FOLDER = 'exports'
    
    @staticmethod
    def validate_config():
        """Validate required configuration"""
        if not Config.HIBP_API_KEY or Config.HIBP_API_KEY == 'your_api_key_here':
            raise ValueError(
                "HIBP_API_KEY is required. Please set it in your .env file.\n"
                "Get your API key from: https://haveibeenpwned.com/API/Key"
            )
        
        return True
