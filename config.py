import os
from dotenv import load_dotenv
from typing import Dict, Any

# Load .env file if running locally
if os.getenv('GAE_ENV', '').startswith('standard'):
    # Running on Cloud Functions
    load_dotenv()

class ConfigError(Exception):
    """Raised when configuration is invalid"""
    pass

class Config:
    """Application configuration"""
    
    # Environment settings
    ENVIRONMENT = os.getenv('ENVIRONMENT', 'production')
    
    # Project configuration
    PROJECT_ID = os.environ.get('GCP_PROJECT_ID')
    
    # Slack configuration
    SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN")
    SLACK_SIGNING_SECRET = os.getenv("SLACK_SIGNING_SECRET")
    SLACK_APP_TOKEN = os.getenv("SLACK_APP_TOKEN")
    
    # Slack app details
    SLACK_APP_ID = os.getenv("SLACK_APP_ID", "A088N3P3AER")
    SLACK_TEAM_ID = os.getenv("SLACK_TEAM_ID", "T02DV1XGHFW")
    SLACK_APP_REDIRECT_URL = f"https://slack.com/app_redirect?app={SLACK_APP_ID}&team={SLACK_TEAM_ID}"
    
    # Slack app installation settings
    SLACK_CLIENT_ID = os.getenv("SLACK_CLIENT_ID")
    SLACK_CLIENT_SECRET = os.getenv("SLACK_CLIENT_SECRET")
    SLACK_REDIRECT_URI = os.getenv("SLACK_REDIRECT_URI", "https://your-server.com/slack/oauth_redirect")
    
    # App Mode Settings
    USE_SOCKET_MODE = os.getenv("USE_SOCKET_MODE", "true").lower() == "true"
    PORT = int(os.getenv("PORT", "3000"))
    
    # Dialogflow configuration
    DIALOGFLOW_PROJECT_ID = os.getenv("DIALOGFLOW_PROJECT_ID")
    DIALOGFLOW_LOCATION = os.getenv("DIALOGFLOW_LOCATION", "us-central1")
    DIALOGFLOW_AGENT_ID = os.getenv("DIALOGFLOW_AGENT_ID")
    CLIENT_ACCESS_TOKEN = os.getenv("CLIENT_ACCESS_TOKEN")
    
    # OAuth configuration for token refresh
    OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID")
    OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET")
    OAUTH_TOKEN_ENDPOINT = os.getenv("OAUTH_TOKEN_ENDPOINT")
    
    # OAuth authorization endpoints
    OAUTH_AUTH_ENDPOINT = os.getenv("OAUTH_AUTH_ENDPOINT", "https://app.dealmaker.tech/oauth/authorize")
    OAUTH_REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI", "https://your-cloud-function-url.com/oauth-callback")
    OAUTH_SCOPE = os.getenv("OAUTH_SCOPE", "read write")
    DEALMAKER_BASE_URL = os.getenv("DEALMAKER_BASE_URL", "https://app.dealmaker.tech/users/sign_in")
    POST_LOGIN_REDIRECT_PARAM = 'redirect_after_login' 
    
    # Google API credentials
    GOOGLE_APPLICATION_CREDENTIALS = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    
    # Firebase configuration
    FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID", "benbot-dev")
    FIREBASE_DATABASE_URL = os.getenv("FIREBASE_DATABASE_URL", "https://benbot-dev.firebaseio.com")
    
    # Application settings
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))
    CACHE_TIMEOUT = 300  # 5 minutes
    
    # Debug settings
    ENABLE_VERBOSE_LOGGING = os.environ.get('ENABLE_VERBOSE_LOGGING', 'true').lower() == 'true'
    PRINT_DIALOGFLOW_RESPONSES = os.environ.get('PRINT_DIALOGFLOW_RESPONSES', 'true').lower() == 'true'
    
    # Event handling
    IGNORE_RETRY_EVENTS = os.environ.get('IGNORE_RETRY_EVENTS', 'true').lower() == 'true'
    
    # App installation
    ALLOW_REINSTALLS = os.environ.get('ALLOW_REINSTALLS', 'true').lower() == 'true'

    @classmethod
    def validate(cls) -> None:
        """Validate required configuration"""
        required_vars = [
            'SLACK_BOT_TOKEN',
            'SLACK_SIGNING_SECRET',
            'DIALOGFLOW_PROJECT_ID'
        ]
        
        missing = [var for var in required_vars if not getattr(cls, var)]
        if missing:
            raise ConfigError(f"Missing required config variables: {', '.join(missing)}")

    @classmethod
    def is_production(cls) -> bool:
        """Check if running in production environment"""
        return cls.ENVIRONMENT.lower() == 'production'
