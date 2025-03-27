import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Microsoft Graph API settings
MS_CLIENT_ID = os.environ.get('MS_CLIENT_ID')
MS_CLIENT_SECRET = os.environ.get('MS_CLIENT_SECRET')
MS_TENANT_ID = os.environ.get('MS_TENANT_ID')
MS_AUTHORITY = f'https://login.microsoftonline.com/{MS_TENANT_ID}'
MS_GRAPH_ENDPOINT = 'https://graph.microsoft.com/v1.0'
MS_SCOPE = ['https://graph.microsoft.com/.default']

# Email settings (SMTP for Microsoft 365)
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.office365.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))  # 587 for TLS
SMTP_USERNAME = os.environ.get('SMTP_USERNAME')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD')
SMTP_USE_TLS = os.environ.get('SMTP_USE_TLS', 'True').lower() in ('true', '1', 't')
ALERT_EMAIL_FROM = os.environ.get('ALERT_EMAIL_FROM')
ALERT_EMAIL_TO = os.environ.get('ALERT_EMAIL_TO')

# Flask settings
FLASK_SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'dev_key_change_in_production')

# Database settings
DB_PATH = os.environ.get('DB_PATH', '/app/data/logs.db')
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
SQLALCHEMY_DATABASE_URI = f'sqlite:///{DB_PATH}'

# Log settings
LOG_POLLING_INTERVAL = int(os.environ.get('LOG_POLLING_INTERVAL', 2))  # minutes
LOG_RETENTION_DAYS = int(os.environ.get('LOG_RETENTION_DAYS', 30))  # days

# Detection thresholds (default values, can be changed via web interface)
DEFAULT_CONFIG = {
    'failed_login_threshold': 5,  # Number of failed logins to trigger alert
    'failed_login_window': 60,    # Time window in minutes for failed login threshold
    'unusual_countries_enabled': True,
    'high_risk_countries': ['RU', 'CN', 'KP', 'IR'],  # ISO country codes
    'after_hours_alerts_enabled': True,
    'work_hours_start': 8,        # 8 AM
    'work_hours_end': 18,         # 6 PM
    'weekend_alerts_enabled': True,
    'admin_account_alerts_enabled': True,
    'impossible_travel_alerts_enabled': True,
    'impossible_travel_speed_kmh': 800,  # Impossible if faster than this
    'new_device_alerts_enabled': True,
    'alert_frequency_minutes': 10,  # Minimum time between similar alerts
}
