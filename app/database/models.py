import datetime
import json
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session

from app.config import SQLALCHEMY_DATABASE_URI, DEFAULT_CONFIG

Base = declarative_base()

# Create engine and session
engine = create_engine(SQLALCHEMY_DATABASE_URI)
session_factory = sessionmaker(bind=engine)
Session = scoped_session(session_factory)


class SignInLog(Base):
    """Model for storing Microsoft Graph sign-in logs"""
    __tablename__ = 'sign_in_logs'

    id = Column(Integer, primary_key=True)
    log_id = Column(String(100), unique=True)  # Original ID from Microsoft Graph
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    user_id = Column(String(100))
    user_display_name = Column(String(200))
    user_principal_name = Column(String(200))
    app_display_name = Column(String(200))
    client_app_used = Column(String(100))
    ip_address = Column(String(50))
    location = Column(String(200))
    status = Column(String(100))
    device_detail = Column(Text)
    authentication_requirement = Column(String(100))
    auth_method = Column(String(100))
    risk_level = Column(String(50))
    risk_state = Column(String(50))
    timestamp = Column(DateTime)
    raw_data = Column(Text)  # Store the complete raw JSON for reference

    def __repr__(self):
        return f"<SignInLog(id='{self.id}', user='{self.user_display_name}', status='{self.status}')>"


class AuditLog(Base):
    """Model for storing Microsoft Graph audit logs (directory activities)"""
    __tablename__ = 'audit_logs'

    id = Column(Integer, primary_key=True)
    log_id = Column(String(100), unique=True)  # Original ID from Microsoft Graph
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    activity_display_name = Column(String(200))
    activity_type = Column(String(100))
    category = Column(String(100))
    actor_id = Column(String(100))
    actor_display_name = Column(String(200))
    target_resources = Column(Text)  # JSON string of target resources
    result = Column(String(50))
    result_reason = Column(String(200))
    timestamp = Column(DateTime)
    raw_data = Column(Text)  # Store the complete raw JSON for reference

    def __repr__(self):
        return f"<AuditLog(id='{self.id}', activity='{self.activity_display_name}', actor='{self.actor_display_name}')>"


class Alert(Base):
    """Model for storing generated security alerts"""
    __tablename__ = 'alerts'

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    alert_type = Column(String(100))
    severity = Column(String(50))  # 'high', 'medium', 'low'
    title = Column(String(200))
    description = Column(Text)
    user_id = Column(String(100))
    user_display_name = Column(String(200))
    source_log_id = Column(String(100))  # Reference to original log ID
    source_log_type = Column(String(50))  # 'signin' or 'audit'
    status = Column(String(50), default='new')  # 'new', 'in_progress', 'resolved', 'dismissed'
    timestamp = Column(DateTime)
    additional_data = Column(Text)  # JSON string of additional context data
    email_sent = Column(Boolean, default=False)

    def __repr__(self):
        return f"<Alert(id='{self.id}', type='{self.alert_type}', severity='{self.severity}')>"


class Configuration(Base):
    """Model for storing application configuration"""
    __tablename__ = 'configuration'

    id = Column(Integer, primary_key=True)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    config_data = Column(Text)  # JSON string of configuration options

    @classmethod
    def get_config(cls, session=None):
        """Get the current configuration or create default if none exists"""
        if not session:
            session = Session()
            should_close = True
        else:
            should_close = False

        try:
            config = session.query(cls).first()
            if not config:
                config = cls(config_data=json.dumps(DEFAULT_CONFIG))
                session.add(config)
                session.commit()
            return json.loads(config.config_data)
        finally:
            if should_close:
                session.close()

    @classmethod
    def update_config(cls, new_config, session=None):
        """Update the configuration with new values"""
        if not session:
            session = Session()
            should_close = True
        else:
            should_close = False

        try:
            config = session.query(cls).first()
            if not config:
                config = cls(config_data=json.dumps(new_config))
                session.add(config)
            else:
                config.config_data = json.dumps(new_config)
            session.commit()
            return True
        finally:
            if should_close:
                session.close()


# Create all tables if they don't exist
def init_db():
    Base.metadata.create_all(engine)
