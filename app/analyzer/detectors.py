import json
import logging
import datetime
from datetime import datetime, timedelta
import json
from typing import List, Dict, Any, Optional, Tuple
import math
from geopy.distance import geodesic

from app.database import Session, SignInLog, AuditLog, Alert, Configuration

logger = logging.getLogger(__name__)

class BaseDetector:
    """Base class for log detectors"""
    
    def __init__(self, session=None):
        self.session = session or Session()
        self.config = Configuration.get_config(self.session)
        
    def __del__(self):
        """Ensure session is closed when object is destroyed"""
        if self.session:
            self.session.close()
            
    def create_alert(self, alert_type: str, severity: str, title: str, description: str,
                    user_id: str, user_display_name: str, source_log_id: str, 
                    source_log_type: str, timestamp: datetime, additional_data: Dict = None) -> Alert:
        """
        Create a new alert
        
        Args:
            alert_type: Type of alert (e.g., 'failed_login', 'suspicious_auth')
            severity: Severity level ('high', 'medium', 'low')
            title: Alert title
            description: Detailed description
            user_id: Affected user ID
            user_display_name: Affected user display name
            source_log_id: ID of the log that triggered the alert
            source_log_type: Type of source log ('signin' or 'audit')
            timestamp: Time of the event
            additional_data: Additional context data
            
        Returns:
            Created Alert object
        """
        if additional_data is None:
            additional_data = {}
            
        # Check if similar alert was created recently
        alert_frequency = self.config.get('alert_frequency_minutes', 10)
        recent_time = datetime.utcnow() - timedelta(minutes=alert_frequency)
        
        existing_alert = self.session.query(Alert).filter(
            Alert.alert_type == alert_type,
            Alert.user_id == user_id,
            Alert.created_at > recent_time
        ).first()
        
        if existing_alert:
            logger.info(f"Similar alert already exists for {alert_type} and user {user_display_name}")
            return None
            
        alert = Alert(
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=description,
            user_id=user_id,
            user_display_name=user_display_name,
            source_log_id=source_log_id,
            source_log_type=source_log_type,
            timestamp=timestamp,
            additional_data=json.dumps(additional_data)
        )
        
        self.session.add(alert)
        self.session.commit()
        
        logger.info(f"Created new {severity} alert: {title}")
        return alert


class SignInDetector(BaseDetector):
    """Detector for suspicious sign-in activities"""
    
    def detect_failed_logins(self) -> List[Alert]:
        """Detect multiple failed login attempts within a time window"""
        alerts = []
        
        # Get configuration values
        threshold = self.config.get('failed_login_threshold', 5)
        window_minutes = self.config.get('failed_login_window', 60)
        
        # Calculate time window
        time_window = datetime.utcnow() - timedelta(minutes=window_minutes)
        
        # Find users with multiple failed logins
        failed_logins = self.session.query(SignInLog).filter(
            SignInLog.status != '0',  # Non-zero status indicates failure
            SignInLog.timestamp > time_window
        ).all()
        
        # Group by user
        user_failures = {}
        for log in failed_logins:
            user_id = log.user_id
            if user_id not in user_failures:
                user_failures[user_id] = []
            user_failures[user_id].append(log)
            
        # Check if any user exceeds threshold
        for user_id, logs in user_failures.items():
            if len(logs) >= threshold:
                # Get user details from first log
                log = logs[0]
                
                # Create alert
                description = f"User had {len(logs)} failed login attempts in the past {window_minutes} minutes."
                description += f" Latest failure from IP: {log.ip_address}"
                
                alert = self.create_alert(
                    alert_type='failed_login',
                    severity='high',
                    title=f"Multiple Failed Logins: {log.user_display_name}",
                    description=description,
                    user_id=user_id,
                    user_display_name=log.user_display_name,
                    source_log_id=log.log_id,
                    source_log_type='signin',
                    timestamp=log.timestamp,
                    additional_data={
                        'failed_count': len(logs),
                        'time_window_minutes': window_minutes,
                        'ip_address': log.ip_address,
                        'failure_codes': [l.status for l in logs]
                    }
                )
                
                if alert:
                    alerts.append(alert)
                    
        return alerts
    
    def detect_unusual_location(self) -> List[Alert]:
        """Detect sign-ins from unusual or high-risk countries"""
        alerts = []
        
        # Skip if feature disabled
        if not self.config.get('unusual_countries_enabled', True):
            return alerts
            
        # Get high-risk countries
        high_risk_countries = self.config.get('high_risk_countries', ['RU', 'CN', 'KP', 'IR'])
        
        # Get recent successful logins
        recent_logins = self.session.query(SignInLog).filter(
            SignInLog.status == '0',  # Successful login
            SignInLog.timestamp > (datetime.utcnow() - timedelta(hours=24))
        ).all()
        
        for log in recent_logins:
            # Parse location data
            try:
                location_data = json.loads(log.location)
                country_code = location_data.get('countryLetterCode', '')
                
                if country_code in high_risk_countries:
                    # Create alert for high-risk country
                    country_name = location_data.get('countryOrRegion', country_code)
                    city = location_data.get('city', 'Unknown')
                    
                    description = f"User signed in from {city}, {country_name} "
                    description += f"({country_code}), which is on the high-risk countries list."
                    
                    alert = self.create_alert(
                        alert_type='high_risk_location',
                        severity='high',
                        title=f"Sign-in from High-Risk Country: {log.user_display_name}",
                        description=description,
                        user_id=log.user_id,
                        user_display_name=log.user_display_name,
                        source_log_id=log.log_id,
                        source_log_type='signin',
                        timestamp=log.timestamp,
                        additional_data={
                            'country_code': country_code,
                            'country': country_name,
                            'city': city,
                            'ip_address': log.ip_address
                        }
                    )
                    
                    if alert:
                        alerts.append(alert)
                        
            except (json.JSONDecodeError, AttributeError):
                continue
                
        return alerts
    
    def detect_after_hours(self) -> List[Alert]:
        """Detect sign-ins outside of normal business hours"""
        alerts = []
        
        # Skip if feature disabled
        if not self.config.get('after_hours_alerts_enabled', True):
            return alerts
            
        # Get work hours configuration
        work_start = self.config.get('work_hours_start', 8)  # 8 AM
        work_end = self.config.get('work_hours_end', 18)    # 6 PM
        weekend_alerts = self.config.get('weekend_alerts_enabled', True)
        
        # Get recent successful logins
        recent_logins = self.session.query(SignInLog).filter(
            SignInLog.status == '0',  # Successful login
            SignInLog.timestamp > (datetime.utcnow() - timedelta(hours=24))
        ).all()
        
        for log in recent_logins:
            if not log.timestamp:
                continue
                
            # Check if login is after hours
            hour = log.timestamp.hour
            day = log.timestamp.weekday()  # 0 = Monday, 6 = Sunday
            
            is_weekend = day >= 5  # Saturday or Sunday
            is_after_hours = hour < work_start or hour >= work_end
            
            if (is_after_hours or (is_weekend and weekend_alerts)):
                # Get time description
                time_desc = "weekend" if is_weekend else "after hours"
                
                description = f"User signed in during {time_desc} at {log.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}."
                description += f" IP address: {log.ip_address}"
                
                alert = self.create_alert(
                    alert_type='after_hours_login',
                    severity='medium',
                    title=f"After Hours Sign-in: {log.user_display_name}",
                    description=description,
                    user_id=log.user_id,
                    user_display_name=log.user_display_name,
                    source_log_id=log.log_id,
                    source_log_type='signin',
                    timestamp=log.timestamp,
                    additional_data={
                        'ip_address': log.ip_address,
                        'login_hour': hour,
                        'login_day': day,
                        'is_weekend': is_weekend
                    }
                )
                
                if alert:
                    alerts.append(alert)
                    
        return alerts
    
    def detect_admin_access(self) -> List[Alert]:
        """Detect sign-ins to administrative accounts"""
        alerts = []
        
        # Skip if feature disabled
        if not self.config.get('admin_account_alerts_enabled', True):
            return alerts
            
        # Get recent logins with admin accounts
        # This would need additional Microsoft Graph API calls to check if user is admin
        # For simplicity, we'll just check for keywords in display name or app name
        admin_keywords = ['admin', 'administrator', 'root', 'superuser', 'security', 'global admin']
        
        recent_logins = self.session.query(SignInLog).filter(
            SignInLog.status == '0',  # Successful login
            SignInLog.timestamp > (datetime.utcnow() - timedelta(hours=24))
        ).all()
        
        for log in recent_logins:
            # Check if account or app has admin keywords
            is_admin_login = False
            user_name = log.user_display_name.lower() if log.user_display_name else ''
            app_name = log.app_display_name.lower() if log.app_display_name else ''
            
            for keyword in admin_keywords:
                if keyword in user_name or keyword in app_name:
                    is_admin_login = True
                    break
                    
            if is_admin_login:
                description = f"Administrative account logged in at {log.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}."
                description += f" IP address: {log.ip_address}, Application: {log.app_display_name}"
                
                alert = self.create_alert(
                    alert_type='admin_login',
                    severity='medium',
                    title=f"Administrative Account Sign-in: {log.user_display_name}",
                    description=description,
                    user_id=log.user_id,
                    user_display_name=log.user_display_name,
                    source_log_id=log.log_id,
                    source_log_type='signin',
                    timestamp=log.timestamp,
                    additional_data={
                        'ip_address': log.ip_address,
                        'app_name': log.app_display_name,
                        'client_app': log.client_app_used
                    }
                )
                
                if alert:
                    alerts.append(alert)
                    
        return alerts
    
    def detect_impossible_travel(self) -> List[Alert]:
        """Detect sign-ins from different locations in timeframe that makes travel impossible"""
        alerts = []
        
        # Skip if feature disabled
        if not self.config.get('impossible_travel_alerts_enabled', True):
            return alerts
            
        # Get impossible travel speed
        max_speed_kmh = self.config.get('impossible_travel_speed_kmh', 800)  # km/h
        
        # Get users who logged in multiple times in the past 24 hours
        recent_time = datetime.utcnow() - timedelta(hours=24)
        
        # Get successful logins
        recent_logins = self.session.query(SignInLog).filter(
            SignInLog.status == '0',  # Successful login
            SignInLog.timestamp > recent_time
        ).all()
        
        # Group by user
        user_logins = {}
        for log in recent_logins:
            user_id = log.user_id
            if user_id not in user_logins:
                user_logins[user_id] = []
            user_logins[user_id].append(log)
            
        # Check users with multiple logins
        for user_id, logs in user_logins.items():
            if len(logs) < 2:
                continue
                
            # Sort logs by timestamp
            logs.sort(key=lambda x: x.timestamp if x.timestamp else datetime.min)
            
            # Check consecutive logins for impossible travel
            for i in range(len(logs) - 1):
                log1 = logs[i]
                log2 = logs[i + 1]
                
                if not log1.timestamp or not log2.timestamp:
                    continue
                    
                # Extract location data
                try:
                    loc1 = json.loads(log1.location)
                    loc2 = json.loads(log2.location)
                    
                    lat1 = loc1.get('geoCoordinates', {}).get('latitude')
                    lon1 = loc1.get('geoCoordinates', {}).get('longitude')
                    lat2 = loc2.get('geoCoordinates', {}).get('latitude')
                    lon2 = loc2.get('geoCoordinates', {}).get('longitude')
                    
                    # Skip if coordinates missing
                    if not all([lat1, lon1, lat2, lon2]):
                        continue
                        
                    # Calculate distance
                    point1 = (lat1, lon1)
                    point2 = (lat2, lon2)
                    distance_km = geodesic(point1, point2).kilometers
                    
                    # Skip if distance is small
                    if distance_km < 100:
                        continue
                        
                    # Calculate time difference
                    time_diff = log2.timestamp - log1.timestamp
                    hours_diff = time_diff.total_seconds() / 3600.0
                    
                    # Calculate required speed
                    if hours_diff > 0:
                        required_speed = distance_km / hours_diff
                        
                        # Check if speed is impossible
                        if required_speed > max_speed_kmh:
                            city1 = loc1.get('city', 'Unknown')
                            city2 = loc2.get('city', 'Unknown')
                            country1 = loc1.get('countryOrRegion', 'Unknown')
                            country2 = loc2.get('countryOrRegion', 'Unknown')
                            
                            description = f"User appears to have traveled from {city1}, {country1} to {city2}, {country2} "
                            description += f"({distance_km:.0f} km) in {hours_diff:.1f} hours, "
                            description += f"requiring a travel speed of {required_speed:.0f} km/h."
                            
                            alert = self.create_alert(
                                alert_type='impossible_travel',
                                severity='high',
                                title=f"Impossible Travel Detected: {log1.user_display_name}",
                                description=description,
                                user_id=user_id,
                                user_display_name=log1.user_display_name,
                                source_log_id=log2.log_id,
                                source_log_type='signin',
                                timestamp=log2.timestamp,
                                additional_data={
                                    'first_location': f"{city1}, {country1}",
                                    'second_location': f"{city2}, {country2}",
                                    'distance_km': round(distance_km),
                                    'time_diff_hours': round(hours_diff, 2),
                                    'required_speed': round(required_speed),
                                    'first_ip': log1.ip_address,
                                    'second_ip': log2.ip_address
                                }
                            )
                            
                            if alert:
                                alerts.append(alert)
                                
                except (json.JSONDecodeError, AttributeError, KeyError, TypeError):
                    continue
                    
        return alerts
    
    def run_all_detectors(self) -> List[Alert]:
        """Run all sign-in detectors and return alerts"""
        all_alerts = []
        
        # Run each detector and collect alerts
        all_alerts.extend(self.detect_failed_logins())
        all_alerts.extend(self.detect_unusual_location())
        all_alerts.extend(self.detect_after_hours())
        all_alerts.extend(self.detect_admin_access())
        all_alerts.extend(self.detect_impossible_travel())
        
        return all_alerts


class AuditDetector(BaseDetector):
    """Detector for suspicious audit log activities"""
    
    def detect_sensitive_changes(self) -> List[Alert]:
        """Detect changes to sensitive settings or permissions"""
        alerts = []
        
        # Get recent audit logs
        recent_logs = self.session.query(AuditLog).filter(
            AuditLog.timestamp > (datetime.utcnow() - timedelta(hours=24))
        ).all()
        
        # Sensitive operations to detect
        sensitive_operations = [
            'Add member to role',
            'Add user',
            'Add owner to service principal',
            'Update service principal',
            'Update application',
            'Add app role assignment to service principal',
            'Add delegated permission grant',
            'Add service principal',
            'Change user password',
            'Reset user password',
            'Add OAuth2PermissionGrant',
            'Consent to application',
            'Update conditional access policy',
            'Update policy',
            'Update organization settings',
            'Disable Strong Authentication',
            'Update SAML2 token signing certificate',
            'Add domain to company',
            'Set DirSync enabled'
        ]
        
        for log in recent_logs:
            # Check if operation is sensitive
            if log.activity_display_name in sensitive_operations:
                description = f"Sensitive operation '{log.activity_display_name}' performed"
                description += f" by {log.actor_display_name} at {log.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}."
                
                # Extract target resources
                try:
                    target_resources = json.loads(log.target_resources)
                    target_info = []
                    
                    for resource in target_resources:
                        resource_type = resource.get('type', 'Unknown')
                        resource_name = resource.get('displayName', 'Unknown')
                        target_info.append(f"{resource_type}: {resource_name}")
                        
                    if target_info:
                        description += f" Target resources: {', '.join(target_info)}"
                except (json.JSONDecodeError, TypeError):
                    pass
                    
                alert = self.create_alert(
                    alert_type='sensitive_change',
                    severity='high',
                    title=f"Sensitive Operation: {log.activity_display_name}",
                    description=description,
                    user_id=log.actor_id,
                    user_display_name=log.actor_display_name,
                    source_log_id=log.log_id,
                    source_log_type='audit',
                    timestamp=log.timestamp,
                    additional_data={
                        'activity': log.activity_display_name,
                        'category': log.category,
                        'result': log.result,
                        'result_reason': log.result_reason
                    }
                )
                
                if alert:
                    alerts.append(alert)
                    
        return alerts
    
    def run_all_detectors(self) -> List[Alert]:
        """Run all audit log detectors and return alerts"""
        all_alerts = []
        
        # Run each detector and collect alerts
        all_alerts.extend(self.detect_sensitive_changes())
        
        return all_alerts


def run_all_detections(session=None) -> List[Alert]:
    """Run all detectors and return all alerts"""
    session = session or Session()
    
    try:
        all_alerts = []
        
        # Run sign-in detectors
        signin_detector = SignInDetector(session)
        all_alerts.extend(signin_detector.run_all_detectors())
        
        # Run audit detectors
        audit_detector = AuditDetector(session)
        all_alerts.extend(audit_detector.run_all_detectors())
        
        return all_alerts
    finally:
        session.close()
