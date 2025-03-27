import json
import logging
import datetime
from datetime import datetime, timedelta
import json
from typing import List, Dict, Any

from app.database import Session, SignInLog, AuditLog, Alert, Configuration
from app.database.models import Base, engine

logger = logging.getLogger(__name__)

class LogProcessor:
    """Process and store Microsoft Graph logs"""
    
    def __init__(self):
        self.session = Session()
        self.config = Configuration.get_config(self.session)
        
    def __del__(self):
        """Ensure session is closed when object is destroyed"""
        self.session.close()
        
    def process_sign_in_logs(self, logs: List[Dict[Any, Any]]) -> int:
        """
        Process and store sign-in logs
        
        Args:
            logs: List of sign-in log entries from Microsoft Graph
            
        Returns:
            Number of new logs processed
        """
        new_logs_count = 0
        
        for log in logs:
            log_id = log.get('id')
            
            # Check if log already exists
            existing_log = self.session.query(SignInLog).filter_by(log_id=log_id).first()
            if existing_log:
                continue
                
            # Extract relevant fields
            timestamp = datetime.strptime(log.get('createdDateTime', ''), '%Y-%m-%dT%H:%M:%SZ') if log.get('createdDateTime') else None
            user_id = log.get('userId', '')
            user_display_name = log.get('userDisplayName', '')
            user_principal_name = log.get('userPrincipalName', '')
            app_display_name = log.get('appDisplayName', '')
            client_app = log.get('clientAppUsed', '')
            ip_address = log.get('ipAddress', '')
            
            # Process location info
            location_info = log.get('location', {})
            location = json.dumps(location_info) if location_info else '{}'
            
            # Process status info
            status_info = log.get('status', {})
            status = status_info.get('errorCode', '0')
            
            # Process device detail
            device_detail = json.dumps(log.get('deviceDetail', {}))
            
            # Process authentication info
            auth_requirement = log.get('authenticationRequirement', '')
            auth_method = ''
            auth_methods = log.get('authenticationMethodsUsed', [])
            if auth_methods and len(auth_methods) > 0:
                auth_method = auth_methods[0]
                
            # Process risk info
            risk_level = log.get('riskLevel', 'none')
            risk_state = log.get('riskState', 'none')
            
            # Create new SignInLog entry
            new_log = SignInLog(
                log_id=log_id,
                user_id=user_id,
                user_display_name=user_display_name,
                user_principal_name=user_principal_name,
                app_display_name=app_display_name,
                client_app_used=client_app,
                ip_address=ip_address,
                location=location,
                status=status,
                device_detail=device_detail,
                authentication_requirement=auth_requirement,
                auth_method=auth_method,
                risk_level=risk_level,
                risk_state=risk_state,
                timestamp=timestamp,
                raw_data=json.dumps(log)
            )
            
            self.session.add(new_log)
            new_logs_count += 1
            
        if new_logs_count > 0:
            self.session.commit()
            logger.info(f"Processed {new_logs_count} new sign-in logs")
            
        return new_logs_count
    
    def process_audit_logs(self, logs: List[Dict[Any, Any]]) -> int:
        """
        Process and store audit logs
        
        Args:
            logs: List of audit log entries from Microsoft Graph
            
        Returns:
            Number of new logs processed
        """
        new_logs_count = 0
        
        for log in logs:
            log_id = log.get('id')
            
            # Check if log already exists
            existing_log = self.session.query(AuditLog).filter_by(log_id=log_id).first()
            if existing_log:
                continue
                
            # Extract relevant fields
            timestamp = datetime.strptime(log.get('activityDateTime', ''), '%Y-%m-%dT%H:%M:%SZ') if log.get('activityDateTime') else None
            activity_display_name = log.get('activityDisplayName', '')
            activity_type = log.get('activityType', '')
            category = log.get('category', '')
            
            # Process initiator/actor info
            initiator = log.get('initiatedBy', {})
            user = initiator.get('user', {})
            actor_id = user.get('id', '')
            actor_display_name = user.get('displayName', '')
            
            # Process target resources
            target_resources = json.dumps(log.get('targetResources', []))
            
            # Process result info
            result = log.get('result', '')
            result_reason = log.get('resultReason', '')
            
            # Create new AuditLog entry
            new_log = AuditLog(
                log_id=log_id,
                activity_display_name=activity_display_name,
                activity_type=activity_type,
                category=category,
                actor_id=actor_id,
                actor_display_name=actor_display_name,
                target_resources=target_resources,
                result=result,
                result_reason=result_reason,
                timestamp=timestamp,
                raw_data=json.dumps(log)
            )
            
            self.session.add(new_log)
            new_logs_count += 1
            
        if new_logs_count > 0:
            self.session.commit()
            logger.info(f"Processed {new_logs_count} new audit logs")
            
        return new_logs_count
    
    def cleanup_old_logs(self):
        """Delete logs older than the retention period"""
        retention_days = self.config.get('log_retention_days', 30)
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        # Delete old sign-in logs
        old_signin_logs = self.session.query(SignInLog).filter(SignInLog.created_at < cutoff_date).delete()
        
        # Delete old audit logs
        old_audit_logs = self.session.query(AuditLog).filter(AuditLog.created_at < cutoff_date).delete()
        
        self.session.commit()
        logger.info(f"Cleaned up {old_signin_logs} old sign-in logs and {old_audit_logs} old audit logs")
