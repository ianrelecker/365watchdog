import logging
import json
import smtplib
import ssl
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict

from app.database import Alert, Configuration, Session
from app.config import (
    SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SMTP_USE_TLS,
    ALERT_EMAIL_FROM, ALERT_EMAIL_TO
)

logger = logging.getLogger(__name__)

class EmailSender:
    """Email notification sender for alerts using SMTP (compatible with Microsoft 365)"""
    
    def __init__(self):
        self.smtp_server = SMTP_SERVER
        self.smtp_port = SMTP_PORT
        self.username = SMTP_USERNAME
        self.password = SMTP_PASSWORD
        self.use_tls = SMTP_USE_TLS
        self.from_email = ALERT_EMAIL_FROM
        self.to_email = ALERT_EMAIL_TO
        self.session = Session()
        self.config = Configuration.get_config(self.session)
        
    def __del__(self):
        """Ensure session is closed when object is destroyed"""
        if self.session:
            self.session.close()
            
    def format_alert_html(self, alert: Alert) -> str:
        """Format an alert into HTML for email notification"""
        try:
            # Parse additional data
            additional_data = json.loads(alert.additional_data) if alert.additional_data else {}
            
            # Determine color based on severity
            if alert.severity == 'high':
                severity_color = '#ff4444'  # Red
            elif alert.severity == 'medium':
                severity_color = '#ffbb33'  # Orange/Amber
            else:
                severity_color = '#33b5e5'  # Blue
                
            # Format timestamp
            timestamp_str = alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC') if alert.timestamp else 'Unknown'
                
            # Build HTML content
            html = f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <div style="background-color: #0078d4; color: white; padding: 20px; text-align: center;">
                    <h1 style="margin: 0;">Microsoft 365 Security Alert</h1>
                </div>
                
                <div style="padding: 20px; border: 1px solid #ddd; background-color: #f9f9f9;">
                    <div style="margin-bottom: 20px; padding: 15px; background-color: {severity_color}; color: white; border-radius: 5px;">
                        <h2 style="margin: 0;">{alert.title}</h2>
                        <p style="margin: 5px 0 0 0;">Severity: {alert.severity.upper()}</p>
                    </div>
                    
                    <h3>Alert Details</h3>
                    <p style="white-space: pre-line;">{alert.description}</p>
                    
                    <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                        <tr>
                            <th style="text-align: left; padding: 8px; border-bottom: 1px solid #ddd;">Property</th>
                            <th style="text-align: left; padding: 8px; border-bottom: 1px solid #ddd;">Value</th>
                        </tr>
                        <tr>
                            <td style="padding: 8px; border-bottom: 1px solid #ddd;">User</td>
                            <td style="padding: 8px; border-bottom: 1px solid #ddd;">{alert.user_display_name}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px; border-bottom: 1px solid #ddd;">Timestamp</td>
                            <td style="padding: 8px; border-bottom: 1px solid #ddd;">{timestamp_str}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px; border-bottom: 1px solid #ddd;">Alert Type</td>
                            <td style="padding: 8px; border-bottom: 1px solid #ddd;">{alert.alert_type}</td>
                        </tr>
            """
            
            # Add additional data rows to table
            for key, value in additional_data.items():
                # Format key for display
                display_key = ' '.join(word.capitalize() for word in key.split('_'))
                html += f"""
                        <tr>
                            <td style="padding: 8px; border-bottom: 1px solid #ddd;">{display_key}</td>
                            <td style="padding: 8px; border-bottom: 1px solid #ddd;">{value}</td>
                        </tr>
                """
                
            # Add recommended actions based on alert type
            recommendations = self.get_recommendations(alert.alert_type)
            
            html += f"""
                    </table>
                    
                    <div style="margin-top: 20px; padding: 15px; background-color: #e1f5fe; border-radius: 5px;">
                        <h3 style="margin-top: 0;">Recommended Actions</h3>
                        <ul>
            """
            
            for recommendation in recommendations:
                html += f"<li>{recommendation}</li>"
                
            html += f"""
                        </ul>
                    </div>
                </div>
                
                <div style="padding: 20px; text-align: center; color: #666; font-size: 12px;">
                    <p>This is an automated security alert from your Microsoft 365 Graph Monitoring system.</p>
                    <p>Alert ID: {alert.id} | Generated at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                </div>
            </div>
            """
            
            return html
        except Exception as e:
            logger.error(f"Error formatting alert HTML: {e}")
            # Fallback to simple format
            return f"<h1>Security Alert: {alert.title}</h1><p>{alert.description}</p>"
    
    def get_recommendations(self, alert_type: str) -> List[str]:
        """Get recommended actions based on alert type"""
        recommendations = {
            'failed_login': [
                "Review the sign-in logs to verify if this is a legitimate user having trouble or a potential attack.",
                "Contact the user to confirm if they were attempting to sign in.",
                "If suspicious, consider temporarily blocking the user account and resetting the password.",
                "Review the IP addresses involved for potential blocklisting."
            ],
            'high_risk_location': [
                "Contact the user to verify if they are traveling in this location.",
                "If the user did not initiate this sign-in, immediately disable the account and reset credentials.",
                "Consider adding conditional access policies to block or require additional verification for high-risk countries.",
                "Check for other suspicious activities from the same IP address or region."
            ],
            'after_hours_login': [
                "Verify with the user if this was a legitimate sign-in.",
                "Check the user's normal working pattern and travel schedule.",
                "Consider updating conditional access policies for time-based restrictions if needed."
            ],
            'admin_login': [
                "Confirm that the admin activity was authorized.",
                "Review what actions were performed after the sign-in.",
                "Consider implementing Privileged Identity Management for just-in-time admin access.",
                "Ensure that all admin accounts are protected with MFA."
            ],
            'impossible_travel': [
                "Immediately contact the user to verify both sign-ins.",
                "If either sign-in was unauthorized, disable the account and reset credentials.",
                "Check for additional suspicious activities from both IP addresses.",
                "Consider implementing location-based conditional access policies."
            ],
            'sensitive_change': [
                "Verify that this change was authorized and properly documented.",
                "Review the specific resources that were modified and their current state.",
                "Check for any related changes that might be part of a larger attack.",
                "Consider restoring previous settings if the change was not authorized."
            ]
        }
        
        # Return recommendations for the alert type, or default recommendations
        return recommendations.get(alert_type, [
            "Investigate the alert details to determine if this is a security incident.",
            "Contact affected users to verify if the activity was legitimate.",
            "Review related audit logs for additional suspicious activities.",
            "Update security policies if needed to prevent similar incidents."
        ])
    
    def send_alert_email(self, alert: Alert) -> bool:
        """
        Send email notification for an alert using SMTP
        
        Args:
            alert: The Alert object to send notification for
            
        Returns:
            bool: True if email was sent successfully, False otherwise
        """
        if not self.smtp_server or not self.username or not self.password or not self.from_email or not self.to_email:
            logger.error("Missing email configuration (SMTP server, username, password, from, or to email)")
            return False
            
        try:
            # Format email content
            html_content = self.format_alert_html(alert)
            
            # Create email message
            message = MIMEMultipart("alternative")
            message["Subject"] = f"SECURITY ALERT: {alert.title}"
            message["From"] = self.from_email
            message["To"] = self.to_email
            
            # Add HTML content
            html_part = MIMEText(html_content, "html")
            message.attach(html_part)
            
            # Create a plain text version as fallback
            plain_text = f"SECURITY ALERT: {alert.title}\n\n{alert.description}\n\nSeverity: {alert.severity.upper()}\nUser: {alert.user_display_name}\nAlert Type: {alert.alert_type}"
            text_part = MIMEText(plain_text, "plain")
            message.attach(text_part)
            
            # Connect to SMTP server and send email
            context = ssl.create_default_context()
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls(context=context)
                server.login(self.username, self.password)
                server.sendmail(self.from_email, self.to_email, message.as_string())
                
            logger.info(f"Alert email sent successfully for alert ID {alert.id}")
            
            # Update alert as email sent
            alert.email_sent = True
            self.session.commit()
            
            return True
                
        except Exception as e:
            logger.error(f"Error sending alert email: {e}")
            return False
    
    def send_pending_alerts(self) -> int:
        """
        Send emails for all pending alerts
        
        Returns:
            int: Number of emails sent
        """
        # Get all unsent alerts
        pending_alerts = self.session.query(Alert).filter(
            Alert.email_sent == False
        ).all()
        
        sent_count = 0
        for alert in pending_alerts:
            if self.send_alert_email(alert):
                sent_count += 1
                
        return sent_count
