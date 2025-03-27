import json
import logging
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from sqlalchemy import desc

from app.web.forms import ConfigurationForm, EmailTestForm
from app.database import Session, SignInLog, AuditLog, Alert, Configuration
from app.analyzer import run_all_detections
from app.alert import EmailSender
from app.config import ALERT_EMAIL_TO

logger = logging.getLogger(__name__)

# Create Blueprint
web_bp = Blueprint('web', __name__, template_folder='templates')

@web_bp.route('/')
def index():
    """Dashboard page"""
    session = Session()
    try:
        # Get recent alerts (last 7 days)
        recent_time = datetime.utcnow() - timedelta(days=7)
        alerts = session.query(Alert).filter(
            Alert.created_at > recent_time
        ).order_by(desc(Alert.created_at)).all()
        
        # Get alert counts by severity
        high_alerts = sum(1 for a in alerts if a.severity == 'high')
        medium_alerts = sum(1 for a in alerts if a.severity == 'medium')
        low_alerts = sum(1 for a in alerts if a.severity == 'low')
        
        # Get alert counts by type
        alert_types = {}
        for alert in alerts:
            if alert.alert_type not in alert_types:
                alert_types[alert.alert_type] = 0
            alert_types[alert.alert_type] += 1
            
        # Get recent sign-in logs count
        signin_count = session.query(SignInLog).filter(
            SignInLog.created_at > recent_time
        ).count()
        
        # Get recent audit logs count
        audit_count = session.query(AuditLog).filter(
            AuditLog.created_at > recent_time
        ).count()
        
        return render_template('index.html',
                              alerts=alerts,
                              high_alerts=high_alerts,
                              medium_alerts=medium_alerts,
                              low_alerts=low_alerts,
                              alert_types=alert_types,
                              signin_count=signin_count,
                              audit_count=audit_count)
    finally:
        session.close()

@web_bp.route('/alerts')
def alerts():
    """Alerts page"""
    session = Session()
    try:
        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        # Get filter parameters
        severity = request.args.get('severity')
        alert_type = request.args.get('type')
        days = request.args.get('days', 7, type=int)
        
        # Build query
        query = session.query(Alert)
        
        # Apply filters
        if severity:
            query = query.filter(Alert.severity == severity)
        if alert_type:
            query = query.filter(Alert.alert_type == alert_type)
        if days:
            recent_time = datetime.utcnow() - timedelta(days=days)
            query = query.filter(Alert.created_at > recent_time)
            
        # Get total count for pagination
        total = query.count()
        
        # Apply pagination
        alerts = query.order_by(desc(Alert.created_at)).limit(per_page).offset((page - 1) * per_page).all()
        
        # Get unique alert types for filter dropdown
        alert_types = session.query(Alert.alert_type).distinct().all()
        alert_types = [t[0] for t in alert_types]
        
        return render_template('alerts.html',
                              alerts=alerts,
                              page=page,
                              per_page=per_page,
                              total=total,
                              pages=(total + per_page - 1) // per_page,
                              severity=severity,
                              alert_type=alert_type,
                              days=days,
                              alert_types=alert_types)
    finally:
        session.close()

@web_bp.route('/alert/<int:alert_id>')
def alert_detail(alert_id):
    """Alert detail page"""
    session = Session()
    try:
        # Get the alert
        alert = session.query(Alert).filter(Alert.id == alert_id).first_or_404()
        
        # Parse additional data
        additional_data = {}
        if alert.additional_data:
            try:
                additional_data = json.loads(alert.additional_data)
            except json.JSONDecodeError:
                pass
                
        # Get source log
        source_log = None
        if alert.source_log_id and alert.source_log_type:
            if alert.source_log_type == 'signin':
                source_log = session.query(SignInLog).filter(
                    SignInLog.log_id == alert.source_log_id
                ).first()
            elif alert.source_log_type == 'audit':
                source_log = session.query(AuditLog).filter(
                    AuditLog.log_id == alert.source_log_id
                ).first()
                
        # Get raw log data
        raw_log_data = None
        if source_log and hasattr(source_log, 'raw_data'):
            try:
                raw_log_data = json.loads(source_log.raw_data)
                # Format for display
                raw_log_data = json.dumps(raw_log_data, indent=2)
            except json.JSONDecodeError:
                raw_log_data = source_log.raw_data
                
        return render_template('alert_detail.html',
                              alert=alert,
                              additional_data=additional_data,
                              source_log=source_log,
                              raw_log_data=raw_log_data)
    finally:
        session.close()

@web_bp.route('/signin-logs')
def signin_logs():
    """Sign-in logs page"""
    session = Session()
    try:
        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        # Get filter parameters
        status = request.args.get('status')
        user = request.args.get('user')
        days = request.args.get('days', 7, type=int)
        
        # Build query
        query = session.query(SignInLog)
        
        # Apply filters
        if status:
            query = query.filter(SignInLog.status == status)
        if user:
            query = query.filter(SignInLog.user_display_name.ilike(f'%{user}%'))
        if days:
            recent_time = datetime.utcnow() - timedelta(days=days)
            query = query.filter(SignInLog.created_at > recent_time)
            
        # Get total count for pagination
        total = query.count()
        
        # Apply pagination
        logs = query.order_by(desc(SignInLog.created_at)).limit(per_page).offset((page - 1) * per_page).all()
        
        return render_template('signin_logs.html',
                              logs=logs,
                              page=page,
                              per_page=per_page,
                              total=total,
                              pages=(total + per_page - 1) // per_page,
                              status=status,
                              user=user,
                              days=days)
    finally:
        session.close()

@web_bp.route('/audit-logs')
def audit_logs():
    """Audit logs page"""
    session = Session()
    try:
        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        # Get filter parameters
        activity = request.args.get('activity')
        actor = request.args.get('actor')
        days = request.args.get('days', 7, type=int)
        
        # Build query
        query = session.query(AuditLog)
        
        # Apply filters
        if activity:
            query = query.filter(AuditLog.activity_display_name.ilike(f'%{activity}%'))
        if actor:
            query = query.filter(AuditLog.actor_display_name.ilike(f'%{actor}%'))
        if days:
            recent_time = datetime.utcnow() - timedelta(days=days)
            query = query.filter(AuditLog.created_at > recent_time)
            
        # Get total count for pagination
        total = query.count()
        
        # Apply pagination
        logs = query.order_by(desc(AuditLog.created_at)).limit(per_page).offset((page - 1) * per_page).all()
        
        return render_template('audit_logs.html',
                              logs=logs,
                              page=page,
                              per_page=per_page,
                              total=total,
                              pages=(total + per_page - 1) // per_page,
                              activity=activity,
                              actor=actor,
                              days=days)
    finally:
        session.close()

@web_bp.route('/configuration', methods=['GET', 'POST'])
def configuration():
    """Configuration page"""
    session = Session()
    try:
        # Get current configuration
        config = Configuration.get_config(session)
        
        # Create form and populate with current values
        form = ConfigurationForm()
        
        if request.method == 'GET':
            # Populate form with current config values
            form.failed_login_threshold.data = config.get('failed_login_threshold', 5)
            form.failed_login_window.data = config.get('failed_login_window', 60)
            form.unusual_countries_enabled.data = config.get('unusual_countries_enabled', True)
            form.high_risk_countries.data = '\n'.join(config.get('high_risk_countries', ['RU', 'CN', 'KP', 'IR']))
            form.after_hours_alerts_enabled.data = config.get('after_hours_alerts_enabled', True)
            form.work_hours_start.data = config.get('work_hours_start', 8)
            form.work_hours_end.data = config.get('work_hours_end', 18)
            form.weekend_alerts_enabled.data = config.get('weekend_alerts_enabled', True)
            form.admin_account_alerts_enabled.data = config.get('admin_account_alerts_enabled', True)
            form.impossible_travel_alerts_enabled.data = config.get('impossible_travel_alerts_enabled', True)
            form.impossible_travel_speed_kmh.data = config.get('impossible_travel_speed_kmh', 800)
            form.new_device_alerts_enabled.data = config.get('new_device_alerts_enabled', True)
            form.alert_frequency_minutes.data = config.get('alert_frequency_minutes', 10)
            form.email_to.data = ALERT_EMAIL_TO
            
        elif form.validate_on_submit():
            # Update configuration with form values
            new_config = config.copy()
            
            new_config['failed_login_threshold'] = form.failed_login_threshold.data
            new_config['failed_login_window'] = form.failed_login_window.data
            new_config['unusual_countries_enabled'] = form.unusual_countries_enabled.data
            
            # Process high-risk countries
            high_risk_countries = []
            if form.high_risk_countries.data:
                lines = form.high_risk_countries.data.splitlines()
                for line in lines:
                    country_code = line.strip().upper()
                    if country_code:
                        high_risk_countries.append(country_code)
            new_config['high_risk_countries'] = high_risk_countries
            
            new_config['after_hours_alerts_enabled'] = form.after_hours_alerts_enabled.data
            new_config['work_hours_start'] = form.work_hours_start.data
            new_config['work_hours_end'] = form.work_hours_end.data
            new_config['weekend_alerts_enabled'] = form.weekend_alerts_enabled.data
            new_config['admin_account_alerts_enabled'] = form.admin_account_alerts_enabled.data
            new_config['impossible_travel_alerts_enabled'] = form.impossible_travel_alerts_enabled.data
            new_config['impossible_travel_speed_kmh'] = form.impossible_travel_speed_kmh.data
            new_config['new_device_alerts_enabled'] = form.new_device_alerts_enabled.data
            new_config['alert_frequency_minutes'] = form.alert_frequency_minutes.data
            
            # Save updated configuration
            Configuration.update_config(new_config, session)
            
            flash('Configuration updated successfully', 'success')
            return redirect(url_for('web.configuration'))
            
        # Email test form
        email_test_form = EmailTestForm()
        
        return render_template('configuration.html',
                              form=form,
                              email_test_form=email_test_form)
    finally:
        session.close()

@web_bp.route('/test-email', methods=['POST'])
def test_email():
    """Send test email"""
    form = EmailTestForm()
    
    if form.validate_on_submit():
        email = form.email.data
        
        # Create test alert
        test_alert = Alert(
            alert_type='test',
            severity='medium',
            title='Test Alert',
            description='This is a test alert to verify email delivery.',
            user_id='test',
            user_display_name='Test User',
            source_log_id='test',
            source_log_type='test',
            timestamp=datetime.utcnow(),
            additional_data=json.dumps({
                'test': True,
                'timestamp': datetime.utcnow().isoformat()
            })
        )
        
        # Send test email
        sender = EmailSender()
        
        # Override to email with test form value
        sender.to_email = email
        
        result = sender.send_alert_email(test_alert)
        
        if result:
            flash(f'Test email sent successfully to {email}', 'success')
        else:
            flash(f'Failed to send test email to {email}. Check logs for details.', 'danger')
            
    else:
        # Form validation failed
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'Error in {field}: {error}', 'danger')
                
    return redirect(url_for('web.configuration'))

@web_bp.route('/run-detection', methods=['POST'])
def run_detection():
    """Manually run detection"""
    try:
        # Run detection
        alerts = run_all_detections()
        
        # Send emails
        sender = EmailSender()
        emails_sent = sender.send_pending_alerts()
        
        flash(f'Detection ran successfully. {len(alerts)} new alerts generated. {emails_sent} emails sent.', 'success')
    except Exception as e:
        logger.error(f"Error running detection: {e}")
        flash(f'Error running detection: {str(e)}', 'danger')
        
    return redirect(url_for('web.index'))

@web_bp.route('/health')
def health():
    """Health check endpoint"""
    session = Session()
    try:
        # Check database connection
        session.execute("SELECT 1")
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500
    finally:
        session.close()
