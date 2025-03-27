import logging
import time
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler

from app import create_app
from app.database import init_db, Session
from app.graph.client import GraphClient
from app.analyzer.log_processor import LogProcessor
from app.analyzer.detectors import run_all_detections
from app.alert.email_sender import EmailSender
from app.config import LOG_POLLING_INTERVAL

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create Flask app
app = create_app()

def fetch_and_process_logs():
    """
    Fetch logs from Microsoft Graph API and process them
    """
    logger.info("Starting log fetch and processing job")
    session = Session()
    
    try:
        # Initialize Graph client
        graph_client = GraphClient()
        
        # Initialize log processor
        log_processor = LogProcessor()
        
        # Get sign-in logs
        logger.info("Fetching sign-in logs from Microsoft Graph")
        signin_logs = graph_client.get_sign_in_logs(minutes=LOG_POLLING_INTERVAL)
        new_signin_logs = log_processor.process_sign_in_logs(signin_logs)
        logger.info(f"Processed {new_signin_logs} new sign-in logs")
        
        # Get audit logs
        logger.info("Fetching audit logs from Microsoft Graph")
        audit_logs = graph_client.get_audit_logs(minutes=LOG_POLLING_INTERVAL)
        new_audit_logs = log_processor.process_audit_logs(audit_logs)
        logger.info(f"Processed {new_audit_logs} new audit logs")
        
        # Clean up old logs
        log_processor.cleanup_old_logs()
        
        # Run detections
        if new_signin_logs > 0 or new_audit_logs > 0:
            logger.info("Running detection rules")
            alerts = run_all_detections(session)
            logger.info(f"Generated {len(alerts)} new alerts")
            
            # Send email alerts
            if alerts:
                logger.info("Sending email alerts")
                email_sender = EmailSender()
                emails_sent = email_sender.send_pending_alerts()
                logger.info(f"Sent {emails_sent} email notifications")
        
        logger.info("Log fetch and processing job completed")
    except Exception as e:
        logger.error(f"Error in fetch_and_process_logs: {e}")
    finally:
        session.close()

def init_scheduler():
    """
    Initialize the background scheduler for periodic tasks
    """
    scheduler = BackgroundScheduler()
    
    # Add log fetch and processing job
    scheduler.add_job(
        fetch_and_process_logs,
        'interval',
        minutes=LOG_POLLING_INTERVAL,
        id='fetch_logs',
        replace_existing=True
    )
    
    # Start the scheduler
    scheduler.start()
    logger.info(f"Scheduler started with log polling interval: {LOG_POLLING_INTERVAL} minutes")
    
    return scheduler

def main():
    """
    Main entry point for the application
    """
    # Initialize database
    init_db()
    logger.info("Database initialized")
    
    # Initialize scheduler
    scheduler = init_scheduler()
    
    try:
        # Run initial log fetch
        fetch_and_process_logs()
        
        # Run Flask app
        app.run(host='0.0.0.0', port=5000)
    except KeyboardInterrupt:
        logger.info("Application shutting down...")
        scheduler.shutdown()
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
        scheduler.shutdown()
        raise

if __name__ == '__main__':
    main()
