import logging
import os
from datetime import datetime
from flask import Flask

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def create_app(test_config=None):
    """Create and configure the Flask application"""
    app = Flask(__name__)
    
    if test_config is None:
        # Load instance config
        app.config.from_mapping(
            SECRET_KEY=os.environ.get('FLASK_SECRET_KEY', 'dev'),
        )
    else:
        # Load test config
        app.config.from_mapping(test_config)
        
    # Register template filters
    @app.template_filter('from_json')
    def from_json(value):
        """Convert JSON string to Python object"""
        import json
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return {}
            
    # Context processor for templates
    @app.context_processor
    def inject_now():
        """Inject current time into templates"""
        return {'now': datetime.utcnow()}
        
    # Register blueprints
    from app.web import web_bp
    app.register_blueprint(web_bp)
    
    return app
