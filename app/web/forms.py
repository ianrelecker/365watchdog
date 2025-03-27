from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, IntegerField, SelectField, TextAreaField, SubmitField, SelectMultipleField, widgets
from wtforms.validators import DataRequired, Email, NumberRange, Optional, Length

class MultiCheckboxField(SelectMultipleField):
    """Custom field for multiple checkbox input"""
    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()

class ConfigurationForm(FlaskForm):
    """Form for configuring detection settings"""
    
    # Failed login detection
    failed_login_threshold = IntegerField('Failed Login Threshold', 
                                         validators=[DataRequired(), NumberRange(min=1, max=100)],
                                         description='Number of failed logins to trigger an alert')
    failed_login_window = IntegerField('Failed Login Window (minutes)', 
                                      validators=[DataRequired(), NumberRange(min=5, max=1440)],
                                      description='Time window for counting failed logins')
    
    # Unusual location detection
    unusual_countries_enabled = BooleanField('Enable High-Risk Country Detection',
                                           description='Alert on sign-ins from high-risk countries')
    high_risk_countries = TextAreaField('High-Risk Countries (ISO country codes, one per line)',
                                      validators=[Optional()],
                                      description='List of ISO country codes considered high-risk')
    
    # After-hours detection
    after_hours_alerts_enabled = BooleanField('Enable After-Hours Sign-in Detection',
                                            description='Alert on sign-ins outside of business hours')
    work_hours_start = IntegerField('Work Hours Start (0-23)', 
                                   validators=[Optional(), NumberRange(min=0, max=23)],
                                   description='Start of business hours (24-hour format)')
    work_hours_end = IntegerField('Work Hours End (0-23)', 
                                 validators=[Optional(), NumberRange(min=0, max=23)],
                                 description='End of business hours (24-hour format)')
    weekend_alerts_enabled = BooleanField('Enable Weekend Sign-in Detection',
                                        description='Alert on sign-ins during weekends')
    
    # Admin account detection
    admin_account_alerts_enabled = BooleanField('Enable Admin Account Sign-in Detection',
                                              description='Alert on administrative account sign-ins')
    
    # Impossible travel detection
    impossible_travel_alerts_enabled = BooleanField('Enable Impossible Travel Detection',
                                                  description='Alert on impossible travel scenarios')
    impossible_travel_speed_kmh = IntegerField('Maximum Possible Travel Speed (km/h)', 
                                              validators=[Optional(), NumberRange(min=100, max=2000)],
                                              description='Maximum speed considered physically possible')
    
    # New device detection
    new_device_alerts_enabled = BooleanField('Enable New Device Detection',
                                           description='Alert when users sign in from new devices')
    
    # General settings
    alert_frequency_minutes = IntegerField('Minimum Time Between Similar Alerts (minutes)', 
                                          validators=[DataRequired(), NumberRange(min=1, max=1440)],
                                          description='Minimum time between similar alerts for the same user')
    
    # Email settings
    email_to = StringField('Alert Email Recipients',
                          validators=[Optional(), Email()],
                          description='Email address to send alerts to')
    
    # Save button
    submit = SubmitField('Save Configuration')

class EmailTestForm(FlaskForm):
    """Form for testing email delivery"""
    
    email = StringField('Test Email Address', 
                       validators=[DataRequired(), Email()],
                       description='Email address to send test alert to')
    
    submit = SubmitField('Send Test Email')
