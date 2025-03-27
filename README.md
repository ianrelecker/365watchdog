# Microsoft 365 Graph Security Monitor

A Docker container that monitors Microsoft 365 sign-in and audit logs for suspicious activities and sends email alerts.

![Microsoft 365 Security Monitor](https://img.shields.io/badge/Microsoft%20365-Security%20Monitor-blue)
![Docker](https://img.shields.io/badge/Docker-Ready-brightgreen)
![Python](https://img.shields.io/badge/Python-3.11-blue)

## Features

- Connects to Microsoft Graph API to fetch sign-in and audit logs
- Detects suspicious activities like:
  - Multiple failed login attempts
  - Sign-ins from unusual locations or high-risk countries
  - After-hours or weekend login activity
  - Administrative account usage
  - Impossible travel scenarios
  - Sensitive account or permission changes
- Sends email notifications for detected security events
- Provides a web interface for configuration and alert management
- Stores log data with customizable retention period

## Prerequisites

- Docker and Docker Compose
- Microsoft 365 account with admin permissions
- Registered Azure AD application with appropriate permissions
- Microsoft 365 or other SMTP-compatible email account for notifications

## Setup Instructions

### 1. Register Azure AD Application

1. Go to the Azure Portal and navigate to Azure Active Directory
2. Select "App registrations" and click "New registration"
3. Name the application (e.g., "MS Graph Security Monitor")
4. Select "Accounts in this organizational directory only"
5. Click "Register"
6. Note the "Application (client) ID" and "Directory (tenant) ID"
7. Go to "Certificates & secrets" and create a new client secret
8. Note the client secret value (you'll only see it once)
9. Go to "API permissions" and add the following permissions:
   - Microsoft Graph API > Application permissions:
     - AuditLog.Read.All
     - Directory.Read.All
     - User.Read.All
10. Click "Grant admin consent"

### 2. Configure the Application

1. Clone this repository
2. Create a `.env` file from the `.env.sample` template:
   ```bash
   cp .env.sample .env
   ```
3. Edit the `.env` file and add your:
   - Microsoft Graph API credentials (client ID, client secret, tenant ID)
   - Email settings (SMTP server, credentials, from/to addresses)
   - Other custom settings as needed

### 3. Build and Run the Container

```bash
docker-compose up -d
```

The web interface will be available at http://localhost:5000

### 4. Configure Detection Settings

After starting the container, you can configure detection settings through the web interface:

1. Access the web interface at http://localhost:5000
2. Go to the "Configuration" page
3. Adjust settings like:
   - Failed login thresholds
   - Working hours
   - High-risk countries
   - Email notification settings
4. Save your configuration

## How It Works

1. The container polls Microsoft Graph API every 2 minutes to fetch new sign-in and audit logs
2. New logs are stored in a SQLite database for analysis
3. Detection rules analyze logs for suspicious patterns
4. When suspicious activities are detected, alerts are generated
5. Email notifications are sent for new alerts
6. The web interface allows users to view logs, alerts, and adjust settings

## Detection Examples

The monitor detects various suspicious activities, including:

- **Failed Login Detection**: Alerts when a user has multiple failed login attempts within a configured time window.
- **Unusual Location**: Alerts when a user signs in from a high-risk country or unusual location.
- **After-Hours Login**: Alerts when a user signs in outside of regular business hours or on weekends.
- **Admin Account Access**: Alerts on administrative account sign-ins.
- **Impossible Travel**: Alerts when a user appears to sign in from different locations in a timeframe that makes physical travel impossible.
- **Sensitive Changes**: Alerts when sensitive account changes or permission modifications are made.

## Customization

The monitor is highly customizable through the web interface. You can adjust:

- Detection thresholds
- Working hours
- High-risk countries
- Alert frequency
- Email notification settings

## Data Storage

By default, log data is stored for 30 days in a SQLite database within the Docker volume. This retention period is configurable through the web interface.

## Project Structure

```
.
├── app/                      # Main application code
│   ├── alert/                # Email alert functionality
│   ├── analyzer/             # Log analysis and detection rules
│   ├── database/             # Database models and operations
│   ├── graph/                # Microsoft Graph API client
│   ├── web/                  # Flask web interface
│   │   └── templates/        # HTML templates
│   ├── __init__.py           # Flask app factory
│   ├── config.py             # Configuration settings
│   └── main.py               # Application entry point
├── data/                     # Database storage (created by Docker)
├── Dockerfile                # Docker image definition
├── docker-compose.yml        # Docker Compose configuration
├── .env.sample              # Sample environment variables
├── requirements.txt          # Python dependencies
└── README.md                 # This file
```

## Troubleshooting

### Common Issues

1. **Authentication Errors**: Make sure your Azure AD application is properly configured with the correct permissions, and your client credentials are correctly set in the `.env` file.

2. **No Logs Appearing**: Ensure your Microsoft 365 audit logging is enabled in the Security & Compliance Center. It can take up to 24 hours for audit logging to be fully enabled.

3. **Email Alerts Not Sending**: Check your SMTP configuration (server, port, username, password) and email settings. Use the "Test Email" feature in the configuration page to verify email delivery.

4. **Container Not Starting**: View the container logs with `docker-compose logs` to diagnose startup issues.

## Contributing

Contributions to this project are welcome. Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Create a new Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
