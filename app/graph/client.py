import logging
import datetime
import json
import msal
import requests
from datetime import datetime, timedelta

from app.config import (
    MS_CLIENT_ID,
    MS_CLIENT_SECRET,
    MS_AUTHORITY,
    MS_GRAPH_ENDPOINT,
    MS_SCOPE
)

logger = logging.getLogger(__name__)

class GraphClient:
    """Client for interacting with Microsoft Graph API"""
    
    def __init__(self):
        self.client_id = MS_CLIENT_ID
        self.client_secret = MS_CLIENT_SECRET
        self.authority = MS_AUTHORITY
        self.scope = MS_SCOPE
        self.endpoint = MS_GRAPH_ENDPOINT
        
        # Initialize confidential client with MSAL
        self.app = msal.ConfidentialClientApplication(
            client_id=self.client_id,
            client_credential=self.client_secret,
            authority=self.authority
        )
        
        self.access_token = None
        
    def get_token(self):
        """Acquire token for application permissions"""
        if not self.access_token:
            result = self.app.acquire_token_for_client(scopes=self.scope)
            if "access_token" in result:
                self.access_token = result["access_token"]
                logger.info("Successfully acquired access token for Graph API")
                return self.access_token
            else:
                error = result.get("error")
                error_description = result.get("error_description")
                logger.error(f"Failed to acquire token: {error} - {error_description}")
                raise Exception(f"Failed to acquire token: {error} - {error_description}")
        return self.access_token
    
    def make_request(self, endpoint, params=None):
        """Make a request to Microsoft Graph API"""
        if not params:
            params = {}
            
        token = self.get_token()
        headers = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        url = f"{self.endpoint}/{endpoint}"
        response = requests.get(url, headers=headers, params=params)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 401:
            # Token might be expired, clear it and try again
            self.access_token = None
            token = self.get_token()
            headers['Authorization'] = f'Bearer {token}'
            response = requests.get(url, headers=headers, params=params)
            if response.status_code == 200:
                return response.json()
            
        logger.error(f"Graph API request failed with status code {response.status_code}: {response.text}")
        response.raise_for_status()
        
    def get_sign_in_logs(self, minutes=None):
        """
        Retrieve sign-in logs from Microsoft Graph API
        
        Args:
            minutes: If provided, retrieve logs from the last X minutes
            
        Returns:
            List of sign-in log entries
        """
        filter_params = ""
        if minutes:
            time_threshold = datetime.utcnow() - timedelta(minutes=minutes)
            time_str = time_threshold.strftime('%Y-%m-%dT%H:%M:%SZ')
            filter_params = f"createdDateTime ge {time_str}"
            
        params = {
            "$filter": filter_params,
            "$orderby": "createdDateTime desc",
            "$top": 100  # Adjust as needed
        }
        
        result = self.make_request("auditLogs/signIns", params)
        return result.get("value", [])
    
    def get_audit_logs(self, minutes=None):
        """
        Retrieve directory audit logs from Microsoft Graph API
        
        Args:
            minutes: If provided, retrieve logs from the last X minutes
            
        Returns:
            List of audit log entries
        """
        filter_params = ""
        if minutes:
            time_threshold = datetime.utcnow() - timedelta(minutes=minutes)
            time_str = time_threshold.strftime('%Y-%m-%dT%H:%M:%SZ')
            filter_params = f"activityDateTime ge {time_str}"
            
        params = {
            "$filter": filter_params,
            "$orderby": "activityDateTime desc",
            "$top": 100  # Adjust as needed
        }
        
        result = self.make_request("auditLogs/directoryAudits", params)
        return result.get("value", [])
