import os
import json
import smtplib
import requests
from typing import Dict, List, Optional, Union, Any
import structlog
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import slack_sdk
from slack_sdk.errors import SlackApiError

logger = structlog.get_logger()

class IncidentNotifier:
    """
    Handles incident notifications through various channels.
    """
    
    def __init__(self, config: Dict):
        """
        Initialize the incident notifier.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.notification_config = config.get('notifications', {})
        
        # Initialize notification channels
        self.channels = self._initialize_channels()
        
        logger.info("incident_notifier_initialized",
                   channels=list(self.channels.keys()))
    
    def _initialize_channels(self) -> Dict:
        """
        Initialize notification channels.
        
        Returns:
            Dictionary of initialized channels
        """
        channels = {}
        
        # Email channel
        if 'email' in self.notification_config:
            channels['email'] = {
                'enabled': True,
                'config': self.notification_config['email']
            }
        
        # Slack channel
        if 'slack' in self.notification_config:
            channels['slack'] = {
                'enabled': True,
                'config': self.notification_config['slack'],
                'client': slack_sdk.WebClient(
                    token=self.notification_config['slack']['token']
                )
            }
        
        # Webhook channel
        if 'webhook' in self.notification_config:
            channels['webhook'] = {
                'enabled': True,
                'config': self.notification_config['webhook']
            }
        
        return channels
    
    def notify_incident(self, 
                       incident: Dict,
                       channels: Optional[List[str]] = None) -> Dict:
        """
        Send incident notifications.
        
        Args:
            incident: Incident information
            channels: List of channels to notify (default: all enabled channels)
            
        Returns:
            Notification results
        """
        if channels is None:
            channels = [c for c, config in self.channels.items() 
                       if config.get('enabled', False)]
        
        results = {
            'incident_id': incident.get('id'),
            'timestamp': datetime.now().isoformat(),
            'notifications': {}
        }
        
        for channel in channels:
            if channel not in self.channels:
                logger.warning("unknown_notification_channel",
                             channel=channel)
                continue
            
            try:
                if channel == 'email':
                    results['notifications']['email'] = self._send_email(incident)
                elif channel == 'slack':
                    results['notifications']['slack'] = self._send_slack(incident)
                elif channel == 'webhook':
                    results['notifications']['webhook'] = self._send_webhook(incident)
                
                logger.info("notification_sent",
                           channel=channel,
                           incident_id=incident.get('id'))
                
            except Exception as e:
                logger.error("notification_failed",
                           channel=channel,
                           incident_id=incident.get('id'),
                           error=str(e))
                results['notifications'][channel] = {
                    'status': 'failed',
                    'error': str(e)
                }
        
        return results
    
    def _send_email(self, incident: Dict) -> Dict:
        """
        Send email notification.
        
        Args:
            incident: Incident information
            
        Returns:
            Email sending result
        """
        config = self.channels['email']['config']
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = config['from_email']
        msg['To'] = config['to_email']
        msg['Subject'] = f"Security Incident Alert: {incident.get('title', 'Unknown')}"
        
        # Create email body
        body = self._format_email_body(incident)
        msg.attach(MIMEText(body, 'html'))
        
        # Send email
        with smtplib.SMTP(config['smtp_server'], config['smtp_port']) as server:
            if config.get('use_tls', True):
                server.starttls()
            
            if 'username' in config and 'password' in config:
                server.login(config['username'], config['password'])
            
            server.send_message(msg)
        
        return {
            'status': 'sent',
            'recipient': config['to_email']
        }
    
    def _send_slack(self, incident: Dict) -> Dict:
        """
        Send Slack notification.
        
        Args:
            incident: Incident information
            
        Returns:
            Slack sending result
        """
        config = self.channels['slack']['config']
        client = self.channels['slack']['client']
        
        # Create message blocks
        blocks = self._format_slack_blocks(incident)
        
        # Send message
        response = client.chat_postMessage(
            channel=config['channel'],
            blocks=blocks,
            text=incident.get('title', 'Security Incident Alert')
        )
        
        return {
            'status': 'sent',
            'channel': config['channel'],
            'ts': response['ts']
        }
    
    def _send_webhook(self, incident: Dict) -> Dict:
        """
        Send webhook notification.
        
        Args:
            incident: Incident information
            
        Returns:
            Webhook sending result
        """
        config = self.channels['webhook']['config']
        
        # Send webhook
        response = requests.post(
            config['url'],
            json=incident,
            headers=config.get('headers', {}),
            timeout=config.get('timeout', 5)
        )
        
        return {
            'status': 'sent',
            'status_code': response.status_code,
            'response': response.text
        }
    
    def _format_email_body(self, incident: Dict) -> str:
        """
        Format incident information for email.
        
        Args:
            incident: Incident information
            
        Returns:
            Formatted HTML email body
        """
        return f"""
        <html>
            <body>
                <h2>Security Incident Alert</h2>
                <p><strong>Title:</strong> {incident.get('title', 'Unknown')}</p>
                <p><strong>Severity:</strong> {incident.get('severity', 'Unknown')}</p>
                <p><strong>Timestamp:</strong> {incident.get('timestamp', 'Unknown')}</p>
                <p><strong>Description:</strong></p>
                <p>{incident.get('description', 'No description available')}</p>
                <p><strong>Details:</strong></p>
                <pre>{json.dumps(incident.get('details', {}), indent=2)}</pre>
            </body>
        </html>
        """
    
    def _format_slack_blocks(self, incident: Dict) -> List[Dict]:
        """
        Format incident information for Slack.
        
        Args:
            incident: Incident information
            
        Returns:
            Slack message blocks
        """
        severity_color = {
            'high': '#ff0000',
            'medium': '#ffa500',
            'low': '#ffff00'
        }.get(incident.get('severity', 'low').lower(), '#808080')
        
        return [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"Security Incident Alert: {incident.get('title', 'Unknown')}"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{incident.get('severity', 'Unknown')}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Timestamp:*\n{incident.get('timestamp', 'Unknown')}"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Description:*\n{incident.get('description', 'No description available')}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Details:*\n```{json.dumps(incident.get('details', {}), indent=2)}```"
                }
            }
        ] 