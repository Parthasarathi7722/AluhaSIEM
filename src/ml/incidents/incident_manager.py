import os
import json
import uuid
from typing import Dict, List, Optional, Union, Any
import structlog
from datetime import datetime
import pandas as pd
import numpy as np

from src.ml.notifications.incident_notifier import IncidentNotifier
from src.ml.evaluation.model_evaluator import ModelEvaluator

logger = structlog.get_logger()

class IncidentManager:
    """
    Manages security incidents detected by ML models.
    """
    
    def __init__(self, config: Dict):
        """
        Initialize the incident manager.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.incident_dir = os.path.join(
            config['ml_engine']['model_path'],
            'incidents'
        )
        
        # Create incidents directory if it doesn't exist
        os.makedirs(self.incident_dir, exist_ok=True)
        
        # Initialize components
        self.notifier = IncidentNotifier(config)
        self.evaluator = ModelEvaluator(config)
        
        # Load incident rules
        self.rules = self._load_incident_rules()
        
        logger.info("incident_manager_initialized",
                   incident_dir=self.incident_dir)
    
    def _load_incident_rules(self) -> Dict:
        """
        Load incident rules from configuration.
        
        Returns:
            Dictionary of incident rules
        """
        rules = self.config.get('incident_rules', {})
        
        # Add default rules if none provided
        if not rules:
            rules = {
                'anomaly_score_threshold': 0.8,
                'severity_levels': {
                    'high': 0.9,
                    'medium': 0.7,
                    'low': 0.5
                },
                'notification_channels': {
                    'high': ['email', 'slack', 'webhook'],
                    'medium': ['slack', 'webhook'],
                    'low': ['webhook']
                }
            }
        
        return rules
    
    def process_detection(self,
                         events: List[Dict],
                         predictions: np.ndarray,
                         scores: np.ndarray,
                         model_info: Dict) -> List[Dict]:
        """
        Process ML detection results and generate incidents.
        
        Args:
            events: List of security events
            predictions: Model predictions
            scores: Anomaly scores
            model_info: Model information
            
        Returns:
            List of generated incidents
        """
        incidents = []
        
        # Convert to DataFrame for easier processing
        df = pd.DataFrame(events)
        df['prediction'] = predictions
        df['score'] = scores
        
        # Group events by time window
        window_size = self.config.get('incident_window_size', 300)  # 5 minutes
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['window'] = df['timestamp'].dt.floor(f'{window_size}S')
        
        # Process each time window
        for window, group in df.groupby('window'):
            # Check if any events exceed threshold
            high_score_events = group[group['score'] > self.rules['anomaly_score_threshold']]
            
            if not high_score_events.empty:
                # Create incident
                incident = self._create_incident(
                    events=high_score_events.to_dict('records'),
                    window=window,
                    model_info=model_info
                )
                
                # Save incident
                self._save_incident(incident)
                
                # Send notifications
                self.notifier.notify_incident(
                    incident,
                    channels=self.rules['notification_channels'][incident['severity']]
                )
                
                incidents.append(incident)
        
        return incidents
    
    def _create_incident(self,
                        events: List[Dict],
                        window: datetime,
                        model_info: Dict) -> Dict:
        """
        Create an incident from detected events.
        
        Args:
            events: List of detected events
            window: Time window
            model_info: Model information
            
        Returns:
            Incident information
        """
        # Calculate incident severity
        max_score = max(event['score'] for event in events)
        severity = self._determine_severity(max_score)
        
        # Create incident
        incident = {
            'id': str(uuid.uuid4()),
            'title': f"Anomaly Detected: {len(events)} events",
            'severity': severity,
            'timestamp': window.isoformat(),
            'description': self._generate_description(events),
            'details': {
                'events': events,
                'model_info': model_info,
                'max_score': max_score,
                'event_count': len(events)
            }
        }
        
        return incident
    
    def _determine_severity(self, score: float) -> str:
        """
        Determine incident severity based on score.
        
        Args:
            score: Anomaly score
            
        Returns:
            Severity level
        """
        thresholds = self.rules['severity_levels']
        
        if score >= thresholds['high']:
            return 'high'
        elif score >= thresholds['medium']:
            return 'medium'
        elif score >= thresholds['low']:
            return 'low'
        else:
            return 'info'
    
    def _generate_description(self, events: List[Dict]) -> str:
        """
        Generate incident description.
        
        Args:
            events: List of events
            
        Returns:
            Description string
        """
        # Count event types
        event_types = {}
        for event in events:
            event_type = event.get('event_type', 'unknown')
            event_types[event_type] = event_types.get(event_type, 0) + 1
        
        # Generate description
        description = f"Detected {len(events)} anomalous events:\n"
        for event_type, count in event_types.items():
            description += f"- {count} {event_type} events\n"
        
        return description
    
    def _save_incident(self, incident: Dict) -> str:
        """
        Save incident to file.
        
        Args:
            incident: Incident information
            
        Returns:
            Path to saved incident file
        """
        # Create incident file path
        incident_path = os.path.join(
            self.incident_dir,
            f"{incident['id']}.json"
        )
        
        # Save incident
        with open(incident_path, 'w') as f:
            json.dump(incident, f, indent=2)
        
        logger.info("incident_saved",
                   incident_id=incident['id'],
                   path=incident_path)
        
        return incident_path
    
    def get_incident(self, incident_id: str) -> Dict:
        """
        Get incident information.
        
        Args:
            incident_id: Incident ID
            
        Returns:
            Incident information
        """
        incident_path = os.path.join(
            self.incident_dir,
            f"{incident_id}.json"
        )
        
        if not os.path.exists(incident_path):
            raise ValueError(f"Incident {incident_id} not found")
        
        with open(incident_path, 'r') as f:
            incident = json.load(f)
        
        return incident
    
    def list_incidents(self,
                      severity: Optional[str] = None,
                      start_time: Optional[datetime] = None,
                      end_time: Optional[datetime] = None) -> List[Dict]:
        """
        List incidents with optional filtering.
        
        Args:
            severity: Filter by severity level
            start_time: Filter by start time
            end_time: Filter by end time
            
        Returns:
            List of incidents
        """
        incidents = []
        
        for filename in os.listdir(self.incident_dir):
            if not filename.endswith('.json'):
                continue
            
            try:
                incident = self.get_incident(filename[:-5])
                
                # Apply filters
                if severity and incident['severity'] != severity:
                    continue
                
                incident_time = datetime.fromisoformat(incident['timestamp'])
                if start_time and incident_time < start_time:
                    continue
                if end_time and incident_time > end_time:
                    continue
                
                incidents.append(incident)
                
            except Exception as e:
                logger.warning("failed_to_load_incident",
                             filename=filename,
                             error=str(e))
        
        return sorted(incidents, key=lambda x: x['timestamp'], reverse=True) 