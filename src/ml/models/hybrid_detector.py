import os
from typing import Dict, List, Tuple, Optional
import numpy as np
import pandas as pd
import structlog
from datetime import datetime

from .anomaly_detector import AnomalyDetector
from ..integrations.wazuh_ml import WazuhMLIntegration

logger = structlog.get_logger()

class HybridDetector:
    """
    Hybrid anomaly detection model combining local ML and Wazuh ML capabilities.
    """
    
    def __init__(self, config: Dict):
        """
        Initialize the hybrid detector.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.local_detector = AnomalyDetector(config)
        self.wazuh_ml = WazuhMLIntegration(config)
        
        # Hybrid model configuration
        self.hybrid_config = config.get('hybrid_model', {})
        self.local_weight = self.hybrid_config.get('local_weight', 0.5)
        self.wazuh_weight = 1 - self.local_weight
        self.ensemble_method = self.hybrid_config.get('ensemble_method', 'weighted')
        
        logger.info("hybrid_detector_initialized",
                   local_weight=self.local_weight,
                   wazuh_weight=self.wazuh_weight,
                   ensemble_method=self.ensemble_method)
    
    def train(self, data: pd.DataFrame) -> Dict:
        """
        Train both local and Wazuh ML models.
        
        Args:
            data: Training data
            
        Returns:
            Combined training metrics
        """
        logger.info("training_hybrid_detector_started",
                   data_shape=data.shape)
        
        # Train local model
        local_metrics = self.local_detector.train(data)
        
        # Train Wazuh model
        wazuh_data = self._prepare_wazuh_data(data)
        wazuh_metrics = self.wazuh_ml.train_model(
            self.hybrid_config.get('wazuh_model_id', 'default'),
            wazuh_data
        )
        
        # Combine metrics
        combined_metrics = {
            'local_metrics': local_metrics,
            'wazuh_metrics': wazuh_metrics,
            'ensemble_weights': {
                'local': self.local_weight,
                'wazuh': self.wazuh_weight
            }
        }
        
        logger.info("training_hybrid_detector_completed",
                   metrics=combined_metrics)
        
        return combined_metrics
    
    def predict(self, data: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """
        Make predictions using both models and combine results.
        
        Args:
            data: Input data
            
        Returns:
            Tuple of (predictions, scores)
            - predictions: 1 for anomaly, 0 for normal
            - scores: Combined anomaly scores
        """
        logger.info("hybrid_prediction_started",
                   data_shape=data.shape)
        
        # Get local predictions
        local_predictions, local_scores = self.local_detector.predict(data)
        
        # Get Wazuh predictions
        wazuh_data = self._prepare_wazuh_data(data)
        wazuh_results = self.wazuh_ml.predict(
            self.hybrid_config.get('wazuh_model_id', 'default'),
            wazuh_data
        )
        wazuh_predictions = np.array(wazuh_results['predictions'])
        wazuh_scores = np.array(wazuh_results['scores'])
        
        # Combine predictions based on ensemble method
        if self.ensemble_method == 'weighted':
            # Weighted average of scores
            combined_scores = (
                self.local_weight * local_scores +
                self.wazuh_weight * wazuh_scores
            )
            # Binary predictions based on combined scores
            combined_predictions = (combined_scores > 0.5).astype(int)
        
        elif self.ensemble_method == 'voting':
            # Majority voting
            combined_predictions = (
                (self.local_weight * local_predictions +
                 self.wazuh_weight * wazuh_predictions) > 0.5
            ).astype(int)
            # Average scores for anomalies
            combined_scores = (
                self.local_weight * local_scores +
                self.wazuh_weight * wazuh_scores
            )
        
        else:
            raise ValueError(f"Unknown ensemble method: {self.ensemble_method}")
        
        logger.info("hybrid_prediction_completed",
                   anomaly_count=int(np.sum(combined_predictions)))
        
        return combined_predictions, combined_scores
    
    def _prepare_wazuh_data(self, data: pd.DataFrame) -> Dict:
        """
        Prepare data for Wazuh ML API.
        
        Args:
            data: Input DataFrame
            
        Returns:
            Dictionary formatted for Wazuh API
        """
        # Convert DataFrame to list of dictionaries
        events = data.to_dict('records')
        
        # Add metadata
        return {
            'events': events,
            'timestamp': datetime.now().isoformat(),
            'source': 'hybrid_detector'
        }
    
    def get_model_info(self) -> Dict:
        """
        Get information about both models.
        
        Returns:
            Combined model information
        """
        local_info = self.local_detector.get_model_info()
        wazuh_info = self.wazuh_ml.get_model_status(
            self.hybrid_config.get('wazuh_model_id', 'default')
        )
        
        return {
            'local_model': local_info,
            'wazuh_model': wazuh_info,
            'ensemble_config': {
                'local_weight': self.local_weight,
                'wazuh_weight': self.wazuh_weight,
                'ensemble_method': self.ensemble_method
            }
        }
    
    def update_weights(self, local_weight: float) -> None:
        """
        Update ensemble weights.
        
        Args:
            local_weight: New weight for local model (0 to 1)
        """
        if not 0 <= local_weight <= 1:
            raise ValueError("Weight must be between 0 and 1")
        
        self.local_weight = local_weight
        self.wazuh_weight = 1 - local_weight
        
        logger.info("ensemble_weights_updated",
                   local_weight=self.local_weight,
                   wazuh_weight=self.wazuh_weight)
    
    def get_alerts(self, 
                  start_time: Optional[datetime] = None,
                  end_time: Optional[datetime] = None) -> List[Dict]:
        """
        Get alerts from both models.
        
        Args:
            start_time: Start time for alert search
            end_time: End time for alert search
            
        Returns:
            Combined list of alerts
        """
        # Get Wazuh alerts
        wazuh_alerts = self.wazuh_ml.get_model_alerts(
            self.hybrid_config.get('wazuh_model_id', 'default'),
            start_time,
            end_time
        )
        
        # TODO: Implement local alert retrieval
        local_alerts = []
        
        # Combine and sort alerts
        combined_alerts = wazuh_alerts + local_alerts
        combined_alerts.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return combined_alerts 