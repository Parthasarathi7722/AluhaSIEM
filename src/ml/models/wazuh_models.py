import os
from typing import Dict, List, Optional, Union, Any
import numpy as np
import pandas as pd
import structlog
from datetime import datetime

from ..integrations.wazuh_ml import WazuhMLIntegration

logger = structlog.get_logger()

class WazuhModelFactory:
    """
    Factory for creating different types of Wazuh ML models.
    """
    
    @staticmethod
    def create_model(model_type: str, config: Dict) -> 'BaseWazuhModel':
        """
        Create a Wazuh ML model of the specified type.
        
        Args:
            model_type: Type of model to create
            config: Configuration dictionary
            
        Returns:
            Instance of the specified model type
        """
        if model_type == 'anomaly_detection':
            return WazuhAnomalyDetector(config)
        elif model_type == 'behavior_analysis':
            return WazuhBehaviorAnalyzer(config)
        elif model_type == 'threat_detection':
            return WazuhThreatDetector(config)
        elif model_type == 'pattern_recognition':
            return WazuhPatternRecognizer(config)
        else:
            raise ValueError(f"Unknown model type: {model_type}")


class BaseWazuhModel:
    """
    Base class for Wazuh ML models.
    """
    
    def __init__(self, config: Dict):
        """
        Initialize the base Wazuh model.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.wazuh_ml = WazuhMLIntegration(config)
        self.model_id = None
        self.model_info = {}
        
        logger.info("wazuh_model_initialized", 
                   model_type=self.__class__.__name__)
    
    def train(self, data: Dict) -> Dict:
        """
        Train the model.
        
        Args:
            data: Training data
            
        Returns:
            Training metrics
        """
        raise NotImplementedError("Subclasses must implement train method")
    
    def predict(self, data: Dict) -> Dict:
        """
        Make predictions using the model.
        
        Args:
            data: Input data
            
        Returns:
            Prediction results
        """
        raise NotImplementedError("Subclasses must implement predict method")
    
    def get_model_info(self) -> Dict:
        """
        Get information about the model.
        
        Returns:
            Model information
        """
        if not self.model_id:
            return {"status": "not_initialized"}
        
        return self.wazuh_ml.get_model_status(self.model_id)
    
    def export_model(self, export_path: str) -> str:
        """
        Export the model to file.
        
        Args:
            export_path: Path to save the exported model
            
        Returns:
            Path to the exported model file
        """
        if not self.model_id:
            raise ValueError("Model not initialized")
        
        return self.wazuh_ml.export_model(self.model_id, export_path)
    
    def import_model(self, model_path: str) -> Dict:
        """
        Import a model from file.
        
        Args:
            model_path: Path to the model file
            
        Returns:
            Imported model information
        """
        if not self.model_id:
            raise ValueError("Model ID not set")
        
        return self.wazuh_ml.import_model(self.model_id, model_path)


class WazuhAnomalyDetector(BaseWazuhModel):
    """
    Wazuh anomaly detection model.
    """
    
    def __init__(self, config: Dict):
        """
        Initialize the anomaly detector.
        
        Args:
            config: Configuration dictionary
        """
        super().__init__(config)
        self.model_id = config.get('wazuh_models', {}).get('anomaly_detection', {}).get('model_id', 'anomaly_detector')
        self.contamination = config.get('wazuh_models', {}).get('anomaly_detection', {}).get('contamination', 0.1)
        self.threshold = config.get('wazuh_models', {}).get('anomaly_detection', {}).get('threshold', 0.5)
        
        logger.info("anomaly_detector_initialized",
                   model_id=self.model_id,
                   contamination=self.contamination,
                   threshold=self.threshold)
    
    def train(self, data: Dict) -> Dict:
        """
        Train the anomaly detection model.
        
        Args:
            data: Training data
            
        Returns:
            Training metrics
        """
        logger.info("training_anomaly_detector_started",
                   data_size=len(data.get('events', [])))
        
        # Prepare training data
        training_data = {
            'events': data.get('events', []),
            'parameters': {
                'contamination': self.contamination,
                'threshold': self.threshold
            }
        }
        
        # Train model
        metrics = self.wazuh_ml.train_model(self.model_id, training_data)
        
        logger.info("training_anomaly_detector_completed",
                   metrics=metrics)
        
        return metrics
    
    def predict(self, data: Dict) -> Dict:
        """
        Detect anomalies in the input data.
        
        Args:
            data: Input data
            
        Returns:
            Anomaly detection results
        """
        logger.info("anomaly_detection_started",
                   data_size=len(data.get('events', [])))
        
        # Make predictions
        results = self.wazuh_ml.predict(self.model_id, data)
        
        # Process results
        anomalies = []
        for i, (prediction, score) in enumerate(zip(results.get('predictions', []), results.get('scores', []))):
            if prediction == 1 and score > self.threshold:
                anomalies.append({
                    'index': i,
                    'score': score,
                    'event': data.get('events', [])[i] if i < len(data.get('events', [])) else None
                })
        
        logger.info("anomaly_detection_completed",
                   anomaly_count=len(anomalies))
        
        return {
            'predictions': results.get('predictions', []),
            'scores': results.get('scores', []),
            'anomalies': anomalies
        }


class WazuhBehaviorAnalyzer(BaseWazuhModel):
    """
    Wazuh user behavior analysis model.
    """
    
    def __init__(self, config: Dict):
        """
        Initialize the behavior analyzer.
        
        Args:
            config: Configuration dictionary
        """
        super().__init__(config)
        self.model_id = config.get('wazuh_models', {}).get('behavior_analysis', {}).get('model_id', 'behavior_analyzer')
        self.sensitivity = config.get('wazuh_models', {}).get('behavior_analysis', {}).get('sensitivity', 'medium')
        self.time_window = config.get('wazuh_models', {}).get('behavior_analysis', {}).get('time_window', 3600)
        
        logger.info("behavior_analyzer_initialized",
                   model_id=self.model_id,
                   sensitivity=self.sensitivity,
                   time_window=self.time_window)
    
    def train(self, data: Dict) -> Dict:
        """
        Train the behavior analysis model.
        
        Args:
            data: Training data
            
        Returns:
            Training metrics
        """
        logger.info("training_behavior_analyzer_started",
                   data_size=len(data.get('events', [])))
        
        # Prepare training data
        training_data = {
            'events': data.get('events', []),
            'parameters': {
                'sensitivity': self.sensitivity,
                'time_window': self.time_window
            }
        }
        
        # Train model
        metrics = self.wazuh_ml.train_model(self.model_id, training_data)
        
        logger.info("training_behavior_analyzer_completed",
                   metrics=metrics)
        
        return metrics
    
    def predict(self, data: Dict) -> Dict:
        """
        Analyze user behavior in the input data.
        
        Args:
            data: Input data
            
        Returns:
            Behavior analysis results
        """
        logger.info("behavior_analysis_started",
                   data_size=len(data.get('events', [])))
        
        # Make predictions
        results = self.wazuh_ml.predict(self.model_id, data)
        
        # Process results
        behavior_anomalies = []
        for i, (prediction, score) in enumerate(zip(results.get('predictions', []), results.get('scores', []))):
            if prediction == 1:
                behavior_anomalies.append({
                    'index': i,
                    'score': score,
                    'event': data.get('events', [])[i] if i < len(data.get('events', [])) else None,
                    'behavior_type': results.get('behavior_types', [])[i] if 'behavior_types' in results and i < len(results.get('behavior_types', [])) else 'unknown'
                })
        
        logger.info("behavior_analysis_completed",
                   anomaly_count=len(behavior_anomalies))
        
        return {
            'predictions': results.get('predictions', []),
            'scores': results.get('scores', []),
            'behavior_anomalies': behavior_anomalies,
            'behavior_types': results.get('behavior_types', [])
        }


class WazuhThreatDetector(BaseWazuhModel):
    """
    Wazuh threat detection model.
    """
    
    def __init__(self, config: Dict):
        """
        Initialize the threat detector.
        
        Args:
            config: Configuration dictionary
        """
        super().__init__(config)
        self.model_id = config.get('wazuh_models', {}).get('threat_detection', {}).get('model_id', 'threat_detector')
        self.confidence_threshold = config.get('wazuh_models', {}).get('threat_detection', {}).get('confidence_threshold', 0.7)
        self.threat_categories = config.get('wazuh_models', {}).get('threat_detection', {}).get('threat_categories', ['malware', 'exploit', 'data_exfiltration'])
        
        logger.info("threat_detector_initialized",
                   model_id=self.model_id,
                   confidence_threshold=self.confidence_threshold,
                   threat_categories=self.threat_categories)
    
    def train(self, data: Dict) -> Dict:
        """
        Train the threat detection model.
        
        Args:
            data: Training data
            
        Returns:
            Training metrics
        """
        logger.info("training_threat_detector_started",
                   data_size=len(data.get('events', [])))
        
        # Prepare training data
        training_data = {
            'events': data.get('events', []),
            'parameters': {
                'confidence_threshold': self.confidence_threshold,
                'threat_categories': self.threat_categories
            }
        }
        
        # Train model
        metrics = self.wazuh_ml.train_model(self.model_id, training_data)
        
        logger.info("training_threat_detector_completed",
                   metrics=metrics)
        
        return metrics
    
    def predict(self, data: Dict) -> Dict:
        """
        Detect threats in the input data.
        
        Args:
            data: Input data
            
        Returns:
            Threat detection results
        """
        logger.info("threat_detection_started",
                   data_size=len(data.get('events', [])))
        
        # Make predictions
        results = self.wazuh_ml.predict(self.model_id, data)
        
        # Process results
        threats = []
        for i, (prediction, score) in enumerate(zip(results.get('predictions', []), results.get('scores', []))):
            if prediction == 1 and score > self.confidence_threshold:
                threat_category = results.get('threat_categories', [])[i] if 'threat_categories' in results and i < len(results.get('threat_categories', [])) else 'unknown'
                threats.append({
                    'index': i,
                    'score': score,
                    'event': data.get('events', [])[i] if i < len(data.get('events', [])) else None,
                    'threat_category': threat_category,
                    'severity': results.get('severities', [])[i] if 'severities' in results and i < len(results.get('severities', [])) else 'medium'
                })
        
        logger.info("threat_detection_completed",
                   threat_count=len(threats))
        
        return {
            'predictions': results.get('predictions', []),
            'scores': results.get('scores', []),
            'threats': threats,
            'threat_categories': results.get('threat_categories', []),
            'severities': results.get('severities', [])
        }


class WazuhPatternRecognizer(BaseWazuhModel):
    """
    Wazuh pattern recognition model.
    """
    
    def __init__(self, config: Dict):
        """
        Initialize the pattern recognizer.
        
        Args:
            config: Configuration dictionary
        """
        super().__init__(config)
        self.model_id = config.get('wazuh_models', {}).get('pattern_recognition', {}).get('model_id', 'pattern_recognizer')
        self.min_confidence = config.get('wazuh_models', {}).get('pattern_recognition', {}).get('min_confidence', 0.6)
        self.pattern_types = config.get('wazuh_models', {}).get('pattern_recognition', {}).get('pattern_types', ['command_pattern', 'network_pattern', 'file_access_pattern'])
        
        logger.info("pattern_recognizer_initialized",
                   model_id=self.model_id,
                   min_confidence=self.min_confidence,
                   pattern_types=self.pattern_types)
    
    def train(self, data: Dict) -> Dict:
        """
        Train the pattern recognition model.
        
        Args:
            data: Training data
            
        Returns:
            Training metrics
        """
        logger.info("training_pattern_recognizer_started",
                   data_size=len(data.get('events', [])))
        
        # Prepare training data
        training_data = {
            'events': data.get('events', []),
            'parameters': {
                'min_confidence': self.min_confidence,
                'pattern_types': self.pattern_types
            }
        }
        
        # Train model
        metrics = self.wazuh_ml.train_model(self.model_id, training_data)
        
        logger.info("training_pattern_recognizer_completed",
                   metrics=metrics)
        
        return metrics
    
    def predict(self, data: Dict) -> Dict:
        """
        Recognize patterns in the input data.
        
        Args:
            data: Input data
            
        Returns:
            Pattern recognition results
        """
        logger.info("pattern_recognition_started",
                   data_size=len(data.get('events', [])))
        
        # Make predictions
        results = self.wazuh_ml.predict(self.model_id, data)
        
        # Process results
        patterns = []
        for i, (prediction, score) in enumerate(zip(results.get('predictions', []), results.get('scores', []))):
            if prediction == 1 and score > self.min_confidence:
                pattern_type = results.get('pattern_types', [])[i] if 'pattern_types' in results and i < len(results.get('pattern_types', [])) else 'unknown'
                patterns.append({
                    'index': i,
                    'score': score,
                    'event': data.get('events', [])[i] if i < len(data.get('events', [])) else None,
                    'pattern_type': pattern_type,
                    'pattern_details': results.get('pattern_details', [])[i] if 'pattern_details' in results and i < len(results.get('pattern_details', [])) else {}
                })
        
        logger.info("pattern_recognition_completed",
                   pattern_count=len(patterns))
        
        return {
            'predictions': results.get('predictions', []),
            'scores': results.get('scores', []),
            'patterns': patterns,
            'pattern_types': results.get('pattern_types', []),
            'pattern_details': results.get('pattern_details', [])
        } 