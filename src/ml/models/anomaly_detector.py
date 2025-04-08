import os
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import logging
from typing import Dict, List, Tuple, Optional, Union
import structlog
from datetime import datetime
import json
from cryptography.fernet import Fernet

# Configure structured logging
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ]
)
logger = structlog.get_logger()

class AnomalyDetector:
    """
    Anomaly detection model for WazuhAI using Isolation Forest algorithm.
    """
    
    def __init__(self, config: Dict):
        """
        Initialize the anomaly detector.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.model = None
        self.scaler = StandardScaler()
        self.model_path = os.path.join(
            config.get('models', {}).get('storage_path', '/app/models'),
            'anomaly_detector'
        )
        self.feature_columns = []
        self.model_version = "1.0.0"
        self.model_info = {
            'created_at': datetime.now().isoformat(),
            'last_trained': None,
            'training_samples': 0,
            'performance_metrics': {}
        }
        
        # Initialize encryption if enabled
        self.encryption_enabled = config.get('models', {}).get('encryption', {}).get('enabled', False)
        if self.encryption_enabled:
            encryption_key = config.get('models', {}).get('encryption', {}).get('key')
            if not encryption_key:
                raise ValueError("Encryption key not provided in config")
            self.fernet = Fernet(encryption_key.encode())
        
        # Initialize drift detection
        self.drift_config = config.get('models', {}).get('drift_detection', {})
        self.drift_threshold = self.drift_config.get('threshold', 0.1)
        self.drift_history = []
        
        # Create model directory if it doesn't exist
        os.makedirs(self.model_path, exist_ok=True)
        
        logger.info("anomaly_detector_initialized", 
                   model_path=self.model_path,
                   model_version=self.model_version,
                   encryption_enabled=self.encryption_enabled)
    
    def preprocess_data(self, data: pd.DataFrame) -> pd.DataFrame:
        """
        Preprocess the input data.
        
        Args:
            data: Input DataFrame
            
        Returns:
            Preprocessed DataFrame
        """
        # Handle missing values
        data = data.fillna(0)
        
        # Select features
        if not self.feature_columns:
            self.feature_columns = data.columns.tolist()
        
        data = data[self.feature_columns]
        
        # Scale features
        if not hasattr(self.scaler, 'mean_'):
            self.scaler.fit(data)
        
        scaled_data = self.scaler.transform(data)
        return pd.DataFrame(scaled_data, columns=data.columns)
    
    def train(self, data: pd.DataFrame) -> Dict:
        """
        Train the anomaly detection model.
        
        Args:
            data: Training data
            
        Returns:
            Training metrics
        """
        logger.info("training_anomaly_detector_started", 
                   data_shape=data.shape,
                   model_version=self.model_version)
        
        # Preprocess data
        processed_data = self.preprocess_data(data)
        
        # Initialize model
        self.model = IsolationForest(
            n_estimators=100,
            max_samples='auto',
            contamination=0.1,
            random_state=42
        )
        
        # Train model
        self.model.fit(processed_data)
        
        # Update model info
        self.model_info['last_trained'] = datetime.now().isoformat()
        self.model_info['training_samples'] = len(data)
        
        # Calculate training metrics
        scores = self.model.score_samples(processed_data)
        metrics = {
            'mean_score': float(np.mean(scores)),
            'std_score': float(np.std(scores)),
            'min_score': float(np.min(scores)),
            'max_score': float(np.max(scores))
        }
        self.model_info['performance_metrics'] = metrics
        
        # Save model
        self._save_model()
        
        logger.info("training_anomaly_detector_completed", 
                   metrics=metrics,
                   model_version=self.model_version)
        
        return metrics
    
    def predict(self, data: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict anomalies in the input data.
        
        Args:
            data: Input data
            
        Returns:
            Tuple of (predictions, scores)
            - predictions: 1 for normal, -1 for anomaly
            - scores: Anomaly scores (lower is more anomalous)
        """
        if self.model is None:
            self._load_model()
        
        # Preprocess data
        processed_data = self.preprocess_data(data)
        
        # Make predictions
        predictions = self.model.predict(processed_data)
        scores = self.model.score_samples(processed_data)
        
        # Convert predictions to binary (0 for normal, 1 for anomaly)
        binary_predictions = (predictions == -1).astype(int)
        
        # Check for drift
        if self.drift_config.get('enabled', True):
            self._check_drift(scores)
        
        logger.info("anomaly_prediction_completed", 
                   data_shape=data.shape,
                   anomaly_count=int(np.sum(binary_predictions)),
                   model_version=self.model_version)
        
        return binary_predictions, scores
    
    def _save_model(self) -> None:
        """Save the model and scaler to disk."""
        # Create version directory
        version_dir = os.path.join(self.model_path, self.model_version)
        os.makedirs(version_dir, exist_ok=True)
        
        # Save model files
        model_file = os.path.join(version_dir, 'model.joblib')
        scaler_file = os.path.join(version_dir, 'scaler.joblib')
        info_file = os.path.join(version_dir, 'model_info.json')
        
        # Save model and scaler
        joblib.dump(self.model, model_file)
        joblib.dump(self.scaler, scaler_file)
        
        # Save feature columns
        with open(os.path.join(version_dir, 'features.txt'), 'w') as f:
            f.write('\n'.join(self.feature_columns))
        
        # Save model info
        with open(info_file, 'w') as f:
            json.dump(self.model_info, f, indent=2)
        
        # Encrypt files if enabled
        if self.encryption_enabled:
            for file_path in [model_file, scaler_file, info_file]:
                with open(file_path, 'rb') as f:
                    data = f.read()
                encrypted_data = self.fernet.encrypt(data)
                with open(file_path, 'wb') as f:
                    f.write(encrypted_data)
        
        logger.info("model_saved", 
                   model_file=model_file,
                   scaler_file=scaler_file,
                   model_version=self.model_version)
    
    def _load_model(self) -> None:
        """Load the model and scaler from disk."""
        version_dir = os.path.join(self.model_path, self.model_version)
        model_file = os.path.join(version_dir, 'model.joblib')
        scaler_file = os.path.join(version_dir, 'scaler.joblib')
        info_file = os.path.join(version_dir, 'model_info.json')
        features_file = os.path.join(version_dir, 'features.txt')
        
        if not all(os.path.exists(f) for f in [model_file, scaler_file, info_file, features_file]):
            raise FileNotFoundError("Model files not found. Please train the model first.")
        
        # Decrypt files if enabled
        if self.encryption_enabled:
            for file_path in [model_file, scaler_file, info_file]:
                with open(file_path, 'rb') as f:
                    encrypted_data = f.read()
                decrypted_data = self.fernet.decrypt(encrypted_data)
                with open(file_path, 'wb') as f:
                    f.write(decrypted_data)
        
        # Load model and scaler
        self.model = joblib.load(model_file)
        self.scaler = joblib.load(scaler_file)
        
        # Load feature columns
        with open(features_file, 'r') as f:
            self.feature_columns = f.read().strip().split('\n')
        
        # Load model info
        with open(info_file, 'r') as f:
            self.model_info = json.load(f)
        
        logger.info("model_loaded", 
                   model_file=model_file,
                   scaler_file=scaler_file,
                   model_version=self.model_version)
    
    def _check_drift(self, scores: np.ndarray) -> None:
        """
        Check for model drift using score distribution.
        
        Args:
            scores: Anomaly scores from prediction
        """
        current_mean = np.mean(scores)
        current_std = np.std(scores)
        
        # Calculate drift metric (normalized difference in distributions)
        if self.model_info['performance_metrics']:
            baseline_mean = self.model_info['performance_metrics']['mean_score']
            baseline_std = self.model_info['performance_metrics']['std_score']
            
            mean_drift = abs(current_mean - baseline_mean) / baseline_std
            std_drift = abs(current_std - baseline_std) / baseline_std
            
            drift_metric = max(mean_drift, std_drift)
            
            # Store drift history
            self.drift_history.append({
                'timestamp': datetime.now().isoformat(),
                'drift_metric': float(drift_metric),
                'mean_drift': float(mean_drift),
                'std_drift': float(std_drift)
            })
            
            # Keep only recent history
            max_history = self.drift_config.get('history_size', 1000)
            if len(self.drift_history) > max_history:
                self.drift_history = self.drift_history[-max_history:]
            
            # Check if drift exceeds threshold
            if drift_metric > self.drift_threshold:
                logger.warning("model_drift_detected",
                             drift_metric=float(drift_metric),
                             threshold=self.drift_threshold,
                             model_version=self.model_version)
                
                if self.drift_config.get('alert_on_drift', True):
                    # TODO: Implement alert mechanism
                    pass
    
    def get_model_info(self) -> Dict:
        """
        Get information about the model.
        
        Returns:
            Model information dictionary
        """
        info = {
            'model_type': 'IsolationForest',
            'model_version': self.model_version,
            'feature_count': len(self.feature_columns),
            'features': self.feature_columns,
            'is_trained': self.model is not None,
            'created_at': self.model_info.get('created_at'),
            'last_trained': self.model_info.get('last_trained'),
            'training_samples': self.model_info.get('training_samples', 0),
            'performance_metrics': self.model_info.get('performance_metrics', {}),
            'drift_detection': {
                'enabled': self.drift_config.get('enabled', True),
                'threshold': self.drift_threshold,
                'current_drift': self.drift_history[-1] if self.drift_history else None
            }
        }
        
        return info 