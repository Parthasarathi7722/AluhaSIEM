import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Union, Any
import structlog
from sklearn.metrics import (
    precision_score, recall_score, f1_score, 
    roc_auc_score, confusion_matrix, classification_report
)
from datetime import datetime

logger = structlog.get_logger()

class ModelEvaluator:
    """
    Evaluates ML model performance and tracks metrics.
    """
    
    def __init__(self, config: Dict):
        """
        Initialize the model evaluator.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.metrics_history = []
        self.current_metrics = {}
        
        logger.info("model_evaluator_initialized")
    
    def evaluate_model(self, 
                      y_true: np.ndarray, 
                      y_pred: np.ndarray, 
                      y_prob: Optional[np.ndarray] = None,
                      model_info: Optional[Dict] = None) -> Dict:
        """
        Evaluate model performance.
        
        Args:
            y_true: True labels
            y_pred: Predicted labels
            y_prob: Prediction probabilities
            model_info: Additional model information
            
        Returns:
            Dictionary of evaluation metrics
        """
        metrics = {}
        
        # Basic classification metrics
        metrics['precision'] = precision_score(y_true, y_pred, average='weighted')
        metrics['recall'] = recall_score(y_true, y_pred, average='weighted')
        metrics['f1'] = f1_score(y_true, y_pred, average='weighted')
        
        # ROC AUC if probabilities are available
        if y_prob is not None:
            metrics['roc_auc'] = roc_auc_score(y_true, y_prob, average='weighted')
        
        # Confusion matrix
        metrics['confusion_matrix'] = confusion_matrix(y_true, y_pred).tolist()
        
        # Classification report
        metrics['classification_report'] = classification_report(y_true, y_pred, output_dict=True)
        
        # Add model info if provided
        if model_info:
            metrics['model_info'] = model_info
        
        # Add timestamp
        metrics['timestamp'] = datetime.now().isoformat()
        
        # Update current metrics and history
        self.current_metrics = metrics
        self.metrics_history.append(metrics)
        
        logger.info("model_evaluation_completed",
                   metrics=metrics)
        
        return metrics
    
    def evaluate_drift(self, 
                      reference_metrics: Dict,
                      current_metrics: Dict,
                      threshold: float = 0.1) -> Dict:
        """
        Evaluate model drift.
        
        Args:
            reference_metrics: Reference metrics from previous evaluation
            current_metrics: Current metrics to compare against
            threshold: Drift detection threshold
            
        Returns:
            Dictionary containing drift analysis results
        """
        drift_analysis = {
            'timestamp': datetime.now().isoformat(),
            'metrics_drift': {},
            'drift_detected': False
        }
        
        # Compare key metrics
        for metric in ['precision', 'recall', 'f1']:
            if metric in reference_metrics and metric in current_metrics:
                drift = abs(reference_metrics[metric] - current_metrics[metric])
                drift_analysis['metrics_drift'][metric] = drift
                
                if drift > threshold:
                    drift_analysis['drift_detected'] = True
        
        # Compare ROC AUC if available
        if 'roc_auc' in reference_metrics and 'roc_auc' in current_metrics:
            drift = abs(reference_metrics['roc_auc'] - current_metrics['roc_auc'])
            drift_analysis['metrics_drift']['roc_auc'] = drift
            
            if drift > threshold:
                drift_analysis['drift_detected'] = True
        
        logger.info("drift_evaluation_completed",
                   drift_analysis=drift_analysis)
        
        return drift_analysis
    
    def get_metrics_history(self) -> List[Dict]:
        """
        Get metrics history.
        
        Returns:
            List of historical metrics
        """
        return self.metrics_history
    
    def get_current_metrics(self) -> Dict:
        """
        Get current metrics.
        
        Returns:
            Current metrics dictionary
        """
        return self.current_metrics
    
    def export_metrics(self, export_path: str) -> str:
        """
        Export metrics to file.
        
        Args:
            export_path: Path to save metrics
            
        Returns:
            Path to exported metrics file
        """
        metrics_df = pd.DataFrame(self.metrics_history)
        metrics_df.to_csv(export_path, index=False)
        
        logger.info("metrics_exported",
                   export_path=export_path)
        
        return export_path
    
    def import_metrics(self, metrics_path: str) -> List[Dict]:
        """
        Import metrics from file.
        
        Args:
            metrics_path: Path to metrics file
            
        Returns:
            List of imported metrics
        """
        metrics_df = pd.read_csv(metrics_path)
        self.metrics_history = metrics_df.to_dict('records')
        
        if self.metrics_history:
            self.current_metrics = self.metrics_history[-1]
        
        logger.info("metrics_imported",
                   metrics_path=metrics_path)
        
        return self.metrics_history 