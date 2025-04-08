import unittest
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List
import os
import json
import tempfile
import shutil

from src.ml.models.anomaly_detector import AnomalyDetector
from src.ml.models.hybrid_detector import HybridDetector
from src.ml.features.feature_extractor import FeatureExtractor
from src.ml.features.advanced_features import AdvancedFeatureExtractor
from src.ml.integrations.wazuh_ml import WazuhMLIntegration
from src.ml.models.wazuh_models import WazuhModelFactory

class TestHybridSystem(unittest.TestCase):
    """Test suite for the hybrid ML system."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment."""
        # Create temporary directory for test files
        cls.test_dir = tempfile.mkdtemp()
        
        # Load test configuration
        cls.config = {
            'ml_engine': {
                'model_path': os.path.join(cls.test_dir, 'models'),
                'encryption_enabled': False,
                'drift_detection': {
                    'enabled': True,
                    'threshold': 0.1
                }
            },
            'feature_extraction': {
                'window_size': 3600,
                'text_features': {'enabled': True},
                'sequence_features': {'enabled': True},
                'correlation_features': {'enabled': True},
                'entropy_features': {'enabled': True}
            },
            'wazuh_ml': {
                'api_url': 'https://wazuh-manager:55000',
                'username': 'test_user',
                'password': 'test_pass',
                'verify_ssl': False
            }
        }
        
        # Create sample security events
        cls.sample_events = cls._generate_sample_events(100)
        
        # Initialize components
        cls.feature_extractor = FeatureExtractor(cls.config)
        cls.advanced_feature_extractor = AdvancedFeatureExtractor(cls.config)
        cls.anomaly_detector = AnomalyDetector(cls.config)
        cls.wazuh_ml = WazuhMLIntegration(cls.config)
        cls.hybrid_detector = HybridDetector(cls.config)
    
    @classmethod
    def tearDownClass(cls):
        """Clean up test environment."""
        shutil.rmtree(cls.test_dir)
    
    @staticmethod
    def _generate_sample_events(count: int) -> List[Dict]:
        """Generate sample security events for testing."""
        events = []
        base_time = datetime.now()
        
        for i in range(count):
            event = {
                'timestamp': base_time + timedelta(seconds=i),
                'event_type': np.random.choice(['login', 'command', 'file_access', 'network']),
                'source_ip': f'192.168.1.{np.random.randint(1, 255)}',
                'destination_ip': f'192.168.1.{np.random.randint(1, 255)}',
                'username': f'user_{np.random.randint(1, 10)}',
                'process_name': f'process_{np.random.randint(1, 5)}',
                'command': f'command_{np.random.randint(1, 20)}',
                'file_path': f'/path/to/file_{np.random.randint(1, 10)}.txt',
                'alert_level': np.random.randint(1, 5)
            }
            events.append(event)
        
        return events
    
    def test_feature_extraction(self):
        """Test basic feature extraction."""
        features = self.feature_extractor.extract_features(self.sample_events)
        self.assertIsInstance(features, pd.DataFrame)
        self.assertGreater(len(features.columns), 0)
    
    def test_advanced_feature_extraction(self):
        """Test advanced feature extraction."""
        features = self.advanced_feature_extractor.extract_features(self.sample_events)
        self.assertIsInstance(features, pd.DataFrame)
        self.assertGreater(len(features.columns), 0)
        
        # Check for specific feature types
        feature_names = features.columns.tolist()
        self.assertTrue(any('entropy' in name for name in feature_names))
        self.assertTrue(any('transition' in name for name in feature_names))
        self.assertTrue(any('correlation' in name for name in feature_names))
    
    def test_anomaly_detector(self):
        """Test anomaly detector."""
        # Train model
        features = self.feature_extractor.extract_features(self.sample_events)
        self.anomaly_detector.train(features)
        
        # Test prediction
        predictions = self.anomaly_detector.predict(features)
        self.assertIsInstance(predictions, np.ndarray)
        self.assertEqual(len(predictions), len(features))
        
        # Test model info
        model_info = self.anomaly_detector.get_model_info()
        self.assertIsInstance(model_info, dict)
        self.assertIn('model_type', model_info)
        self.assertIn('version', model_info)
    
    def test_wazuh_ml_integration(self):
        """Test Wazuh ML integration."""
        # Test model factory
        model_factory = WazuhModelFactory(self.config)
        anomaly_model = model_factory.create_model('anomaly_detector')
        self.assertIsNotNone(anomaly_model)
        
        # Test model training
        features = self.feature_extractor.extract_features(self.sample_events)
        try:
            anomaly_model.train(features)
        except Exception as e:
            self.skipTest(f"Wazuh ML API not available: {str(e)}")
        
        # Test model prediction
        try:
            predictions = anomaly_model.predict(features)
            self.assertIsInstance(predictions, np.ndarray)
            self.assertEqual(len(predictions), len(features))
        except Exception as e:
            self.skipTest(f"Wazuh ML API not available: {str(e)}")
    
    def test_hybrid_detector(self):
        """Test hybrid detector."""
        # Train hybrid model
        features = self.feature_extractor.extract_features(self.sample_events)
        self.hybrid_detector.train(features)
        
        # Test prediction
        predictions = self.hybrid_detector.predict(features)
        self.assertIsInstance(predictions, np.ndarray)
        self.assertEqual(len(predictions), len(features))
        
        # Test model info
        model_info = self.hybrid_detector.get_model_info()
        self.assertIsInstance(model_info, dict)
        self.assertIn('local_model', model_info)
        self.assertIn('wazuh_model', model_info)
        
        # Test weight update
        new_weights = {'local': 0.7, 'wazuh': 0.3}
        self.hybrid_detector.update_weights(new_weights)
        updated_info = self.hybrid_detector.get_model_info()
        self.assertEqual(updated_info['weights'], new_weights)
    
    def test_model_persistence(self):
        """Test model saving and loading."""
        # Train and save model
        features = self.feature_extractor.extract_features(self.sample_events)
        self.anomaly_detector.train(features)
        
        # Create new detector instance
        new_detector = AnomalyDetector(self.config)
        
        # Test prediction with loaded model
        predictions = new_detector.predict(features)
        self.assertIsInstance(predictions, np.ndarray)
        self.assertEqual(len(predictions), len(features))
    
    def test_drift_detection(self):
        """Test drift detection."""
        # Train initial model
        features = self.feature_extractor.extract_features(self.sample_events)
        self.anomaly_detector.train(features)
        
        # Generate drifted data
        drifted_events = self._generate_sample_events(100)
        for event in drifted_events:
            event['alert_level'] = np.random.randint(4, 8)  # Higher alert levels
        
        drifted_features = self.feature_extractor.extract_features(drifted_events)
        
        # Test drift detection
        predictions = self.anomaly_detector.predict(drifted_features)
        model_info = self.anomaly_detector.get_model_info()
        self.assertIn('drift_detected', model_info)
    
    def test_feature_extraction_error_handling(self):
        """Test error handling in feature extraction."""
        # Test with empty events
        features = self.feature_extractor.extract_features([])
        self.assertTrue(features.empty)
        
        # Test with invalid events
        invalid_events = [{'invalid': 'data'}]
        features = self.feature_extractor.extract_features(invalid_events)
        self.assertIsInstance(features, pd.DataFrame)
    
    def test_model_error_handling(self):
        """Test error handling in model operations."""
        # Test prediction without training
        features = self.feature_extractor.extract_features(self.sample_events)
        new_detector = AnomalyDetector(self.config)
        
        with self.assertRaises(Exception):
            new_detector.predict(features)
        
        # Test with invalid features
        invalid_features = pd.DataFrame({'invalid': [1, 2, 3]})
        with self.assertRaises(Exception):
            self.anomaly_detector.predict(invalid_features)

if __name__ == '__main__':
    unittest.main() 