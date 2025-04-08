import os
import json
import requests
from typing import Dict, List, Optional
import structlog
from datetime import datetime, timedelta

logger = structlog.get_logger()

class WazuhMLIntegration:
    """
    Integration with Wazuh's built-in ML capabilities.
    """
    
    def __init__(self, config: Dict):
        """
        Initialize Wazuh ML integration.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.wazuh_config = config.get('wazuh', {})
        self.api_url = self.wazuh_config.get('api_url', 'https://localhost:55000')
        self.username = self.wazuh_config.get('username', 'wazuh-wui')
        self.password = self.wazuh_config.get('password', '')
        self.verify_ssl = self.wazuh_config.get('verify_ssl', False)
        self.token = None
        self.token_expiry = None
        
        logger.info("wazuh_ml_integration_initialized",
                   api_url=self.api_url)
    
    def _get_token(self) -> str:
        """
        Get authentication token from Wazuh API.
        
        Returns:
            Authentication token
        """
        if self.token and self.token_expiry and datetime.now() < self.token_expiry:
            return self.token
        
        url = f"{self.api_url}/security/user/authenticate"
        response = requests.post(
            url,
            auth=(self.username, self.password),
            verify=self.verify_ssl
        )
        
        if response.status_code != 200:
            raise Exception(f"Failed to authenticate with Wazuh API: {response.text}")
        
        self.token = response.json()['data']['token']
        self.token_expiry = datetime.now() + timedelta(minutes=30)
        return self.token
    
    def get_ml_models(self) -> List[Dict]:
        """
        Get list of available ML models from Wazuh.
        
        Returns:
            List of ML model information
        """
        token = self._get_token()
        url = f"{self.api_url}/ml/models"
        headers = {'Authorization': f'Bearer {token}'}
        
        response = requests.get(url, headers=headers, verify=self.verify_ssl)
        if response.status_code != 200:
            raise Exception(f"Failed to get ML models: {response.text}")
        
        return response.json()['data']
    
    def get_model_status(self, model_id: str) -> Dict:
        """
        Get status of a specific ML model.
        
        Args:
            model_id: ID of the ML model
            
        Returns:
            Model status information
        """
        token = self._get_token()
        url = f"{self.api_url}/ml/models/{model_id}/status"
        headers = {'Authorization': f'Bearer {token}'}
        
        response = requests.get(url, headers=headers, verify=self.verify_ssl)
        if response.status_code != 200:
            raise Exception(f"Failed to get model status: {response.text}")
        
        return response.json()['data']
    
    def train_model(self, model_id: str, data: Dict) -> Dict:
        """
        Train a Wazuh ML model.
        
        Args:
            model_id: ID of the ML model
            data: Training data and parameters
            
        Returns:
            Training results
        """
        token = self._get_token()
        url = f"{self.api_url}/ml/models/{model_id}/train"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        response = requests.post(
            url,
            headers=headers,
            json=data,
            verify=self.verify_ssl
        )
        if response.status_code != 200:
            raise Exception(f"Failed to train model: {response.text}")
        
        return response.json()['data']
    
    def predict(self, model_id: str, data: Dict) -> Dict:
        """
        Make predictions using a Wazuh ML model.
        
        Args:
            model_id: ID of the ML model
            data: Input data for prediction
            
        Returns:
            Prediction results
        """
        token = self._get_token()
        url = f"{self.api_url}/ml/models/{model_id}/predict"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        response = requests.post(
            url,
            headers=headers,
            json=data,
            verify=self.verify_ssl
        )
        if response.status_code != 200:
            raise Exception(f"Failed to make prediction: {response.text}")
        
        return response.json()['data']
    
    def get_model_metrics(self, model_id: str) -> Dict:
        """
        Get performance metrics for a ML model.
        
        Args:
            model_id: ID of the ML model
            
        Returns:
            Model performance metrics
        """
        token = self._get_token()
        url = f"{self.api_url}/ml/models/{model_id}/metrics"
        headers = {'Authorization': f'Bearer {token}'}
        
        response = requests.get(url, headers=headers, verify=self.verify_ssl)
        if response.status_code != 200:
            raise Exception(f"Failed to get model metrics: {response.text}")
        
        return response.json()['data']
    
    def update_model_config(self, model_id: str, config: Dict) -> Dict:
        """
        Update configuration of a ML model.
        
        Args:
            model_id: ID of the ML model
            config: New model configuration
            
        Returns:
            Updated model information
        """
        token = self._get_token()
        url = f"{self.api_url}/ml/models/{model_id}/config"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        response = requests.put(
            url,
            headers=headers,
            json=config,
            verify=self.verify_ssl
        )
        if response.status_code != 200:
            raise Exception(f"Failed to update model config: {response.text}")
        
        return response.json()['data']
    
    def get_model_alerts(self, model_id: str, 
                        start_time: Optional[datetime] = None,
                        end_time: Optional[datetime] = None) -> List[Dict]:
        """
        Get alerts generated by a ML model.
        
        Args:
            model_id: ID of the ML model
            start_time: Start time for alert search
            end_time: End time for alert search
            
        Returns:
            List of model alerts
        """
        token = self._get_token()
        url = f"{self.api_url}/ml/models/{model_id}/alerts"
        headers = {'Authorization': f'Bearer {token}'}
        
        params = {}
        if start_time:
            params['start_time'] = start_time.isoformat()
        if end_time:
            params['end_time'] = end_time.isoformat()
        
        response = requests.get(
            url,
            headers=headers,
            params=params,
            verify=self.verify_ssl
        )
        if response.status_code != 200:
            raise Exception(f"Failed to get model alerts: {response.text}")
        
        return response.json()['data']
    
    def export_model(self, model_id: str, export_path: str) -> str:
        """
        Export a ML model to file.
        
        Args:
            model_id: ID of the ML model
            export_path: Path to save the exported model
            
        Returns:
            Path to the exported model file
        """
        token = self._get_token()
        url = f"{self.api_url}/ml/models/{model_id}/export"
        headers = {'Authorization': f'Bearer {token}'}
        
        response = requests.get(url, headers=headers, verify=self.verify_ssl)
        if response.status_code != 200:
            raise Exception(f"Failed to export model: {response.text}")
        
        # Save the model file
        os.makedirs(os.path.dirname(export_path), exist_ok=True)
        with open(export_path, 'wb') as f:
            f.write(response.content)
        
        return export_path
    
    def import_model(self, model_id: str, model_path: str) -> Dict:
        """
        Import a ML model from file.
        
        Args:
            model_id: ID for the imported model
            model_path: Path to the model file
            
        Returns:
            Imported model information
        """
        token = self._get_token()
        url = f"{self.api_url}/ml/models/{model_id}/import"
        headers = {'Authorization': f'Bearer {token}'}
        
        with open(model_path, 'rb') as f:
            files = {'model': f}
            response = requests.post(
                url,
                headers=headers,
                files=files,
                verify=self.verify_ssl
            )
        
        if response.status_code != 200:
            raise Exception(f"Failed to import model: {response.text}")
        
        return response.json()['data'] 