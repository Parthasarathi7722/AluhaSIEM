import os
import json
import shutil
from typing import Dict, List, Optional, Union, Any
import structlog
from datetime import datetime
import subprocess
import signal
import psutil
import hashlib

logger = structlog.get_logger()

class ModelDeployment:
    """
    Manages model deployment and serving.
    """
    
    def __init__(self, config: Dict):
        """
        Initialize the model deployment system.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.deployment_dir = os.path.join(
            config['ml_engine']['model_path'],
            'deployments'
        )
        self.serving_dir = os.path.join(
            config['ml_engine']['model_path'],
            'serving'
        )
        
        # Create directories if they don't exist
        os.makedirs(self.deployment_dir, exist_ok=True)
        os.makedirs(self.serving_dir, exist_ok=True)
        
        # Track running deployments
        self.running_deployments = {}
        
        logger.info("model_deployment_initialized",
                   deployment_dir=self.deployment_dir,
                   serving_dir=self.serving_dir)
    
    def deploy_model(self,
                    model_path: str,
                    deployment_name: str,
                    deployment_config: Dict) -> str:
        """
        Deploy a model for serving.
        
        Args:
            model_path: Path to the model file
            deployment_name: Name of the deployment
            deployment_config: Deployment configuration
            
        Returns:
            Deployment ID
        """
        # Generate deployment ID
        deployment_id = self._generate_deployment_id(deployment_name, deployment_config)
        
        # Create deployment directory
        deployment_path = os.path.join(self.deployment_dir, deployment_id)
        os.makedirs(deployment_path, exist_ok=True)
        
        # Copy model file
        model_filename = os.path.basename(model_path)
        new_model_path = os.path.join(deployment_path, model_filename)
        shutil.copy2(model_path, new_model_path)
        
        # Save deployment metadata
        metadata = {
            'deployment_id': deployment_id,
            'name': deployment_name,
            'config': deployment_config,
            'model_path': new_model_path,
            'timestamp': datetime.now().isoformat(),
            'status': 'created'
        }
        
        metadata_path = os.path.join(deployment_path, 'metadata.json')
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info("model_deployment_created",
                   deployment_id=deployment_id,
                   metadata=metadata)
        
        return deployment_id
    
    def start_serving(self, deployment_id: str) -> Dict:
        """
        Start serving a deployed model.
        
        Args:
            deployment_id: Deployment ID
            
        Returns:
            Deployment status
        """
        deployment_path = os.path.join(self.deployment_dir, deployment_id)
        metadata_path = os.path.join(deployment_path, 'metadata.json')
        
        if not os.path.exists(metadata_path):
            raise ValueError(f"Deployment {deployment_id} not found")
        
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        # Check if already running
        if deployment_id in self.running_deployments:
            logger.warning("deployment_already_running",
                         deployment_id=deployment_id)
            return metadata
        
        # Start serving process
        try:
            process = subprocess.Popen(
                ['python', '-m', 'src.ml.serving.model_server',
                 '--model_path', metadata['model_path'],
                 '--config', json.dumps(metadata['config'])],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Store process info
            self.running_deployments[deployment_id] = {
                'process': process,
                'pid': process.pid,
                'start_time': datetime.now().isoformat()
            }
            
            # Update metadata
            metadata['status'] = 'running'
            metadata['pid'] = process.pid
            metadata['start_time'] = self.running_deployments[deployment_id]['start_time']
            
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info("model_serving_started",
                       deployment_id=deployment_id,
                       pid=process.pid)
            
            return metadata
            
        except Exception as e:
            logger.error("failed_to_start_serving",
                        deployment_id=deployment_id,
                        error=str(e))
            raise
    
    def stop_serving(self, deployment_id: str) -> Dict:
        """
        Stop serving a deployed model.
        
        Args:
            deployment_id: Deployment ID
            
        Returns:
            Deployment status
        """
        deployment_path = os.path.join(self.deployment_dir, deployment_id)
        metadata_path = os.path.join(deployment_path, 'metadata.json')
        
        if not os.path.exists(metadata_path):
            raise ValueError(f"Deployment {deployment_id} not found")
        
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        # Check if running
        if deployment_id not in self.running_deployments:
            logger.warning("deployment_not_running",
                         deployment_id=deployment_id)
            return metadata
        
        # Stop serving process
        try:
            process_info = self.running_deployments[deployment_id]
            process = process_info['process']
            
            # Send termination signal
            process.terminate()
            
            # Wait for process to terminate
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            
            # Remove from running deployments
            del self.running_deployments[deployment_id]
            
            # Update metadata
            metadata['status'] = 'stopped'
            metadata['stop_time'] = datetime.now().isoformat()
            
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info("model_serving_stopped",
                       deployment_id=deployment_id)
            
            return metadata
            
        except Exception as e:
            logger.error("failed_to_stop_serving",
                        deployment_id=deployment_id,
                        error=str(e))
            raise
    
    def get_deployment_status(self, deployment_id: str) -> Dict:
        """
        Get deployment status.
        
        Args:
            deployment_id: Deployment ID
            
        Returns:
            Deployment status
        """
        deployment_path = os.path.join(self.deployment_dir, deployment_id)
        metadata_path = os.path.join(deployment_path, 'metadata.json')
        
        if not os.path.exists(metadata_path):
            raise ValueError(f"Deployment {deployment_id} not found")
        
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        # Check if process is still running
        if deployment_id in self.running_deployments:
            process_info = self.running_deployments[deployment_id]
            process = process_info['process']
            
            if process.poll() is not None:
                # Process has terminated
                metadata['status'] = 'stopped'
                metadata['stop_time'] = datetime.now().isoformat()
                del self.running_deployments[deployment_id]
                
                with open(metadata_path, 'w') as f:
                    json.dump(metadata, f, indent=2)
        
        return metadata
    
    def list_deployments(self) -> List[Dict]:
        """
        List all deployments.
        
        Returns:
            List of deployment metadata
        """
        deployments = []
        
        for deployment_id in os.listdir(self.deployment_dir):
            try:
                deployment_info = self.get_deployment_status(deployment_id)
                deployments.append(deployment_info)
            except Exception as e:
                logger.warning("failed_to_load_deployment",
                             deployment_id=deployment_id,
                             error=str(e))
        
        return sorted(deployments, key=lambda x: x['timestamp'], reverse=True)
    
    def _generate_deployment_id(self, name: str, config: Dict) -> str:
        """
        Generate a unique deployment ID.
        
        Args:
            name: Deployment name
            config: Deployment configuration
            
        Returns:
            Deployment ID
        """
        # Create a string representation of deployment info
        info_str = f"{name}_{json.dumps(config, sort_keys=True)}"
        
        # Generate hash
        hash_obj = hashlib.sha256(info_str.encode())
        deployment_id = hash_obj.hexdigest()[:12]
        
        return deployment_id 