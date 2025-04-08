import os
import json
import hashlib
from typing import Dict, List, Optional, Union, Any
import structlog
from datetime import datetime
import shutil

logger = structlog.get_logger()

class ModelVersioning:
    """
    Manages model versions and experiment tracking.
    """
    
    def __init__(self, config: Dict):
        """
        Initialize the model versioning system.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.version_dir = os.path.join(
            config['ml_engine']['model_path'],
            'versions'
        )
        self.experiment_dir = os.path.join(
            config['ml_engine']['model_path'],
            'experiments'
        )
        
        # Create directories if they don't exist
        os.makedirs(self.version_dir, exist_ok=True)
        os.makedirs(self.experiment_dir, exist_ok=True)
        
        logger.info("model_versioning_initialized",
                   version_dir=self.version_dir,
                   experiment_dir=self.experiment_dir)
    
    def create_version(self, 
                      model_path: str,
                      model_info: Dict,
                      metrics: Optional[Dict] = None) -> str:
        """
        Create a new model version.
        
        Args:
            model_path: Path to the model file
            model_info: Model information
            metrics: Model metrics
            
        Returns:
            Version ID
        """
        # Generate version ID
        version_id = self._generate_version_id(model_info)
        
        # Create version directory
        version_path = os.path.join(self.version_dir, version_id)
        os.makedirs(version_path, exist_ok=True)
        
        # Copy model file
        model_filename = os.path.basename(model_path)
        new_model_path = os.path.join(version_path, model_filename)
        shutil.copy2(model_path, new_model_path)
        
        # Save metadata
        metadata = {
            'version_id': version_id,
            'timestamp': datetime.now().isoformat(),
            'model_info': model_info,
            'metrics': metrics or {},
            'model_path': new_model_path
        }
        
        metadata_path = os.path.join(version_path, 'metadata.json')
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info("model_version_created",
                   version_id=version_id,
                   metadata=metadata)
        
        return version_id
    
    def get_version(self, version_id: str) -> Dict:
        """
        Get version information.
        
        Args:
            version_id: Version ID
            
        Returns:
            Version metadata
        """
        version_path = os.path.join(self.version_dir, version_id)
        metadata_path = os.path.join(version_path, 'metadata.json')
        
        if not os.path.exists(metadata_path):
            raise ValueError(f"Version {version_id} not found")
        
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        return metadata
    
    def list_versions(self) -> List[Dict]:
        """
        List all model versions.
        
        Returns:
            List of version metadata
        """
        versions = []
        
        for version_id in os.listdir(self.version_dir):
            try:
                version_info = self.get_version(version_id)
                versions.append(version_info)
            except Exception as e:
                logger.warning("failed_to_load_version",
                             version_id=version_id,
                             error=str(e))
        
        return sorted(versions, key=lambda x: x['timestamp'], reverse=True)
    
    def create_experiment(self,
                         name: str,
                         description: str,
                         parameters: Dict) -> str:
        """
        Create a new experiment.
        
        Args:
            name: Experiment name
            description: Experiment description
            parameters: Experiment parameters
            
        Returns:
            Experiment ID
        """
        # Generate experiment ID
        experiment_id = self._generate_experiment_id(name, parameters)
        
        # Create experiment directory
        experiment_path = os.path.join(self.experiment_dir, experiment_id)
        os.makedirs(experiment_path, exist_ok=True)
        
        # Save experiment metadata
        metadata = {
            'experiment_id': experiment_id,
            'name': name,
            'description': description,
            'parameters': parameters,
            'timestamp': datetime.now().isoformat(),
            'status': 'created',
            'versions': []
        }
        
        metadata_path = os.path.join(experiment_path, 'metadata.json')
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info("experiment_created",
                   experiment_id=experiment_id,
                   metadata=metadata)
        
        return experiment_id
    
    def add_version_to_experiment(self,
                                experiment_id: str,
                                version_id: str) -> None:
        """
        Add a model version to an experiment.
        
        Args:
            experiment_id: Experiment ID
            version_id: Version ID
        """
        experiment_path = os.path.join(self.experiment_dir, experiment_id)
        metadata_path = os.path.join(experiment_path, 'metadata.json')
        
        if not os.path.exists(metadata_path):
            raise ValueError(f"Experiment {experiment_id} not found")
        
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        if version_id not in metadata['versions']:
            metadata['versions'].append(version_id)
            
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info("version_added_to_experiment",
                       experiment_id=experiment_id,
                       version_id=version_id)
    
    def get_experiment(self, experiment_id: str) -> Dict:
        """
        Get experiment information.
        
        Args:
            experiment_id: Experiment ID
            
        Returns:
            Experiment metadata
        """
        experiment_path = os.path.join(self.experiment_dir, experiment_id)
        metadata_path = os.path.join(experiment_path, 'metadata.json')
        
        if not os.path.exists(metadata_path):
            raise ValueError(f"Experiment {experiment_id} not found")
        
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        return metadata
    
    def list_experiments(self) -> List[Dict]:
        """
        List all experiments.
        
        Returns:
            List of experiment metadata
        """
        experiments = []
        
        for experiment_id in os.listdir(self.experiment_dir):
            try:
                experiment_info = self.get_experiment(experiment_id)
                experiments.append(experiment_info)
            except Exception as e:
                logger.warning("failed_to_load_experiment",
                             experiment_id=experiment_id,
                             error=str(e))
        
        return sorted(experiments, key=lambda x: x['timestamp'], reverse=True)
    
    def _generate_version_id(self, model_info: Dict) -> str:
        """
        Generate a unique version ID.
        
        Args:
            model_info: Model information
            
        Returns:
            Version ID
        """
        # Create a string representation of model info
        info_str = json.dumps(model_info, sort_keys=True)
        
        # Generate hash
        hash_obj = hashlib.sha256(info_str.encode())
        version_id = hash_obj.hexdigest()[:12]
        
        return version_id
    
    def _generate_experiment_id(self, name: str, parameters: Dict) -> str:
        """
        Generate a unique experiment ID.
        
        Args:
            name: Experiment name
            parameters: Experiment parameters
            
        Returns:
            Experiment ID
        """
        # Create a string representation of experiment info
        info_str = f"{name}_{json.dumps(parameters, sort_keys=True)}"
        
        # Generate hash
        hash_obj = hashlib.sha256(info_str.encode())
        experiment_id = hash_obj.hexdigest()[:12]
        
        return experiment_id 