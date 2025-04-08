import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Union, Any
import structlog
from datetime import datetime, timedelta
import re
import hashlib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler

logger = structlog.get_logger()

class AdvancedFeatureExtractor:
    """
    Advanced feature extraction for security event data.
    """
    
    def __init__(self, config: Dict):
        """
        Initialize the advanced feature extractor.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.feature_configs = config.get('advanced_features', {})
        
        # Initialize feature extractors
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=self.feature_configs.get('tfidf_max_features', 100),
            stop_words='english'
        )
        self.scaler = StandardScaler()
        
        # Feature extraction settings
        self.text_features_enabled = self.feature_configs.get('text_features', {}).get('enabled', True)
        self.sequence_features_enabled = self.feature_configs.get('sequence_features', {}).get('enabled', True)
        self.correlation_features_enabled = self.feature_configs.get('correlation_features', {}).get('enabled', True)
        self.entropy_features_enabled = self.feature_configs.get('entropy_features', {}).get('enabled', True)
        
        logger.info("advanced_feature_extractor_initialized",
                   text_features_enabled=self.text_features_enabled,
                   sequence_features_enabled=self.sequence_features_enabled,
                   correlation_features_enabled=self.correlation_features_enabled,
                   entropy_features_enabled=self.entropy_features_enabled)
    
    def extract_features(self, events: List[Dict]) -> pd.DataFrame:
        """
        Extract advanced features from security events.
        
        Args:
            events: List of security event dictionaries
            
        Returns:
            DataFrame containing extracted features
        """
        if not events:
            logger.warning("no_events_to_process")
            return pd.DataFrame()
        
        # Convert events to DataFrame
        df = pd.DataFrame(events)
        
        # Extract basic features
        features = {}
        
        # Text features
        if self.text_features_enabled:
            features.update(self._extract_text_features(df))
        
        # Sequence features
        if self.sequence_features_enabled:
            features.update(self._extract_sequence_features(df))
        
        # Correlation features
        if self.correlation_features_enabled:
            features.update(self._extract_correlation_features(df))
        
        # Entropy features
        if self.entropy_features_enabled:
            features.update(self._extract_entropy_features(df))
        
        # Create feature DataFrame
        feature_df = pd.DataFrame([features])
        
        logger.info("advanced_features_extracted", 
                   feature_count=len(feature_df.columns),
                   event_count=len(events))
        
        return feature_df
    
    def _extract_text_features(self, df: pd.DataFrame) -> Dict:
        """
        Extract features from text fields.
        
        Args:
            df: Input DataFrame
            
        Returns:
            Dictionary of text-related features
        """
        features = {}
        
        # Command features
        if 'command' in df.columns:
            # TF-IDF features for commands
            commands = df['command'].fillna('').astype(str)
            if len(commands) > 0:
                try:
                    tfidf_matrix = self.tfidf_vectorizer.fit_transform(commands)
                    tfidf_features = tfidf_matrix.mean(axis=0).A1
                    for i, value in enumerate(tfidf_features):
                        features[f'command_tfidf_{i}'] = value
                except Exception as e:
                    logger.warning("tfidf_extraction_failed", error=str(e))
            
            # Command length features
            features['command_avg_length'] = df['command'].str.len().mean()
            features['command_max_length'] = df['command'].str.len().max()
            features['command_min_length'] = df['command'].str.len().min()
            
            # Command complexity features
            features['command_special_char_ratio'] = df['command'].apply(
                lambda x: len(re.findall(r'[^a-zA-Z0-9\s]', str(x))) / len(str(x)) if len(str(x)) > 0 else 0
            ).mean()
            
            # Command entropy
            features['command_entropy'] = self._calculate_entropy(
                df['command'].value_counts()
            )
        
        # Username features
        if 'username' in df.columns:
            # Username complexity
            features['username_special_char_ratio'] = df['username'].apply(
                lambda x: len(re.findall(r'[^a-zA-Z0-9\s]', str(x))) / len(str(x)) if len(str(x)) > 0 else 0
            ).mean()
            
            # Username entropy
            features['username_entropy'] = self._calculate_entropy(
                df['username'].value_counts()
            )
        
        # File path features
        if 'file_path' in df.columns:
            # Path depth
            features['path_avg_depth'] = df['file_path'].apply(
                lambda x: len(str(x).split('/')) if '/' in str(x) else 1
            ).mean()
            
            # File extension entropy
            extensions = df['file_path'].apply(
                lambda x: str(x).split('.')[-1] if '.' in str(x) else 'no_extension'
            )
            features['file_extension_entropy'] = self._calculate_entropy(
                extensions.value_counts()
            )
        
        return features
    
    def _extract_sequence_features(self, df: pd.DataFrame) -> Dict:
        """
        Extract features from event sequences.
        
        Args:
            df: Input DataFrame
            
        Returns:
            Dictionary of sequence-related features
        """
        features = {}
        
        # Sort by timestamp if available
        if 'timestamp' in df.columns:
            df = df.sort_values('timestamp')
        
        # Event type sequences
        if 'event_type' in df.columns:
            # Event type transitions
            event_types = df['event_type'].values
            if len(event_types) > 1:
                transitions = {}
                for i in range(len(event_types) - 1):
                    transition = f"{event_types[i]}->{event_types[i+1]}"
                    transitions[transition] = transitions.get(transition, 0) + 1
                
                # Add transition features
                for transition, count in transitions.items():
                    features[f'event_transition_{transition}'] = count
                
                # Transition entropy
                features['event_transition_entropy'] = self._calculate_entropy(
                    pd.Series(transitions)
                )
        
        # Command sequences
        if 'command' in df.columns:
            commands = df['command'].values
            if len(commands) > 1:
                # Command transitions
                cmd_transitions = {}
                for i in range(len(commands) - 1):
                    transition = f"{commands[i]}->{commands[i+1]}"
                    cmd_transitions[transition] = cmd_transitions.get(transition, 0) + 1
                
                # Add command transition features
                for transition, count in cmd_transitions.items():
                    features[f'command_transition_{transition}'] = count
                
                # Command transition entropy
                features['command_transition_entropy'] = self._calculate_entropy(
                    pd.Series(cmd_transitions)
                )
        
        # Time-based sequences
        if 'timestamp' in df.columns:
            # Time intervals between events
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            time_diffs = df['timestamp'].diff().dt.total_seconds()
            
            features['avg_time_interval'] = time_diffs.mean()
            features['max_time_interval'] = time_diffs.max()
            features['min_time_interval'] = time_diffs.min()
            features['std_time_interval'] = time_diffs.std()
            
            # Time of day patterns
            df['hour'] = df['timestamp'].dt.hour
            hour_counts = df['hour'].value_counts()
            features['hour_entropy'] = self._calculate_entropy(hour_counts)
            
            # Day of week patterns
            df['day_of_week'] = df['timestamp'].dt.dayofweek
            day_counts = df['day_of_week'].value_counts()
            features['day_of_week_entropy'] = self._calculate_entropy(day_counts)
        
        return features
    
    def _extract_correlation_features(self, df: pd.DataFrame) -> Dict:
        """
        Extract correlation features between different event attributes.
        
        Args:
            df: Input DataFrame
            
        Returns:
            Dictionary of correlation-related features
        """
        features = {}
        
        # User-command correlations
        if 'username' in df.columns and 'command' in df.columns:
            # Commands per user
            user_command_counts = df.groupby('username')['command'].count()
            features['avg_commands_per_user'] = user_command_counts.mean()
            features['max_commands_per_user'] = user_command_counts.max()
            features['min_commands_per_user'] = user_command_counts.min()
            
            # Unique commands per user
            user_unique_commands = df.groupby('username')['command'].nunique()
            features['avg_unique_commands_per_user'] = user_unique_commands.mean()
            features['max_unique_commands_per_user'] = user_unique_commands.max()
            features['min_unique_commands_per_user'] = user_unique_commands.min()
        
        # User-file correlations
        if 'username' in df.columns and 'file_path' in df.columns:
            # Files accessed per user
            user_file_counts = df.groupby('username')['file_path'].count()
            features['avg_files_per_user'] = user_file_counts.mean()
            features['max_files_per_user'] = user_file_counts.max()
            features['min_files_per_user'] = user_file_counts.min()
            
            # Unique files per user
            user_unique_files = df.groupby('username')['file_path'].nunique()
            features['avg_unique_files_per_user'] = user_unique_files.mean()
            features['max_unique_files_per_user'] = user_unique_files.max()
            features['min_unique_files_per_user'] = user_unique_files.min()
        
        # Process-command correlations
        if 'process_name' in df.columns and 'command' in df.columns:
            # Commands per process
            process_command_counts = df.groupby('process_name')['command'].count()
            features['avg_commands_per_process'] = process_command_counts.mean()
            features['max_commands_per_process'] = process_command_counts.max()
            features['min_commands_per_process'] = process_command_counts.min()
            
            # Unique commands per process
            process_unique_commands = df.groupby('process_name')['command'].nunique()
            features['avg_unique_commands_per_process'] = process_unique_commands.mean()
            features['max_unique_commands_per_process'] = process_unique_commands.max()
            features['min_unique_commands_per_process'] = process_unique_commands.min()
        
        # IP-command correlations
        if 'source_ip' in df.columns and 'command' in df.columns:
            # Commands per IP
            ip_command_counts = df.groupby('source_ip')['command'].count()
            features['avg_commands_per_ip'] = ip_command_counts.mean()
            features['max_commands_per_ip'] = ip_command_counts.max()
            features['min_commands_per_ip'] = ip_command_counts.min()
            
            # Unique commands per IP
            ip_unique_commands = df.groupby('source_ip')['command'].nunique()
            features['avg_unique_commands_per_ip'] = ip_unique_commands.mean()
            features['max_unique_commands_per_ip'] = ip_unique_commands.max()
            features['min_unique_commands_per_ip'] = ip_unique_commands.min()
        
        return features
    
    def _extract_entropy_features(self, df: pd.DataFrame) -> Dict:
        """
        Extract entropy-based features.
        
        Args:
            df: Input DataFrame
            
        Returns:
            Dictionary of entropy-related features
        """
        features = {}
        
        # Event type entropy
        if 'event_type' in df.columns:
            features['event_type_entropy'] = self._calculate_entropy(
                df['event_type'].value_counts()
            )
        
        # Username entropy
        if 'username' in df.columns:
            features['username_entropy'] = self._calculate_entropy(
                df['username'].value_counts()
            )
        
        # Process name entropy
        if 'process_name' in df.columns:
            features['process_name_entropy'] = self._calculate_entropy(
                df['process_name'].value_counts()
            )
        
        # Source IP entropy
        if 'source_ip' in df.columns:
            features['source_ip_entropy'] = self._calculate_entropy(
                df['source_ip'].value_counts()
            )
        
        # Destination IP entropy
        if 'destination_ip' in df.columns:
            features['destination_ip_entropy'] = self._calculate_entropy(
                df['destination_ip'].value_counts()
            )
        
        # Alert level entropy
        if 'alert_level' in df.columns:
            features['alert_level_entropy'] = self._calculate_entropy(
                df['alert_level'].value_counts()
            )
        
        # Command entropy
        if 'command' in df.columns:
            features['command_entropy'] = self._calculate_entropy(
                df['command'].value_counts()
            )
        
        # File path entropy
        if 'file_path' in df.columns:
            features['file_path_entropy'] = self._calculate_entropy(
                df['file_path'].value_counts()
            )
        
        # Combined entropy features
        if 'username' in df.columns and 'command' in df.columns:
            # Joint entropy of username and command
            joint_counts = df.groupby(['username', 'command']).size()
            features['username_command_joint_entropy'] = self._calculate_entropy(joint_counts)
        
        if 'source_ip' in df.columns and 'destination_ip' in df.columns:
            # Joint entropy of source and destination IPs
            joint_counts = df.groupby(['source_ip', 'destination_ip']).size()
            features['ip_joint_entropy'] = self._calculate_entropy(joint_counts)
        
        return features
    
    def _calculate_entropy(self, counts: pd.Series) -> float:
        """
        Calculate Shannon entropy of a distribution.
        
        Args:
            counts: Series of counts
            
        Returns:
            Entropy value
        """
        if len(counts) == 0:
            return 0.0
        
        probabilities = counts / counts.sum()
        return -np.sum(probabilities * np.log2(probabilities + 1e-10))
    
    def get_feature_names(self) -> List[str]:
        """
        Get list of feature names.
        
        Returns:
            List of feature names
        """
        # Create sample data to extract feature names
        sample_events = [{
            'timestamp': datetime.now(),
            'event_type': 'sample',
            'source_ip': '192.168.1.1',
            'destination_ip': '192.168.1.2',
            'username': 'user',
            'process_name': 'process',
            'command': 'ls -la',
            'file_path': '/etc/passwd',
            'alert_level': 1
        }]
        
        sample_features = self.extract_features(sample_events)
        return list(sample_features.columns) 