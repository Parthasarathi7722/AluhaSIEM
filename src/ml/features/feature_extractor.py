import pandas as pd
import numpy as np
from typing import Dict, List, Optional
import structlog
from datetime import datetime, timedelta

logger = structlog.get_logger()

class FeatureExtractor:
    """
    Feature extraction for security event data.
    """
    
    def __init__(self, config: Dict):
        """
        Initialize the feature extractor.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.feature_configs = config.get('features', {})
        self.window_size = self.feature_configs.get('window_size', 3600)  # 1 hour default
        
        # Initialize feature extractors based on config
        self.user_behavior_enabled = self.feature_configs.get('user_behavior', {}).get('enabled', True)
        self.network_traffic_enabled = self.feature_configs.get('network_traffic', {}).get('enabled', True)
        self.system_calls_enabled = self.feature_configs.get('system_calls', {}).get('enabled', True)
        self.command_line_enabled = self.feature_configs.get('command_line', {}).get('enabled', True)
        
        logger.info("feature_extractor_initialized", 
                   window_size=self.window_size,
                   user_behavior_enabled=self.user_behavior_enabled,
                   network_traffic_enabled=self.network_traffic_enabled,
                   system_calls_enabled=self.system_calls_enabled,
                   command_line_enabled=self.command_line_enabled)
    
    def extract_features(self, events: List[Dict]) -> pd.DataFrame:
        """
        Extract features from security events.
        
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
        
        # Extract timestamp features
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        
        # Extract basic features
        features = {}
        
        # Event type counts
        event_type_counts = df['event_type'].value_counts()
        for event_type in event_type_counts.index:
            features[f'event_type_{event_type}'] = event_type_counts[event_type]
        
        # Source IP features
        if 'source_ip' in df.columns:
            features.update(self._extract_ip_features(df, 'source_ip'))
        
        # Destination IP features
        if 'destination_ip' in df.columns:
            features.update(self._extract_ip_features(df, 'destination_ip'))
        
        # User features
        if 'username' in df.columns and self.user_behavior_enabled:
            features.update(self._extract_user_features(df))
        
        # Process features
        if 'process_name' in df.columns:
            features.update(self._extract_process_features(df))
        
        # Alert level features
        if 'alert_level' in df.columns:
            features.update(self._extract_alert_features(df))
        
        # Network traffic features
        if self.network_traffic_enabled:
            features.update(self._extract_network_features(df))
        
        # System call features
        if self.system_calls_enabled:
            features.update(self._extract_system_call_features(df))
        
        # Command line features
        if self.command_line_enabled:
            features.update(self._extract_command_line_features(df))
        
        # Create feature DataFrame
        feature_df = pd.DataFrame([features])
        
        logger.info("features_extracted", 
                   feature_count=len(feature_df.columns),
                   event_count=len(events))
        
        return feature_df
    
    def _extract_ip_features(self, df: pd.DataFrame, ip_column: str) -> Dict:
        """
        Extract features related to IP addresses.
        
        Args:
            df: Input DataFrame
            ip_column: Name of the IP column
            
        Returns:
            Dictionary of IP-related features
        """
        features = {}
        
        # IP count
        features[f'{ip_column}_count'] = df[ip_column].nunique()
        
        # IP frequency
        ip_counts = df[ip_column].value_counts()
        features[f'{ip_column}_max_frequency'] = ip_counts.max()
        features[f'{ip_column}_mean_frequency'] = ip_counts.mean()
        
        return features
    
    def _extract_user_features(self, df: pd.DataFrame) -> Dict:
        """
        Extract features related to user activity.
        
        Args:
            df: Input DataFrame
            
        Returns:
            Dictionary of user-related features
        """
        features = {}
        
        # User count
        features['user_count'] = df['username'].nunique()
        
        # User activity frequency
        user_counts = df['username'].value_counts()
        features['user_max_activity'] = user_counts.max()
        features['user_mean_activity'] = user_counts.mean()
        
        # Failed login attempts
        if 'event_type' in df.columns:
            failed_logins = df[df['event_type'] == 'failed_login']
            features['failed_login_count'] = len(failed_logins)
        
        # Command execution patterns
        if 'command' in df.columns:
            command_counts = df['command'].value_counts()
            features['unique_commands'] = len(command_counts)
            features['command_entropy'] = self._calculate_entropy(command_counts)
        
        # File access patterns
        if 'file_path' in df.columns:
            file_counts = df['file_path'].value_counts()
            features['unique_files_accessed'] = len(file_counts)
            features['file_access_entropy'] = self._calculate_entropy(file_counts)
        
        return features
    
    def _extract_process_features(self, df: pd.DataFrame) -> Dict:
        """
        Extract features related to process activity.
        
        Args:
            df: Input DataFrame
            
        Returns:
            Dictionary of process-related features
        """
        features = {}
        
        # Process count
        features['process_count'] = df['process_name'].nunique()
        
        # Process frequency
        process_counts = df['process_name'].value_counts()
        features['process_max_frequency'] = process_counts.max()
        features['process_mean_frequency'] = process_counts.mean()
        
        return features
    
    def _extract_alert_features(self, df: pd.DataFrame) -> Dict:
        """
        Extract features related to alert levels.
        
        Args:
            df: Input DataFrame
            
        Returns:
            Dictionary of alert-related features
        """
        features = {}
        
        # Alert level distribution
        alert_counts = df['alert_level'].value_counts()
        for level in alert_counts.index:
            features[f'alert_level_{level}_count'] = alert_counts[level]
        
        # High severity alerts
        high_severity = df[df['alert_level'] >= 12]
        features['high_severity_count'] = len(high_severity)
        
        return features
    
    def _extract_network_features(self, df: pd.DataFrame) -> Dict:
        """
        Extract features related to network traffic.
        
        Args:
            df: Input DataFrame
            
        Returns:
            Dictionary of network-related features
        """
        features = {}
        
        # Packet statistics
        if 'packet_count' in df.columns:
            features['total_packets'] = df['packet_count'].sum()
            features['avg_packets_per_connection'] = df['packet_count'].mean()
        
        # Byte statistics
        if 'byte_count' in df.columns:
            features['total_bytes'] = df['byte_count'].sum()
            features['avg_bytes_per_connection'] = df['byte_count'].mean()
        
        # Connection statistics
        if 'connection_id' in df.columns:
            features['unique_connections'] = df['connection_id'].nunique()
        
        # Protocol distribution
        if 'protocol' in df.columns:
            protocol_counts = df['protocol'].value_counts()
            for protocol in protocol_counts.index:
                features[f'protocol_{protocol}_count'] = protocol_counts[protocol]
            features['protocol_entropy'] = self._calculate_entropy(protocol_counts)
        
        return features
    
    def _extract_system_call_features(self, df: pd.DataFrame) -> Dict:
        """
        Extract features related to system calls.
        
        Args:
            df: Input DataFrame
            
        Returns:
            Dictionary of system call-related features
        """
        features = {}
        
        # System call frequency
        if 'syscall' in df.columns:
            syscall_counts = df['syscall'].value_counts()
            features['unique_syscalls'] = len(syscall_counts)
            features['syscall_entropy'] = self._calculate_entropy(syscall_counts)
        
        # Process creation patterns
        if 'parent_process' in df.columns:
            parent_counts = df['parent_process'].value_counts()
            features['unique_parent_processes'] = len(parent_counts)
            features['process_creation_entropy'] = self._calculate_entropy(parent_counts)
        
        return features
    
    def _extract_command_line_features(self, df: pd.DataFrame) -> Dict:
        """
        Extract features related to command line activity.
        
        Args:
            df: Input DataFrame
            
        Returns:
            Dictionary of command line-related features
        """
        features = {}
        
        # Command frequency
        if 'command' in df.columns:
            command_counts = df['command'].value_counts()
            features['unique_commands'] = len(command_counts)
            features['command_entropy'] = self._calculate_entropy(command_counts)
        
        # Argument patterns
        if 'arguments' in df.columns:
            arg_counts = df['arguments'].value_counts()
            features['unique_argument_patterns'] = len(arg_counts)
            features['argument_entropy'] = self._calculate_entropy(arg_counts)
        
        # Execution time patterns
        if 'execution_time' in df.columns:
            features['avg_execution_time'] = df['execution_time'].mean()
            features['std_execution_time'] = df['execution_time'].std()
        
        return features
    
    def _calculate_entropy(self, counts: pd.Series) -> float:
        """
        Calculate Shannon entropy of a distribution.
        
        Args:
            counts: Series of counts
            
        Returns:
            Entropy value
        """
        probabilities = counts / counts.sum()
        return -np.sum(probabilities * np.log2(probabilities))
    
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
            'alert_level': 1,
            'command': 'ls',
            'arguments': '-la',
            'execution_time': 0.1,
            'packet_count': 100,
            'byte_count': 1000,
            'protocol': 'TCP',
            'syscall': 'execve',
            'parent_process': 'bash'
        }]
        
        sample_features = self.extract_features(sample_events)
        return list(sample_features.columns) 