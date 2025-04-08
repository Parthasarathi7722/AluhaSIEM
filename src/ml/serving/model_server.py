import os
import json
import argparse
from typing import Dict, List, Optional, Union, Any
import structlog
from datetime import datetime
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify
import joblib
from sklearn.preprocessing import StandardScaler

logger = structlog.get_logger()

app = Flask(__name__)

class ModelServer:
    """
    Server for serving deployed ML models.
    """
    
    def __init__(self, model_path: str, config: Dict):
        """
        Initialize the model server.
        
        Args:
            model_path: Path to the model file
            config: Server configuration
        """
        self.model_path = model_path
        self.config = config
        
        # Load model and scaler
        self.model = joblib.load(model_path)
        scaler_path = os.path.join(os.path.dirname(model_path), 'scaler.joblib')
        self.scaler = joblib.load(scaler_path) if os.path.exists(scaler_path) else None
        
        logger.info("model_server_initialized",
                   model_path=model_path,
                   config=config)
    
    def preprocess_data(self, data: Dict) -> pd.DataFrame:
        """
        Preprocess input data.
        
        Args:
            data: Input data
            
        Returns:
            Preprocessed DataFrame
        """
        # Convert to DataFrame
        df = pd.DataFrame(data)
        
        # Handle missing values
        df = df.fillna(df.mean())
        
        # Scale features if scaler exists
        if self.scaler is not None:
            df = pd.DataFrame(
                self.scaler.transform(df),
                columns=df.columns
            )
        
        return df
    
    def predict(self, data: Dict) -> Dict:
        """
        Make predictions using the model.
        
        Args:
            data: Input data
            
        Returns:
            Prediction results
        """
        try:
            # Preprocess data
            df = self.preprocess_data(data)
            
            # Make predictions
            predictions = self.model.predict(df)
            scores = self.model.score_samples(df)
            
            # Prepare results
            results = {
                'predictions': predictions.tolist(),
                'scores': scores.tolist(),
                'timestamp': datetime.now().isoformat()
            }
            
            logger.info("prediction_made",
                       prediction_count=len(predictions))
            
            return results
            
        except Exception as e:
            logger.error("prediction_failed",
                        error=str(e))
            raise

# Initialize model server
model_server = None

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/predict', methods=['POST'])
def predict():
    """Prediction endpoint."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'error': 'No data provided'
            }), 400
        
        results = model_server.predict(data)
        return jsonify(results)
        
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Model Server')
    parser.add_argument('--model_path', required=True, help='Path to model file')
    parser.add_argument('--config', required=True, help='Server configuration JSON')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to')
    
    args = parser.parse_args()
    
    # Load configuration
    config = json.loads(args.config)
    
    # Initialize model server
    global model_server
    model_server = ModelServer(args.model_path, config)
    
    # Start server
    app.run(host=args.host, port=args.port)

if __name__ == '__main__':
    main() 