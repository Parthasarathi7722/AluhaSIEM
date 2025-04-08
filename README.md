# AluhaSIEM - Advanced Security Information and Event Management with ML

AluhaSIEM is a modern Security Information and Event Management (SIEM) system that leverages machine learning for advanced anomaly detection and security event analysis. It integrates with Wazuh and provides real-time monitoring, alerting, and incident management capabilities.

## Features

- **Machine Learning-Based Anomaly Detection**
  - Isolation Forest algorithm for robust anomaly detection
  - Advanced feature extraction from security events
  - Configurable model parameters and thresholds

- **Wazuh Integration**
  - Seamless integration with Wazuh security platform
  - Real-time event processing and analysis
  - Automated response capabilities

- **Advanced Feature Extraction**
  - Text-based feature extraction
  - Sequence analysis
  - Correlation detection
  - Entropy-based anomaly scoring

- **Incident Management**
  - Automated incident creation and escalation
  - Configurable severity levels
  - Customizable response rules

- **Notification System**
  - Slack integration
  - Email notifications
  - Customizable alert templates

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/AluhaSIEM.git
cd AluhaSIEM
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure the system:
   - Copy `config.yaml` to `config.local.yaml`
   - Update the configuration with your settings
   - Set required environment variables:
     ```bash
     export WAZUH_API_PASSWORD="your_password"
     export SLACK_WEBHOOK_URL="your_webhook_url"
     export EMAIL_PASSWORD="your_email_password"
     ```

## Usage

1. Start the ML engine:
```bash
python src/main.py
```

2. The system will:
   - Initialize the ML model
   - Connect to Wazuh
   - Begin processing security events
   - Send notifications for detected anomalies

3. Monitor the logs:
```bash
tail -f logs/aluha_siem.log
```

## Configuration

The system is configured through `config.yaml`. Key configuration sections:

- **ML Engine**: Model type, training parameters, and prediction thresholds
- **Feature Extraction**: Settings for different feature extraction methods
- **Wazuh Integration**: API connection details
- **Notifications**: Slack and email notification settings
- **Incident Management**: Rules for incident creation and escalation
- **Logging**: Log level and file settings
- **API**: Server configuration and rate limiting

## Development

1. Install development dependencies:
```bash
pip install -r requirements-dev.txt
```

2. Run tests:
```bash
pytest tests/
```

3. Code style:
```bash
flake8 src/
black src/
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please open an issue in the GitHub repository or contact the maintainers.

## Acknowledgments

- Wazuh team for their excellent security platform
- Scikit-learn team for the machine learning libraries
- All contributors and users of AluhaSIEM
