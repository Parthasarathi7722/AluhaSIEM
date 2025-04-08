# WazuhAI - ML-Powered SIEM Solution

![Wazuh Logo](https://wazuh.com/uploads/2021/03/Wazuh_logo_light@2x.png)

## Overview

WazuhAI is an enhanced Security Information and Event Management (SIEM) solution built on top of Wazuh that integrates advanced machine learning capabilities for improved threat detection and incident response. This project provides a complete, containerized setup for deploying a production-ready Wazuh environment with customized ML modules for anomaly detection, behavioral analysis, and predictive threat intelligence.

## Features

- **Complete Wazuh SIEM Stack**: Full implementation of Wazuh server, agents, and the Elastic Stack
- **Enhanced ML Capabilities**: Custom machine learning modules beyond Wazuh's default capabilities
- **Model Context Protocol**: Framework for maintaining, versioning, and improving ML models
- **Docker-Based Deployment**: Easy deployment using containerization
- **Comprehensive Log Management**: Advanced configurations for various log sources
- **Automated Response Actions**: ML-driven incident response automation
- **Performance Optimization**: Tuned configurations for handling large-scale deployments
- **Detailed Documentation**: Complete guides for setup, customization, and operation

## Architecture

```
                                ┌──────────────────┐
                                │                  │
                                │ Wazuh Agents     │
                                │                  │
                                └────────┬─────────┘
                                         │
                                         ▼
┌──────────────────┐          ┌──────────────────┐          ┌──────────────────┐
│                  │          │                  │          │                  │
│ Log Sources      ├─────────▶│ Wazuh Server     ├─────────▶│ Elasticsearch    │
│                  │          │                  │          │                  │
└──────────────────┘          └────────┬─────────┘          └────────┬─────────┘
                                       │                             │
                                       │                             │
                                       ▼                             ▼
                              ┌──────────────────┐          ┌──────────────────┐
                              │                  │          │                  │
                              │ ML Processing    │◀────────▶│ Kibana           │
                              │ Engine           │          │ Dashboard        │
                              │                  │          │                  │
                              └────────┬─────────┘          └──────────────────┘
                                       │
                                       │
                                       ▼
                              ┌──────────────────┐
                              │                  │
                              │ Response         │
                              │ Automation       │
                              │                  │
                              └──────────────────┘
```

## Prerequisites

- Docker and Docker Compose installed
- Minimum of 8GB RAM (16GB recommended for production)
- 4 CPU cores minimum
- 100GB storage space
- Linux-based operating system (Ubuntu 20.04+ recommended)
- Network access to monitored systems

## Quick Start

### Using Docker Compose

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/wazuhai.git
   cd wazuhai
   ```

2. Configure the environment variables:
   ```bash
   cp .env.example .env
   # Edit .env file with your specific configurations
   ```

3. Start the stack:
   ```bash
   docker-compose up -d
   ```

4. Access the Wazuh dashboard:
   ```
   https://localhost:5601
   ```
   Default credentials:
   - Username: admin
   - Password: admin (Change this immediately in production!)

### Manual Installation

For detailed manual installation instructions, refer to the [Installation Guide](docs/installation.md).

## Security Implementation Guide

### 1. Initial Security Setup

1. **Change Default Passwords**
   ```bash
   # Change Elasticsearch password
   curl -X POST "localhost:9200/_security/user/elastic/_password" -H "Content-Type: application/json" -d '{"password":"your_secure_password"}'
   
   # Change Wazuh API password
   docker exec -it wazuh-manager /var/ossec/bin/manage_api
   ```

2. **Generate SSL/TLS Certificates**
   ```bash
   # Create directory for certificates
   mkdir -p config/ssl
   
   # Generate CA certificate
   openssl genrsa -out config/ssl/ca.key 4096
   openssl req -new -x509 -days 365 -key config/ssl/ca.key -out config/ssl/ca.crt
   
   # Generate server certificates
   openssl genrsa -out config/ssl/server.key 2048
   openssl req -new -key config/ssl/server.key -out config/ssl/server.csr
   openssl x509 -req -days 365 -in config/ssl/server.csr -CA config/ssl/ca.crt -CAkey config/ssl/ca.key -CAcreateserial -out config/ssl/server.crt
   ```

3. **Configure Network Security**
   - Update firewall rules:
     ```bash
     # Allow only necessary ports
     ufw allow 1514/tcp  # Wazuh agent registration
     ufw allow 1515/tcp  # Wazuh agent events
     ufw allow 55000/tcp # Wazuh API
     ufw allow 5601/tcp  # Kibana
     ufw allow 9200/tcp  # Elasticsearch
     ```

### 2. Wazuh Configuration Security

1. **Update ossec.conf**
   - Enable TLS for agent communication
   - Configure secure authentication
   - Set up proper file permissions
   - Enable audit logging
   - Configure active response rules

2. **Configure File Integrity Monitoring**
   ```xml
   <syscheck>
     <frequency>43200</frequency>
     <alert_new_files>yes</alert_new_files>
     <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
   </syscheck>
   ```

3. **Set Up Rootcheck**
   ```xml
   <rootcheck>
     <frequency>43200</frequency>
     <check_unixaudit>yes</check_unixaudit>
     <check_files>yes</check_files>
     <check_trojans>yes</check_trojans>
   </rootcheck>
   ```

### 3. Elasticsearch Security

1. **Enable X-Pack Security**
   ```yaml
   xpack.security.enabled: true
   xpack.security.transport.ssl.enabled: true
   xpack.security.transport.ssl.key: /path/to/elasticsearch.key
   xpack.security.transport.ssl.certificate: /path/to/elasticsearch.crt
   xpack.security.transport.ssl.certificate_authorities: /path/to/ca.crt
   ```

2. **Configure Role-Based Access Control**
   ```bash
   # Create roles
   curl -X POST "localhost:9200/_security/role/wazuh_user" -H "Content-Type: application/json" -d '{
     "cluster": ["monitor"],
     "indices": [
       {
         "names": ["wazuh-*"],
         "privileges": ["read", "view_index_metadata"]
       }
     ]
   }'
   ```

### 4. ML Engine Security

1. **Secure API Access**
   - Implement API key authentication
   - Enable rate limiting
   - Use HTTPS for all communications
   - Implement proper input validation

2. **Model Security**
   - Encrypt model files at rest
   - Implement model versioning
   - Set up access controls for model management
   - Monitor model drift and performance

### 5. Monitoring and Auditing

1. **Enable Audit Logging**
   ```yaml
   audit.enabled: true
   audit.log_file: /var/log/audit/audit.log
   ```

2. **Set Up Security Monitoring**
   - Monitor failed login attempts
   - Track configuration changes
   - Monitor system resource usage
   - Set up alerts for security events

### 6. Regular Security Maintenance

1. **Update Schedule**
   ```bash
   # Create update script
   cat > update-security.sh << 'EOF'
   #!/bin/bash
   docker-compose pull
   docker-compose up -d
   docker system prune -f
   EOF
   
   # Make it executable
   chmod +x update-security.sh
   
   # Add to crontab
   echo "0 0 * * 0 /path/to/update-security.sh" | sudo tee -a /etc/crontab
   ```

2. **Backup Security Configurations**
   ```bash
   # Create backup script
   cat > backup-security.sh << 'EOF'
   #!/bin/bash
   BACKUP_DIR="/path/to/backups/$(date +%Y%m%d)"
   mkdir -p $BACKUP_DIR
   cp -r config/ssl $BACKUP_DIR/
   cp config/wazuh/ossec.conf $BACKUP_DIR/
   cp .env $BACKUP_DIR/
   EOF
   ```

### 7. Incident Response

1. **Create Incident Response Plan**
   - Document response procedures
   - Set up alerting thresholds
   - Define escalation paths
   - Create recovery procedures

2. **Test Security Measures**
   ```bash
   # Regular security testing
   docker-compose run --rm wazuh-manager /var/ossec/bin/wazuh-logtest -t
   ```

## Machine Learning Capabilities

### Built-in ML Features

1. **Advanced Anomaly Detection**:
   - User behavior analysis
   - Network traffic pattern analysis
   - System call anomaly detection
   - Command-line argument analysis

2. **Threat Intelligence Integration**:
   - Automated IOC enrichment
   - Reputation scoring system
   - Historical correlation analysis

3. **Predictive Analytics**:
   - Attack chain prediction
   - Vulnerability exploitation likelihood assessment
   - Risk scoring based on environmental context

## Performance Tuning

WazuhAI includes optimized configurations for different deployment sizes:

- **Small**: Up to 50 agents, 5,000 EPS
- **Medium**: Up to 500 agents, 15,000 EPS
- **Large**: Up to 1,000 agents, 25,000+ EPS
- **Enterprise**: Custom configurations for very large deployments

## Maintenance and Updates

### Updating the Stack

```bash
# Pull the latest changes
git pull

# Update the containers
docker-compose down
docker-compose pull
docker-compose up -d
```

### Backup and Restore

Automated backup procedures are included in the deployment. Refer to the [Backup and Restore Guide](docs/backup-restore.md) for detailed instructions.

## Contributing

Contributions to WazuhAI are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting pull requests.

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Wazuh Team for the amazing open-source SIEM platform
- Elastic for the powerful ELK stack
- All contributors to this project
