#!/bin/bash

# Exit on error
set -e

echo "Starting security hardening for WazuhAI..."

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for required tools
for cmd in ufw docker docker-compose openssl; do
    if ! command_exists $cmd; then
        echo "Error: $cmd is required but not installed."
        exit 1
    fi
done

# 1. Configure firewall
echo "Configuring firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 1514/tcp  # Wazuh agent registration
ufw allow 1515/tcp  # Wazuh agent events
ufw allow 55000/tcp # Wazuh API
ufw allow 5601/tcp  # Kibana
ufw allow 9200/tcp  # Elasticsearch
ufw allow 5000/tcp  # ML Engine API
ufw allow 8000/tcp  # Prometheus metrics
ufw --force enable

# 2. Secure Docker configuration
echo "Securing Docker configuration..."
cat > /etc/docker/daemon.json << EOF
{
  "userns-remap": "default",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m",
    "max-file": "3"
  },
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 64000,
      "Soft": 64000
    }
  },
  "live-restore": true
}
EOF

# 3. Set up secure environment variables
echo "Setting up secure environment variables..."
if [ ! -f .env ]; then
    echo "Error: .env file not found. Please create it from .env.example first."
    exit 1
fi

# Generate random passwords if not set
if grep -q "your_secure_password" .env; then
    echo "Generating secure passwords..."
    ELASTIC_PASSWORD=$(openssl rand -base64 24)
    WAZUH_API_PASSWORD=$(openssl rand -base64 24)
    JWT_SECRET=$(openssl rand -base64 32)
    MODEL_ENCRYPTION_KEY=$(openssl rand -base64 32)
    ENCRYPTION_KEY=$(openssl rand -base64 32)
    
    # Update .env file with secure passwords
    sed -i "s/your_secure_elastic_password_here/$ELASTIC_PASSWORD/" .env
    sed -i "s/your_secure_api_password_here/$WAZUH_API_PASSWORD/" .env
    sed -i "s/your_jwt_secret_here/$JWT_SECRET/" .env
    sed -i "s/your_model_encryption_key_here/$MODEL_ENCRYPTION_KEY/" .env
    sed -i "s/your_encryption_key_here/$ENCRYPTION_KEY/" .env
fi

# 4. Set up secure file permissions
echo "Setting secure file permissions..."
find . -type f -name "*.key" -exec chmod 600 {} \;
find . -type f -name "*.crt" -exec chmod 644 {} \;
find . -type f -name "*.pem" -exec chmod 600 {} \;
find . -type f -name ".env" -exec chmod 600 {} \;

# 5. Configure secure logging
echo "Configuring secure logging..."
mkdir -p logs
touch logs/audit.log
chmod 640 logs/audit.log

# 6. Set up secure backup
echo "Setting up secure backup..."
mkdir -p backups
cat > scripts/backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="backups/$(date +%Y%m%d)"
mkdir -p $BACKUP_DIR
tar -czf $BACKUP_DIR/config.tar.gz config/
tar -czf $BACKUP_DIR/ssl.tar.gz config/ssl/
cp .env $BACKUP_DIR/
echo "Backup completed: $BACKUP_DIR"
EOF
chmod +x scripts/backup.sh

# 7. Set up secure update mechanism
echo "Setting up secure update mechanism..."
cat > scripts/update.sh << 'EOF'
#!/bin/bash
# Pull latest changes
git pull

# Backup before update
./scripts/backup.sh

# Update containers
docker-compose pull
docker-compose down
docker-compose up -d

# Clean up
docker system prune -f

echo "Update completed successfully."
EOF
chmod +x scripts/update.sh

# 8. Set up monitoring and alerting
echo "Setting up monitoring and alerting..."
cat > scripts/monitor.sh << 'EOF'
#!/bin/bash
# Check service health
docker-compose ps | grep -v "Up" | grep -v "NAME"

# Check disk space
df -h | grep -v "tmpfs" | awk '{if ($5 > 90) print $0}'

# Check memory usage
free -m | awk 'NR==2{printf "Memory Usage: %s/%sMB (%.2f%%)\n", $3,$2,$3*100/$2 }'

# Check for failed login attempts
grep "Failed password" /var/log/auth.log | tail -n 10
EOF
chmod +x scripts/monitor.sh

# 9. Set up cron jobs for maintenance
echo "Setting up maintenance cron jobs..."
(crontab -l 2>/dev/null || true; echo "0 0 * * 0 /path/to/scripts/backup.sh") | crontab -
(crontab -l 2>/dev/null || true; echo "0 2 * * 0 /path/to/scripts/update.sh") | crontab -
(crontab -l 2>/dev/null || true; echo "*/15 * * * * /path/to/scripts/monitor.sh") | crontab -

# 10. Set up incident response plan
echo "Setting up incident response plan..."
mkdir -p docs
cat > docs/incident_response.md << 'EOF'
# WazuhAI Incident Response Plan

## 1. Detection
- Monitor alerts from Wazuh
- Check ML engine anomaly detection
- Review system logs

## 2. Initial Assessment
- Determine severity level
- Identify affected systems
- Document initial findings

## 3. Containment
- Isolate affected systems
- Block malicious IPs
- Disable compromised accounts

## 4. Eradication
- Remove malware
- Patch vulnerabilities
- Reset compromised credentials

## 5. Recovery
- Restore from backups if necessary
- Verify system integrity
- Resume normal operations

## 6. Lessons Learned
- Document incident
- Update security measures
- Improve detection capabilities
EOF

echo "Security hardening completed successfully."
echo "Please review the following files:"
echo "- .env (secure passwords)"
echo "- config/ssl/ (certificates)"
echo "- scripts/backup.sh (backup script)"
echo "- scripts/update.sh (update script)"
echo "- scripts/monitor.sh (monitoring script)"
echo "- docs/incident_response.md (incident response plan)"
echo ""
echo "Next steps:"
echo "1. Review and customize the security configurations"
echo "2. Test the backup and restore procedures"
echo "3. Conduct a security audit"
echo "4. Train team members on incident response procedures" 