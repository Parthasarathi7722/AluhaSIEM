#!/bin/bash

# Exit on error
set -e

# Create directories
mkdir -p config/ssl
cd config/ssl

# Generate CA private key and certificate
echo "Generating CA private key and certificate..."
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=WazuhAI CA/O=WazuhAI/C=US"

# Function to generate certificates for a service
generate_cert() {
    local service=$1
    local common_name=$2
    
    echo "Generating certificates for $service..."
    
    # Generate private key
    openssl genrsa -out ${service}.key 2048
    
    # Generate CSR
    openssl req -new -key ${service}.key -out ${service}.csr -subj "/CN=${common_name}/O=WazuhAI/C=US"
    
    # Create config file for SAN
    cat > ${service}.cnf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = ${common_name}
O = WazuhAI
C = US

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${common_name}
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF
    
    # Generate certificate with SAN
    openssl x509 -req -days 365 -in ${service}.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
        -out ${service}.crt -extensions v3_req -extfile ${service}.cnf
    
    # Clean up
    rm ${service}.csr ${service}.cnf
    
    echo "Certificates for $service generated successfully."
}

# Generate certificates for each service
generate_cert "elasticsearch" "elasticsearch"
generate_cert "kibana" "kibana"
generate_cert "wazuh" "wazuh-manager"
generate_cert "ml-engine" "ml-engine"

# Set proper permissions
chmod 600 *.key
chmod 644 *.crt

echo "All certificates generated successfully."
echo "CA certificate: config/ssl/ca.crt"
echo "CA private key: config/ssl/ca.key"
echo "Service certificates and keys are in config/ssl/" 