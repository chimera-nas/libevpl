#!/bin/bash

# SPDX-FileCopyrightText: 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

# Generate self-signed certificates for TLS testing

CERT_DIR="$1"
if [ -z "$CERT_DIR" ]; then
    echo "Usage: $0 <certificate_directory>"
    exit 1
fi

mkdir -p "$CERT_DIR"

# Generate private key
openssl genrsa -out "$CERT_DIR/key.pem" 2048

# Generate self-signed certificate
openssl req -new -x509 -key "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" -days 365 \
    -subj "/C=US/ST=Test/L=Test/O=Test/OU=Test/CN=localhost"

# Generate CA certificate (same as server cert for testing)
cp "$CERT_DIR/cert.pem" "$CERT_DIR/ca.pem"

echo "Generated test certificates in $CERT_DIR"