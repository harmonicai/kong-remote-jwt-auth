#!/bin/bash
# Setup script for manual testing with a mock JWT backend service
# Usage: Run inside pongo shell: bash /kong-plugin/spec/setup-mock-test.sh
#
# This script sets up:
# - A mock JWT backend service (using httpbin to echo back a fake JWT)
# - A test service that uses the remote-jwt-auth plugin
#
# Example:
#   pongo shell
#   kms
#   bash /kong-plugin/spec/setup-mock-test.sh

set -e

echo "Setting up Kong for manual testing with mock JWT backend..."

# Check if Kong is running
if ! curl -s http://localhost:8001/ > /dev/null 2>&1; then
  echo "Error: Kong is not running."
  echo "Please start Kong first:"
  echo ""
  echo "  kms"
  echo ""
  exit 1
fi

# Create mock JWT backend service
# This uses httpbin's /base64 endpoint to return a fake JWT string
echo "Creating mock JWT backend service..."
curl -s -X POST http://localhost:8001/services \
  -H "Content-Type: application/json" \
  -d '{
    "name": "mock-jwt-backend",
    "url": "https://httpbin.konghq.com/base64/SldUIHRlc3QgcmVzcG9uc2U="
  }'

curl -s -X POST http://localhost:8001/services/mock-jwt-backend/routes \
  --data name=mock-jwt-route \
  --data 'paths[]=/mock-jwt'

# Create test service (upstream)
echo "Creating test service..."
curl -s -X POST http://localhost:8001/services \
  --data name=test-service \
  --data url=https://httpbin.konghq.com/anything \
  --data connect_timeout=5000 \
  --data read_timeout=5000

# Create route
echo "Creating route..."
curl -s -X POST http://localhost:8001/services/test-service/routes \
  --data name=test-route \
  --data 'paths[]=/test'

# Create consumers
echo "Creating consumers..."
curl -s -X POST http://localhost:8001/consumers \
  --data username=test-consumer

curl -s -X POST http://localhost:8001/consumers \
  --data username=anonymous

# Enable the plugin with Firebase signing certificates and mock JWT backend
echo "Enabling remote-jwt-auth plugin..."
curl -s -X POST http://localhost:8001/services/test-service/plugins \
  -H "Content-Type: application/json" \
  -d '{
    "name": "remote-jwt-auth",
    "config": {
      "authenticated_consumer": "test-consumer",
      "anonymous": "anonymous",
      "signing_urls": ["https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"],
      "claims_to_verify": [
        {"name": "iss", "allowed_values": ["https://securetoken.google.com/innate-empire-283902"]},
        {"name": "aud", "allowed_values": ["innate-empire-283902"]}
      ],
      "jwt_service_url": "http://localhost:8000/mock-jwt",
      "jwt_service_timeout": 5000
    }
  }'

echo ""
echo "Setup complete!"
echo ""
echo "The mock JWT backend returns a static JWT token."
echo "When a valid Firebase JWT is provided, the plugin will:"
echo "  1. Validate the Firebase JWT"
echo "  2. Call the mock backend at /mock-jwt"
echo "  3. Set x-harmonic-cerberus-jwt header with the mock JWT"
echo ""
echo "Test commands:"
echo "  # Request with invalid JWT (falls back to anonymous)"
echo "  curl -i http://localhost:8000/test -H 'Authorization: Bearer invalid-token'"
echo ""
echo "  # Request without auth (falls back to anonymous)"
echo "  curl -i http://localhost:8000/test"
echo ""
echo "  # Test the mock JWT backend directly"
echo "  curl -i http://localhost:8000/mock-jwt"
echo ""
echo "  # View Kong logs"
echo "  tail -f /kong-plugin/servroot/logs/error.log"
echo "  tail -50 /kong-plugin/servroot/logs/error.log"
echo ""
echo "  # Check plugin config"
echo "  curl -s http://localhost:8001/plugins | jq"
