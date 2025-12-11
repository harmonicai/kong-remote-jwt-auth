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
  echo "Please start Kong first with the shared dict configured:"
  echo ""
  echo "  export KONG_NGINX_HTTP_LUA_SHARED_DICT=\"remote_jwt_auth 1m\""
  echo "  kms"
  echo ""
  exit 1
fi

# Create mock JWT backend service
# This uses httpbin's /base64 endpoint to return a fake JWT string
echo "Creating mock JWT backend service..."
curl -s -X POST http://localhost:8001/services \
  --data name=mock-jwt-backend \
  --data url=https://httpbin.konghq.com/base64/ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnpkV0lpT2lJeE1qTTBOVFkzT0Rrd0lpd2libUZ0WlNJNklrTmxjbUpsY25WeklFcFhWQ0lzSW1saGRDSTZNVFV4TmpJek9UQXlNbjAuU2ZsS3h3UkpTTWVLS0YyUVQ0ZndwTWVKZjM2UE9rNnlKVl9hZFFzc3c1Yw

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

# Enable the plugin with mock JWT backend
echo "Enabling remote-jwt-auth plugin..."
curl -s -X POST http://localhost:8001/services/test-service/plugins \
  --data name=remote-jwt-auth \
  --data config.authenticated_consumer=test-consumer \
  --data config.anonymous=anonymous \
  --data 'config.signing_urls[]=https://www.googleapis.com/oauth2/v1/certs' \
  --data config.cache_namespace=mock-test \
  --data config.jwt_service_url=http://localhost:8000/mock-jwt \
  --data config.jwt_service_timeout=5000

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
