#!/bin/bash
# Setup script for manual testing in Pongo shell
# Usage: Run inside pongo shell: bash /kong-plugin/spec/setup-manual-test.sh [options]
#
# Options:
#   --jwt-service-url <url>   URL for the backend JWT service (optional)
#
# Example:
#   bash /kong-plugin/spec/setup-manual-test.sh
#   bash /kong-plugin/spec/setup-manual-test.sh --jwt-service-url http://midtier:80/auth/auth_jwt

set -e

JWT_SERVICE_URL=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --jwt-service-url)
      JWT_SERVICE_URL="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      echo "Usage: $0 [--jwt-service-url <url>]"
      exit 1
      ;;
  esac
done

echo "Setting up Kong for manual testing..."

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

# Create test service
# Uses httpbin.konghq.com, as referenced in the Kong documentation for plugin testing:
# https://developer.konghq.com/custom-plugins/get-started/add-plugin-testing/
echo "Creating service..."
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

# Enable the plugin
echo "Enabling remote-jwt-auth plugin..."
PLUGIN_DATA="name=remote-jwt-auth"
PLUGIN_DATA+="&config.authenticated_consumer=test-consumer"
PLUGIN_DATA+="&config.anonymous=anonymous"
PLUGIN_DATA+="&config.signing_urls[]=https://www.googleapis.com/oauth2/v1/certs"
PLUGIN_DATA+="&config.cache_namespace=manual-test"

if [ -n "$JWT_SERVICE_URL" ]; then
  echo "  jwt_service_url: $JWT_SERVICE_URL"
  PLUGIN_DATA+="&config.jwt_service_url=$JWT_SERVICE_URL"
fi

curl -s -X POST http://localhost:8001/services/test-service/plugins \
  --data "$PLUGIN_DATA"

echo ""
echo "Setup complete!"
echo ""
echo "Test commands:"
echo "  # Request with invalid JWT (falls back to anonymous)"
echo "  curl -i http://localhost:8000/test -H 'Authorization: Bearer invalid-token'"
echo ""
echo "  # Request without auth (falls back to anonymous)"
echo "  curl -i http://localhost:8000/test"
echo ""
echo "  # View Kong logs"
echo "  tail -f /kong-plugin/servroot/logs/error.log"
echo "  tail -50 /kong-plugin/servroot/logs/error.log"
echo ""
echo "  # Check plugin config"
echo "  curl -s http://localhost:8001/plugins | jq"
