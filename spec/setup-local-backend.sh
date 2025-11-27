#!/bin/bash
# Setup script for testing with local backend services (midtier/graphql)
# Uses host.docker.internal to reach services running on your Mac host.
#
# Prerequisites:
#   1. Start your local backend services (docker-compose up in backend repo)
#   2. Start pongo shell:
#      pongo shell
#   3. Start Kong with the shared dict configured:
#      export KONG_NGINX_HTTP_LUA_SHARED_DICT="remote_jwt_auth 1m"
#      kms
#   4. Run this script:
#      bash /kong-plugin/spec/setup-local-backend.sh
#
# This configures Kong similar to local_kong.yaml in the backend repo.

set -e

echo "Setting up Kong for local backend testing..."

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

# Check if midtier is reachable
echo "Checking connectivity to midtier (host.docker.internal:9000)..."
MIDTIER_RESPONSE=$(curl -s --connect-timeout 2 http://host.docker.internal:9000/ 2>&1)
MIDTIER_EXIT=$?
if [ $MIDTIER_EXIT -ne 0 ]; then
  echo "Warning: Cannot connect to midtier (host.docker.internal:9000)"
  echo "Make sure your backend services are running, e.g.:"
  echo "GRPC_DNS_RESOLVER=native ENV_NAME=DEV docker compose -f docker-compose.yml -f docker-compose.debug.yml --env-file settings/docker/dev.env up"
  echo ""
  read -p "Continue anyway? [y/N] " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
  fi
else
  echo "  Response: $MIDTIER_RESPONSE"
  echo "  (This is expected - midtier requires authentication headers)"
fi

echo "Checking connectivity to graphql (host.docker.internal:4000)..."
GRAPHQL_RESPONSE=$(curl -s --connect-timeout 2 http://host.docker.internal:4000/ 2>&1)
GRAPHQL_EXIT=$?
if [ $GRAPHQL_EXIT -ne 0 ]; then
  echo "Warning: Cannot connect to graphql (host.docker.internal:4000)"
  echo "Make sure your backend services are running, e.g.:"
  echo "GRPC_DNS_RESOLVER=native ENV_NAME=DEV docker compose -f docker-compose.yml -f docker-compose.debug.yml --env-file settings/docker/dev.env up"
  echo ""
  read -p "Continue anyway? [y/N] " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
  fi
else
  echo "  Response: ${GRAPHQL_RESPONSE:0:100}..."
  echo "  (Connection successful)"
fi
echo ""

# Create consumers (matching local_kong.yaml)
echo "Creating consumers..."
curl -s -X POST http://localhost:8001/consumers \
  --data username=console-firebase

curl -s -X POST http://localhost:8001/consumers \
  --data username=anonymous
echo

# Add request-termination plugin to anonymous consumer
echo "Adding request-termination to anonymous consumer..."
curl -s -X POST http://localhost:8001/consumers/anonymous/plugins \
  --data name=request-termination \
  --data config.status_code=401 \
  --data 'config.content_type=application/json; charset=utf-8' \
  --data 'config.body={"error": "Authentication error. Include either valid api-key or JWT in your request."}'
echo

# Create midtier service
echo "Creating midtier service..."
curl -s -X POST http://localhost:8001/services \
  --data name=midtier \
  --data url=http://host.docker.internal:9000
echo

# Create midtier route (catch-all)
curl -s -X POST http://localhost:8001/services/midtier/routes \
  --data name=midtier \
  --data 'paths[]=/'
echo

# Enable remote-jwt-auth on midtier
echo "Enabling remote-jwt-auth plugin on midtier..."
curl -s -X POST http://localhost:8001/services/midtier/plugins \
  -H "Content-Type: application/json" \
  -d '{
    "name": "remote-jwt-auth",
    "config": {
      "anonymous": "anonymous",
      "authenticated_consumer": "console-firebase",
      "signing_urls": ["https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"],
      "claims_to_verify": [
        {"name": "iss", "allowed_values": ["https://securetoken.google.com/innate-empire-283902"]},
        {"name": "aud", "allowed_values": ["innate-empire-283902"]}
      ],
      "jwt_service_url": "http://host.docker.internal:9000/auth/auth_jwt",
      "jwt_service_timeout": 5000
    }
  }'
echo

# Create graphql service
echo "Creating graphql service..."
curl -s -X POST http://localhost:8001/services \
  --data name=graphql \
  --data url=http://host.docker.internal:4000
echo

# Create graphql route
curl -s -X POST http://localhost:8001/services/graphql/routes \
  --data name=graphql \
  --data 'paths[]=/graphql'
echo

# Enable remote-jwt-auth on graphql
echo "Enabling remote-jwt-auth plugin on graphql..."
curl -s -X POST http://localhost:8001/services/graphql/plugins \
  -H "Content-Type: application/json" \
  -d '{
    "name": "remote-jwt-auth",
    "config": {
      "anonymous": "anonymous",
      "authenticated_consumer": "console-firebase",
      "signing_urls": ["https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"],
      "claims_to_verify": [
        {"name": "iss", "allowed_values": ["https://securetoken.google.com/innate-empire-283902"]},
        {"name": "aud", "allowed_values": ["innate-empire-283902"]}
      ],
      "jwt_service_url": "http://host.docker.internal:9000/auth/auth_jwt",
      "jwt_service_timeout": 5000
    }
  }'

echo ""
echo "Setup complete!"
echo ""
echo "Kong is now configured similar to local_kong.yaml with:"
echo "  - midtier service at / -> http://host.docker.internal:9000"
echo "  - graphql service at /graphql -> http://host.docker.internal:4000"
echo "  - remote-jwt-auth plugin with jwt_service_url configured"
echo ""
echo "Test commands:"
echo "  # Test midtier (requires valid Firebase JWT)"
echo "  curl -i http://localhost:8000/companies?ids=1354167&extended=true -H 'Authorization: Bearer <firebase-jwt>'"
echo ""
echo "  # Test graphql (requires valid Firebase JWT)"
echo "  curl -i http://localhost:8000/graphql -H 'Authorization: Bearer <firebase-jwt>'"
echo ""
echo "  # Request without auth (returns 401)"
echo "  curl -i http://localhost:8000/"
echo ""
echo "  # View Kong logs"
echo "  tail -f /kong-plugin/servroot/logs/error.log"
echo ""
echo "  # Check plugin config"
echo "  curl -s http://localhost:8001/plugins | jq"
