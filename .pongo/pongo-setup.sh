#!/bin/bash

# This script runs inside the Kong container before tests start
# Use it to set up any test dependencies or configuration

echo "Setting up kong-remote-jwt-auth plugin test environment..."

# Ensure the 'remote_jwt_auth' shared dict is configured for caching
export KONG_NGINX_HTTP_LUA_SHARED_DICT="remote_jwt_auth 1m"

echo "Plugin test environment ready."
