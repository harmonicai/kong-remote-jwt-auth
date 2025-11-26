#!/bin/bash

# This script runs inside the Kong container before tests start
# Use it to set up any test dependencies or configuration

echo "Setting up kong-remote-jwt-auth plugin test environment..."

# Ensure the shared dict is configured (usually done via kong.conf)
# The plugin requires a shared dict named 'remote_jwt_auth'

echo "Plugin test environment ready."
