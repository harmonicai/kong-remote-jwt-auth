# Testing Guide

This document describes how to test the Kong Remote JWT Auth Plugin.

## Test Structure

```
spec/
├── unit/                              # Unit tests (no Kong dependencies)
│   └── simple-backend-jwt-test.lua    # Standalone tests (runs with luajit only)
├── integration/                       # Integration tests (requires Kong/Pongo)
│   ├── 02-plugin-integration_spec.lua # Full plugin integration tests
│   └── 03-schema_spec.lua             # Schema validation tests
└── setup-manual-test.sh               # Setup script for manual testing in Pongo shell
```

---

## Testing with Pongo (Recommended)

[Kong Pongo](https://github.com/Kong/kong-pongo) is the recommended way to run integration tests. It uses Docker to create isolated Kong test environments.

### Install Pongo

```bash
# Clone pongo repository
git clone https://github.com/Kong/kong-pongo.git

# Add pongo to your PATH
mkdir -p ~/.local/bin
ln -s $(realpath kong-pongo/pongo.sh) ~/.local/bin/pongo

# Add to your shell profile (~/.bashrc, ~/.zshrc, etc.)
export PATH="$PATH:~/.local/bin"
```

### Requirements

- Docker and docker-compose
- curl
- realpath (install via `brew install coreutils` on macOS)

### Run Integration Tests with Pongo

```bash
# Navigate to the plugin directory
cd kong-remote-jwt-auth

# Run all tests against default Kong version
pongo run

# Run with verbose output
pongo run -- --verbose

# Run specific test file
pongo run ./spec/integration/02-plugin-integration_spec.lua

# Run against a specific Kong version
KONG_VERSION=3.4.x pongo run

# Run against multiple Kong versions
KONG_VERSION=3.3.x pongo run && KONG_VERSION=3.4.x pongo run
```

### Pongo Commands Reference

```bash
# Build the Kong test image
pongo build

# Start Kong shell (for debugging)
pongo shell

# View Kong error logs
pongo tail

# Stop and clean up containers
pongo down

# Run with only PostgreSQL (default)
pongo run --no-cassandra

# Run with coverage report
pongo run -- --coverage
```

### Pongo Configuration

The `.pongo/pongorc` file contains default options:

```
--no-cassandra
--no-redis
--no-grpcbin
--no-squid
```

These disable unnecessary services to speed up test startup.

---

## Quick Local Tests (No Docker Required)

### Standalone Unit Tests

Requires LuaJIT:

```bash
# macOS
brew install luajit
```

Run the tests:

```bash
# Run standalone tests
luajit spec/unit/simple-backend-jwt-test.lua
```

Expected output:
```
🚀 Running Cerberus JWT Fetching Tests
======================================

🧪 Returns nil when jwt_service_url is not configured
✅ PASS: Returns nil when jwt_service_url is not configured

🧪 Skips anonymous users
✅ PASS: Skips anonymous users
...
📊 Test Results
===============
✅ Passed: 25
❌ Failed: 0
📈 Total:  25

🎉 All tests passed!
```

---

## Test Scenarios Covered

### Unit Tests - Cerberus JWT Fetching

- ✅ Returns nil when `jwt_service_url` not configured
- ✅ Skips anonymous users
- ✅ Skips when no consumer is present
- ✅ Returns cached JWT when available
- ✅ Fetches JWT from backend service successfully
- ✅ Passes original headers to backend
- ✅ Handles HTTP connection failures
- ✅ Handles non-200 HTTP status codes
- ✅ Handles empty response body
- ✅ Uses per-user cache keys
- ✅ Uses default timeout when not specified

### Integration Tests

- ✅ Plugin loads and is accessible via admin API
- ✅ Returns 401 when no authorization header is provided (without anonymous)
- ✅ Returns 401 for invalid JWT format (without anonymous)
- ✅ Allows request with anonymous consumer when auth fails
- ✅ Allows request through when no auth header provided (with anonymous)
- ✅ Accepts JWT from Authorization header
- ✅ Accepts JWT from Proxy-Authorization header
- ✅ Accepts JWT from query parameter
- ✅ Backward compatibility without jwt_service_url

Note: Integration tests use Kong's `http_mock` helper to create mock upstream servers.

### Schema Validation Tests

- ✅ Validates minimal configuration
- ✅ Validates all original fields
- ✅ Validates new JWT service fields (jwt_service_url, jwt_service_timeout)
- ✅ Validates complete configuration with all fields
- ✅ Accepts optional jwt_service_url (nil)
- ✅ Rejects missing required fields (authenticated_consumer)
- ✅ Rejects invalid field types
- ✅ Validates claims_to_verify structure
- ✅ Has correct default values for all fields

---

## Manual Testing (via Pongo shell)

Pongo shell provides a full Kong environment for manual testing:

```bash
# Start Pongo shell
pongo shell

# Start Kong with migrations (inside the shell)
kms

# Run the setup script (inside the shell)
# Without jwt_service_url:
bash /kong-plugin/spec/setup-manual-test.sh

# Or with jwt_service_url (assuming you have midtier running locally):
bash /kong-plugin/spec/setup-manual-test.sh --jwt-service-url http://midtier:80/auth/auth_jwt

# Test a request (will fall back to anonymous with invalid JWT)
curl -i http://localhost:8000/test -H "Authorization: Bearer test-token"

# View Kong logs
tail -f /usr/local/kong/logs/error.log

# Check plugin config
curl -s http://localhost:8001/plugins | jq
```

---

## CI/CD Integration

### GitHub Actions with Pongo

```yaml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install Pongo
        run: |
          git clone https://github.com/Kong/kong-pongo.git
          mkdir -p ~/.local/bin
          ln -s $(realpath kong-pongo/pongo.sh) ~/.local/bin/pongo
          echo "$HOME/.local/bin" >> $GITHUB_PATH

      - name: Run tests
        run: pongo run -- --verbose
```

### Local CI Script

```bash
#!/bin/bash
set -e

# Run unit tests
luajit spec/unit/simple-backend-jwt-test.lua

# Run integration tests with Pongo (if available)
if command -v pongo &> /dev/null; then
    pongo run -- --verbose
fi
```

---

## Troubleshooting

### Common Issues

1. **"pongo: command not found"**
   ```bash
   export PATH="$PATH:~/.local/bin"
   ```

2. **"Docker not running"**
   ```bash
   # Start Docker Desktop or
   sudo systemctl start docker
   ```

3. **Pongo build fails**
   ```bash
   # Clean up and rebuild
   pongo down
   pongo build --force
   ```

### Debugging Tests

```bash
# View Kong logs during test
pongo tail

# Get a shell in the Kong container
pongo shell

# Run specific test with verbose output
pongo run ./spec/integration/02-plugin-integration_spec.lua -- -v -o gtest
```

---

## Test Coverage

The tests cover:

1. **Functionality**: Firebase JWT validation, Cerberus JWT fetching
2. **Error Handling**: Network failures, HTTP errors, malformed responses
3. **Caching**: Per-user JWT caching with TTL
4. **Security**: Anonymous user skipping, per-user cache isolation
5. **Compatibility**: Backward compatibility with existing configurations
6. **Schema**: Validation of configuration fields
