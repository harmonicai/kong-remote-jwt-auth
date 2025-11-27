# Testing Guide

This document describes how to test the Kong Remote JWT Auth Plugin.

## Test Structure

```
spec/
├── unit/                              # Unit tests (no Kong dependencies)
│   └── simple-backend-jwt-test.lua    # Standalone tests (runs with luajit only)
├── integration/                       # Integration tests (requires Kong/Pongo)
│   ├── 01-plugin-integration_spec.lua # Full plugin integration tests
│   └── 02-schema_spec.lua             # Schema validation tests
├── setup-manual-test.sh               # Basic manual testing (no backend)
├── setup-mock-test.sh                 # Testing with mock JWT backend
└── setup-local-backend.sh             # Testing with local midtier/graphql
```

---

## Testing with Pongo (Recommended)

[Kong Pongo](https://github.com/Kong/kong-pongo) is the recommended way to run integration tests for Kong plugins. It uses Docker to create isolated Kong test environments.

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

# Run with verbose output for Busted (arguments after the -- separator)
pongo run -- --verbose

# Run specific test with verbose output in gtest format
pongo run -- -v -o gtest ./spec/integration/01-plugin-integration_spec.lua 

# Only run tests tagged with postgres
pongo run -- --tags=postgres

# Run against a specific Kong version
KONG_VERSION=3.0.x pongo run

# Run against multiple Kong versions
KONG_VERSION=3.0.x pongo run && KONG_VERSION=3.9.x pongo run
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

Pongo shell provides a full Kong environment for manual testing (e.g. with sample requests). There are three setup scripts available.

**Important:** The plugin requires a shared dictionary to be configured. You must set this environment variable **before** starting Kong:

```bash
export KONG_NGINX_HTTP_LUA_SHARED_DICT="remote_jwt_auth 1m"
kms
```

### Option 1: Basic Testing (No Backend)

For testing JWT validation without a backend JWT service:

```bash
KONG_VERSION=3.0.x pongo shell
export KONG_NGINX_HTTP_LUA_SHARED_DICT="remote_jwt_auth 1m"
kms
bash /kong-plugin/spec/setup-manual-test.sh

# Test requests
curl -i 'http://localhost:8000/test' -H 'Authorization: Bearer test-token'
```

### Option 2: Mock JWT Backend

For testing the full flow with a mock JWT backend that returns a static JWT:

```bash
KONG_VERSION=3.0.x pongo shell
export KONG_NGINX_HTTP_LUA_SHARED_DICT="remote_jwt_auth 1m"
kms
bash /kong-plugin/spec/setup-mock-test.sh

# Test the mock backend directly
curl -i 'http://localhost:8000/mock-jwt'

# Test through the plugin
curl -i 'http://localhost:8000/test' -H 'Authorization: Bearer <valid-firebase-jwt>'
```

### Option 3: Local Backend Services (midtier/graphql)

For testing with your local backend Docker Compose services (uses `host.docker.internal`):

1. Update the backend `settings/definitions.py` for the env name you want to test against (e.g. DEV)
   to point to your kong-pongo instance (get correct IP from Docker), e.g.
```
DEV_CONFIG = BaseConfig(
   ENV_NAME="DEV",
...
   KONG_API_URL="http://192.168.107.3:8001"
```

```bash
# 2. Start your backend services (in the backend repo)
cd ~/workspace/backend
GRPC_DNS_RESOLVER=native ENV_NAME=DEV docker compose -f docker-compose.yml -f docker-compose.debug.yml --env-file settings/docker/dev.env up

# 2. Start pongo shell (NOTE: You should specify the kong version you are trying to test against)
KONG_VERSION=3.0.x pongo shell

# 3. Start Kong with the shared dict configured (inside the shell)
export KONG_NGINX_HTTP_LUA_SHARED_DICT="remote_jwt_auth 1m"
kms

# 4. Setup Kong to route to your local Docker midtier/graphql
bash /kong-plugin/spec/setup-local-backend.sh

# Or specify custom ports if your services use different ports:
# bash /kong-plugin/spec/setup-local-backend.sh --midtier-port 8080 --graphql-port 4000

# 5. Test requests (Authorization header requires valid Firebase JWT)
curl -i 'http://localhost:8000/companies?ids=1354167&extended=true' -H 'apikey: localkey'
curl -i 'http://localhost:8000/companies?ids=1354167&extended=true' -H 'Authorization: Bearer <firebase-jwt>'
curl -i -X POST 'http://localhost:8000/graphql' -H 'Authorization: Bearer <firebase-jwt>' -H 'Content-Type: application/json' -d '{"query": "{ __typename }"}'
```

Notes:

- The easiest way to verify backend behaviour with the Cerberus JWT is to add debug breakpoints in the backend `services/midtier/middlewares/header_middleware.py` file (`_get_authenticated_request_state` method)
- If you see permissions errors, the API key may need to be added to the backend container PG `api_key_permissions` table (need to find the API key ID from kong)
- Alternatively, force "ALL" permissions for API keys in the backend `services/midtier/services/kong/kong_service.py` `__decorate_api_keys` function:
```py
    @trace_fn
    def __decorate_api_keys(self, kong_api_keys: list[KongApiKey]) -> list[KongApiKey]:
        # TEMPORARY API KEY DECORATION TO ALLOW LOCAL KONG TESTING
        #
        # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        # !!! DO NOT COMMIT - GRANT ALL PERMISSIONS TO ALL ENDPOINTS !!!
        # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        return [
            key.copy(
                update={
                    "permissions": [Endpoint.ALL],
                    "request_source": RequestSource.CONSUMER_API,
                }
            )
            for key in kong_api_keys
        ]
```

### Common Commands

```bash
# View Kong logs
tail -f /kong-plugin/servroot/logs/error.log

# Check plugin config
curl -s http://localhost:8001/plugins | jq

# Check services
curl -s http://localhost:8001/services | jq
```

---

## CI/CD Integration

### GitHub Actions with Pongo

Unit and pongo integration tests are automatically run as part of the `.github/workflows/test.yml` Github action.