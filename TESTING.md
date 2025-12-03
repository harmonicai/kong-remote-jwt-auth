# Testing Guide

This document describes how to test the Kong Remote JWT Auth Plugin.

## Test Structure

```
spec/
├── unit/                              # Unit tests
│   ├── simple-backend-jwt-test.lua    # Cerberus JWT fetching tests (runs with luajit, duplicated logic)
│   ├── cerberus-test.lua              # Cerberus JWT tests using real module (requires pongo)
│   └── jwt-validation-test.lua        # JWT signature/claims validation tests (requires pongo)
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

### Standalone Unit Tests (Cerberus JWT Fetching)

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

### JWT Token Validation Tests (Requires Pongo)

These tests generate real RSA keys, create X.509 certificates, and sign JWT tokens to test the actual cryptographic validation:

```bash
pongo run spec/unit/jwt-validation-test.lua
```

Expected output:
```
JWT Token Validation Tests
==========================

Generating test RSA key pair and certificate...
  Key and certificate generated successfully

Signature Validation Tests
--------------------------
  validates correctly signed JWT token
   PASS
  rejects JWT signed with wrong key
   PASS
...
Test Results
============
Passed: 45
Failed: 0
Total:  45

All tests passed!
```

### Cerberus JWT Tests (Requires Pongo)

These tests import the real `cerberus.lua` module and test JWT fetching, caching, and retry logic:

```bash
pongo run spec/unit/cerberus-test.lua
```

Expected output:
```
Cerberus JWT Fetching Tests
===========================

Basic Functionality Tests
-------------------------
  clears cerberus header when jwt_service_url is not configured
   PASS
  skips anonymous users
   PASS
...
Test Results
============
Passed: 39
Failed: 0
Total:  39

All tests passed!
```

---

## Test Scenarios Covered

### Unit Tests - Cerberus JWT Fetching (using real module)

**Basic Functionality:**
- ✅ Clears cerberus header when `jwt_service_url` not configured
- ✅ Skips anonymous users
- ✅ Skips when no consumer is present
- ✅ Fetches JWT from backend and sets header
- ✅ Passes original request headers to backend
- ✅ Uses configured timeout
- ✅ Uses default timeout when not specified

**Caching:**
- ✅ Caches JWT after successful fetch
- ✅ Uses per-user cache keys

**Error Handling:**
- ✅ Handles HTTP connection failure gracefully
- ✅ Handles non-200 HTTP status
- ✅ Handles 500 error with retry
- ✅ Handles empty response body
- ✅ Handles nil response body

**Retry Logic:**
- ✅ Retries on connection failure then succeeds
- ✅ Does not retry on 4xx errors
- ✅ Uses configured retry count
- ✅ Uses default retry count when not specified

**Request Configuration:**
- ✅ Uses GET method for backend request
- ✅ Uses configured jwt_service_url

### Unit Tests - JWT Token Validation (with real cryptography)

**Signature Validation:**
- ✅ Validates correctly signed JWT token
- ✅ Rejects JWT signed with wrong key
- ✅ Rejects JWT with unknown kid
- ✅ Rejects JWT with missing kid header
- ✅ Rejects tampered JWT payload

**Claims Verification:**
- ✅ Validates JWT with required claim present and allowed
- ✅ Rejects JWT with disallowed claim value
- ✅ Rejects JWT missing required claim
- ✅ Validates JWT with multiple claim requirements
- ✅ Rejects JWT when one of multiple claims is invalid

**User Header Extraction:**
- ✅ Sets X-Token-User-Id header from sub claim
- ✅ Sets X-Token-User-Email header from email claim
- ✅ Does not set email header when email claim is missing

**Malformed Token Handling:**
- ✅ Rejects nil token
- ✅ Rejects empty string token
- ✅ Rejects completely invalid token format
- ✅ Rejects token with only two parts
- ✅ Rejects token with invalid base64 encoding

**Certificate Fetching:**
- ✅ Caches certificates after first fetch
- ✅ Handles certificate fetch failure gracefully
- ✅ Supports multiple signing URLs with fallback
- ✅ Handles multiple key IDs from same endpoint

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

**Note:** The plugin requires a shared dictionary named `remote_jwt_auth`. This is automatically configured via `.pongo/pongo-setup.sh`, so you can simply run `kms` to start Kong.

### Option 1: Basic Testing (No Backend)

For testing JWT validation without a backend JWT service:

```bash
KONG_VERSION=3.0.x pongo shell
kms
bash /kong-plugin/spec/setup-manual-test.sh

# Test requests
curl -i 'http://localhost:8000/test' -H 'Authorization: Bearer test-token'
```

### Option 2: Mock JWT Backend

For testing the full flow with a mock JWT backend that returns a static JWT:

```bash
KONG_VERSION=3.0.x pongo shell
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

# 3. Start Kong (inside the shell)
kms

# 4. Setup Kong to route to your local Docker midtier/graphql
bash /kong-plugin/spec/setup-local-backend.sh

# Or specify custom ports if your services use different ports:
# bash /kong-plugin/spec/setup-local-backend.sh --midtier-port 8080 --graphql-port 4000

# 5. Test requests (Authorization header requires valid Firebase JWT - for DEV, can fetch from Chrome network inspector in staging)
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