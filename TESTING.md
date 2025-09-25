# Testing Guide

This document describes how to test the Kong Remote JWT Auth Plugin with the new backend JWT fetching functionality.

## Test Structure

```
spec/
├── unit/                          # Unit tests (no Kong dependencies)
│   ├── 01-backend-jwt-fetch_spec.lua     # Tests for backend JWT fetching (requires Kong helpers)
│   ├── 03-schema_spec.lua               # Schema validation tests (requires Kong helpers)
│   └── simple-backend-jwt-test.lua      # Standalone unit tests (no dependencies)
├── integration/                   # Integration tests (requires Kong)
│   └── 02-plugin-integration_spec.lua # Full plugin integration
├── fixtures/                     # Test utilities
│   └── mock-jwt-backend.lua       # Mock backend JWT service
└── run-tests.sh                   # Test runner script
```

## Quick Start - Run Tests Now

### Minimal Setup (Standalone Tests)
```bash
# Install basic dependencies
brew install lua luarocks
luarocks install lua-cjson

# Run standalone unit tests (no Kong required)
lua spec/unit/simple-backend-jwt-test.lua
```

### Full Setup (All Tests)
```bash
# Install LuaRocks if not already installed
brew install luarocks

# Install testing framework
luarocks install busted
luarocks install lua-cjson

# For full integration tests, install Kong development dependencies
luarocks install kong --only-deps
```

### Optional: Kong Development Setup

For full integration testing, you'll need Kong installed and configured for testing.

## Running Tests

### ⚡ Quick Test (Recommended)

**No Kong installation required!**

```bash
# Run standalone unit tests - tests all backend JWT functionality
lua spec/unit/simple-backend-jwt-test.lua
```

Expected output:
```
🚀 Running Backend JWT Fetching Tests
✅ PASS: Returns nil when jwt_service_url is not configured
✅ PASS: Returns cached JWT when available
...
🎉 All tests passed! (18 assertions)
```

### Full Test Suite (Requires Kong)

```bash
# Run all tests with test runner
./spec/run-tests.sh
```

### Run Specific Test Suites (Requires Busted + Kong)

```bash
# Kong-dependent unit tests (requires Kong helpers)
busted spec/unit/01-backend-jwt-fetch_spec.lua --verbose
busted spec/unit/03-schema_spec.lua --verbose

# Integration tests (requires full Kong setup)
busted spec/integration/ --verbose
```

## Manual Testing

### 1. Start Mock Backend Server

```bash
# Start on default port 9999
lua spec/fixtures/mock-jwt-backend.lua

# Or specify custom port
lua spec/fixtures/mock-jwt-backend.lua 8080
```

The mock server provides these test endpoints:

- **GET /get-jwt** - Returns JWT based on existing token headers

### 2. Test Backend Service

```bash
# Simple GET request - works purely based on existing JWT token headers
curl -X GET http://localhost:9999/get-jwt

# Expected response (just the JWT string):
# eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

### 3. Test with Kong

Configure Kong with the plugin:

```yaml
plugins:
  - name: remote-jwt-auth
    config:
      authenticated_consumer: "test-consumer"
      jwt_service_url: "http://localhost:9999/get-jwt"
      jwt_service_timeout: 5000
      signing_urls:
        - "https://www.googleapis.com/oauth2/v1/certs"
```

Then send requests and check for the `x-harmonic-cerberus-jwt` header.

## Test Scenarios Covered

### Unit Tests - Backend JWT Fetching

- ✅ Returns nil when `jwt_service_url` not configured
- ✅ Returns cached JWT when available
- ✅ Fetches JWT from backend service successfully
- ✅ Handles both `jwt` and `token` response fields
- ✅ Handles HTTP connection failures
- ✅ Handles non-200 HTTP status codes
- ✅ Handles missing JWT token in response
- ✅ Works with anonymous consumers
- ✅ Uses default timeout when not specified
- ✅ Uses default TTL when expires_in not provided

### Unit Tests - Schema Validation

- ✅ Validates minimal configuration
- ✅ Validates all original fields
- ✅ Validates new JWT service fields
- ✅ Validates complete configuration
- ✅ Uses correct default values
- ✅ Rejects invalid configurations
- ✅ Maintains backward compatibility

### Integration Tests

- ✅ Plugin loads correctly with new configuration
- ✅ Sets `x-harmonic-cerberus-jwt` header when backend available
- ✅ Continues working when backend unavailable
- ✅ Maintains backward compatibility without `jwt_service_url`

### Mock Backend Test Consumers

The mock backend provides these test consumers:

- **test-consumer**: Returns standard JWT with 3600s TTL
- **anonymous**: Returns JWT for anonymous users with 1800s TTL
- **premium-user**: Returns `token` field instead of `jwt` (tests flexibility)
- **error-consumer**: Returns HTTP 500 error
- **timeout-consumer**: Simulates slow response (10s delay)
- **invalid-json-consumer**: Returns non-JSON response
- **missing-jwt-consumer**: Returns JSON without JWT field
- **any-other**: Returns generic JWT

## Test Coverage

The tests cover:

1. **Functionality**: All new backend JWT fetching features
2. **Error Handling**: Network failures, HTTP errors, malformed responses
3. **Caching**: JWT caching and TTL handling
4. **Compatibility**: Backward compatibility with existing configurations
5. **Schema**: Validation of new configuration fields
6. **Integration**: End-to-end plugin behavior

## CI/CD Integration

To integrate with CI/CD pipelines:

```bash
# In your CI script
./spec/run-tests.sh
```

The script exits with code 0 on success, non-zero on failure.

## Test Results from Latest Run

**✅ All tests successfully passed!**

```
📊 Test Results Summary:
✅ Passed: 18 assertions
❌ Failed: 0
📈 Total:  18

🎉 All tests passed!
```

**Validated functionality:**
- ✅ Backend JWT fetching with caching
- ✅ Error handling (network failures, HTTP errors)
- ✅ Consumer handling (named consumers, anonymous)
- ✅ Configuration validation
- ✅ Backward compatibility

## Installation Commands Summary

**Quick setup for testing:**
```bash
# Install dependencies (if not already installed)
brew install lua luarocks
luarocks install lua-cjson

# Run tests immediately
lua spec/unit/simple-backend-jwt-test.lua
```

**Full testing setup:**
```bash
luarocks install busted
luarocks install lua-cjson
./spec/run-tests.sh
```

## Troubleshooting

### Common Issues

1. **"lua: command not found"**
   ```bash
   brew install lua
   ```

2. **"luarocks: command not found"**
   ```bash
   brew install luarocks
   ```

3. **"module 'cjson' not found"**
   ```bash
   luarocks install lua-cjson
   ```

4. **"busted not found"** (for full test suite)
   ```bash
   luarocks install busted
   ```

5. **"Kong testing helpers not found"** (for integration tests)
   - Integration tests will be skipped automatically
   - For full testing, install Kong: `luarocks install kong --only-deps`

### Quick Validation

To verify the implementation without any setup:
```bash
# Test syntax of all plugin files
lua -e "
local files = {'kong/plugins/remote-jwt-auth/schema.lua', 'kong/plugins/remote-jwt-auth/handler.lua', 'kong/plugins/remote-jwt-auth/cache.lua'}
for _, file in ipairs(files) do
  local f = io.open(file, 'r')
  if f then
    local content = f:read('*all')
    f:close()
    local func, err = load(content, file)
    if func then print('✅ ' .. file .. ': syntax OK') else print('❌ ' .. file .. ': ' .. err) end
  end
end
"
```