-- Cerberus JWT Fetching Tests
-- Tests the real cerberus.lua module with mocked external dependencies
-- Run with: pongo run spec/unit/cerberus-test.lua
--
-- This test imports the REAL cerberus.lua module and mocks only the external
-- dependencies (HTTP client, cache, Kong globals) to test actual fetching logic.

local cjson = require("cjson")

-- ============================================================================
-- Mock Infrastructure (must be set up BEFORE requiring cerberus.lua)
-- ============================================================================

-- Track HTTP requests for verification
local http_requests = {}

-- Mock HTTP responses
local mock_http_responses = {}
local mock_http_should_fail = false
local mock_http_failure_count = 0
local mock_http_max_failures = 0

local function set_mock_http_response(url, response)
    mock_http_responses[url] = response
end

local function set_mock_http_failure(should_fail, max_failures)
    mock_http_should_fail = should_fail
    mock_http_failure_count = 0
    mock_http_max_failures = max_failures or 999
end

-- Mock HTTP client (resty.http)
package.loaded["resty.http"] = {
    new = function()
        return {
            set_timeout = function(self, timeout)
                -- Track timeout setting
                self._timeout = timeout
            end,
            request_uri = function(self, url, options)
                table.insert(http_requests, {
                    url = url,
                    options = options,
                    timeout = self._timeout,
                })

                -- Simulate failures if configured
                if mock_http_should_fail and mock_http_failure_count < mock_http_max_failures then
                    mock_http_failure_count = mock_http_failure_count + 1
                    return nil, "Connection failed"
                end

                local response = mock_http_responses[url]
                if response then
                    return response, nil
                end
                return nil, "No mock response for URL: " .. url
            end,
        }
    end,
}

-- Mock cache
local mock_cache = { data = {} }

mock_cache.get = function(self, key)
    return self.data[key], nil
end

mock_cache.store = function(self, key, value, expires_at)
    self.data[key] = value
    return true, nil
end

mock_cache.clear = function(self)
    self.data = {}
end

package.loaded["kong.plugins.remote-jwt-auth.cache"] = mock_cache

-- Mock Kong globals
local kong_log_messages = {}
local mock_request_headers = {}
local mock_consumer = nil
local set_headers = {}
local debug_enabled = false

-- Helper function to concatenate args with tostring
local function concat_args(...)
    local args = { ... }
    local result = {}
    for i, v in ipairs(args) do
        result[i] = tostring(v)
    end
    return table.concat(result, "")
end

_G.kong = {
    configuration = {
        log_level = debug_enabled and "debug" or "info",
    },
    log = {
        err = function(...)
            table.insert(kong_log_messages, "ERR: " .. concat_args(...))
        end,
        warn = function(...)
            table.insert(kong_log_messages, "WARN: " .. concat_args(...))
        end,
        notice = function(...) end,
        debug = function(...)
            table.insert(kong_log_messages, "DEBUG: " .. concat_args(...))
        end,
    },
    request = {
        get_headers = function()
            return mock_request_headers
        end,
    },
    client = {
        get_consumer = function()
            return mock_consumer
        end,
    },
    service = {
        request = {
            set_header = function(name, value)
                set_headers[name] = value
            end,
            clear_header = function(name)
                set_headers[name] = nil
            end,
        },
    },
}

-- Mock ngx.sleep for retry tests
_G.ngx = _G.ngx or {}
_G.ngx.sleep = function(seconds)
    -- Don't actually sleep in tests
end

-- ============================================================================
-- Now require the REAL cerberus module (after mocks are set up)
-- ============================================================================

local cerberus = require("kong.plugins.remote-jwt-auth.cerberus")

-- ============================================================================
-- Test Framework
-- ============================================================================

local tests_passed = 0
local tests_failed = 0

local function assert_equals(expected, actual, message)
    if expected ~= actual then
        print("   FAIL: " .. (message or "assertion failed"))
        print("   Expected: " .. tostring(expected))
        print("   Actual: " .. tostring(actual))
        tests_failed = tests_failed + 1
        return false
    else
        tests_passed = tests_passed + 1
        return true
    end
end

local function assert_true(value, message)
    return assert_equals(true, value, message)
end

local function assert_false(value, message)
    return assert_equals(false, value, message)
end

local function assert_nil(value, message)
    return assert_equals(nil, value, message)
end

local function assert_not_nil(value, message)
    if value == nil then
        print("   FAIL: " .. (message or "expected non-nil value"))
        tests_failed = tests_failed + 1
        return false
    else
        tests_passed = tests_passed + 1
        return true
    end
end

local function assert_greater_than(expected, actual, message)
    if actual > expected then
        tests_passed = tests_passed + 1
        return true
    else
        print("   FAIL: " .. (message or "expected value to be greater"))
        print("   Expected: > " .. tostring(expected))
        print("   Actual: " .. tostring(actual))
        tests_failed = tests_failed + 1
        return false
    end
end

local function reset_test_state()
    kong_log_messages = {}
    mock_request_headers = {}
    mock_consumer = nil
    set_headers = {}
    mock_cache:clear()
    mock_http_responses = {}
    http_requests = {}
    mock_http_should_fail = false
    mock_http_failure_count = 0
    mock_http_max_failures = 0
    debug_enabled = false
end

local function run_test(name, test_function)
    print("  " .. name)
    reset_test_state()

    local ok, err = pcall(test_function)
    if not ok then
        print("   FAIL: " .. name .. " - " .. tostring(err))
        tests_failed = tests_failed + 1
    else
        print("   PASS")
    end
    print("")
end

-- ============================================================================
-- Test Cases
-- ============================================================================

print("")
print("Cerberus JWT Fetching Tests")
print("===========================")
print("")

-- Base config for tests
local base_config = {
    jwt_service_url = "http://backend:8080/auth/jwt",
    jwt_service_timeout = 5000,
    jwt_service_retries = 3,
    jwt_service_retry_base_delay = 100,
    cache_namespace = "test-cerberus",
}

-- Helper function to shallow copy and merge tables
local function tbl_extend(...)
    local result = {}
    for _, t in ipairs({ ... }) do
        if type(t) == "table" then
            for k, v in pairs(t) do
                result[k] = v
            end
        end
    end
    return result
end

-- ============================================================================
-- Basic Functionality Tests
-- ============================================================================

print("Basic Functionality Tests")
print("-------------------------")

run_test("clears cerberus header when jwt_service_url is not configured", function()
    local config = { cache_namespace = "test" }
    mock_consumer = { username = "test-user" }

    -- Pre-set a spoofed header value that should be cleared
    set_headers["x-harmonic-cerberus-jwt"] = "spoofed-jwt-value"

    cerberus.set_cerberus_jwt_header(config)

    -- Should clear any client-set value
    assert_equals(nil, set_headers["x-harmonic-cerberus-jwt"], "Should clear cerberus header")
end)

run_test("skips anonymous users", function()
    local config = tbl_extend(base_config, {
        anonymous = "anonymous-user",
    })
    mock_consumer = { username = "anonymous-user" }

    set_mock_http_response("http://backend:8080/auth/jwt", {
        status = 200,
        body = "should-not-be-fetched",
    })

    cerberus.set_cerberus_jwt_header(config)

    -- Should not make any HTTP requests
    assert_equals(0, #http_requests, "Should not make HTTP request for anonymous user")
    assert_nil(set_headers["x-harmonic-cerberus-jwt"], "Should not set header for anonymous")
end)

run_test("skips when no consumer present", function()
    local config = tbl_extend(base_config)
    mock_consumer = nil

    set_mock_http_response("http://backend:8080/auth/jwt", {
        status = 200,
        body = "should-not-be-fetched",
    })

    cerberus.set_cerberus_jwt_header(config)

    -- Should not make any HTTP requests
    assert_equals(0, #http_requests, "Should not make HTTP request when no consumer")
    assert_nil(set_headers["x-harmonic-cerberus-jwt"], "Should not set header when no consumer")
end)

run_test("fetches JWT from backend and sets header", function()
    local config = tbl_extend(base_config)
    mock_consumer = { username = "test-user" }

    set_mock_http_response("http://backend:8080/auth/jwt", {
        status = 200,
        body = "cerberus-jwt-token-12345",
    })

    cerberus.set_cerberus_jwt_header(config)

    assert_equals("cerberus-jwt-token-12345", set_headers["x-harmonic-cerberus-jwt"], "Should set cerberus header")
    assert_equals(1, #http_requests, "Should make exactly one HTTP request")
end)

run_test("passes original request headers to backend", function()
    local config = tbl_extend(base_config)
    mock_consumer = { username = "test-user" }
    mock_request_headers = {
        ["authorization"] = "Bearer firebase-token",
        ["user-agent"] = "test-client",
        ["x-custom-header"] = "custom-value",
    }

    set_mock_http_response("http://backend:8080/auth/jwt", {
        status = 200,
        body = "jwt-token",
    })

    cerberus.set_cerberus_jwt_header(config)

    assert_equals(1, #http_requests, "Should make HTTP request")
    local request = http_requests[1]
    assert_equals("Bearer firebase-token", request.options.headers["authorization"], "Should pass auth header")
    assert_equals("test-client", request.options.headers["user-agent"], "Should pass user-agent")
    assert_equals("custom-value", request.options.headers["x-custom-header"], "Should pass custom header")
end)

run_test("uses configured timeout", function()
    local config = tbl_extend(base_config, {
        jwt_service_timeout = 10000,
    })
    mock_consumer = { username = "test-user" }

    set_mock_http_response("http://backend:8080/auth/jwt", {
        status = 200,
        body = "jwt-token",
    })

    cerberus.set_cerberus_jwt_header(config)

    assert_equals(1, #http_requests, "Should make HTTP request")
    assert_equals(10000, http_requests[1].timeout, "Should use configured timeout")
end)

run_test("uses default timeout when not specified", function()
    local config = {
        jwt_service_url = "http://backend:8080/auth/jwt",
        cache_namespace = "test",
        -- jwt_service_timeout not specified
    }
    mock_consumer = { username = "test-user" }

    set_mock_http_response("http://backend:8080/auth/jwt", {
        status = 200,
        body = "jwt-token",
    })

    cerberus.set_cerberus_jwt_header(config)

    assert_equals(1, #http_requests, "Should make HTTP request")
    assert_equals(5000, http_requests[1].timeout, "Should use default 5000ms timeout")
end)

-- ============================================================================
-- Caching Tests
-- ============================================================================

print("Caching Tests")
print("-------------")

run_test("caches JWT after successful fetch", function()
    local config = tbl_extend(base_config)
    mock_consumer = { username = "cache-test-user" }

    set_mock_http_response("http://backend:8080/auth/jwt", {
        status = 200,
        body = "cached-jwt-token",
    })

    -- First call - should fetch
    cerberus.set_cerberus_jwt_header(config)
    assert_equals(1, #http_requests, "First call should make HTTP request")
    assert_equals("cached-jwt-token", set_headers["x-harmonic-cerberus-jwt"], "Should set header")

    -- Clear HTTP mock to prove cache is used
    mock_http_responses = {}
    set_headers = {}

    -- Second call - should use cache
    cerberus.set_cerberus_jwt_header(config)
    assert_equals(1, #http_requests, "Second call should NOT make HTTP request (cached)")
    assert_equals("cached-jwt-token", set_headers["x-harmonic-cerberus-jwt"], "Should set header from cache")
end)

run_test("uses per-user cache keys", function()
    local config = tbl_extend(base_config)

    -- First user
    mock_consumer = { username = "user-alpha" }
    set_mock_http_response("http://backend:8080/auth/jwt", {
        status = 200,
        body = "alpha-jwt-token",
    })

    cerberus.set_cerberus_jwt_header(config)
    assert_equals("alpha-jwt-token", set_headers["x-harmonic-cerberus-jwt"], "Should set alpha's token")

    -- Second user - should make new request, not use alpha's cached token
    mock_consumer = { username = "user-beta" }
    set_mock_http_response("http://backend:8080/auth/jwt", {
        status = 200,
        body = "beta-jwt-token",
    })
    set_headers = {}

    cerberus.set_cerberus_jwt_header(config)
    assert_equals(2, #http_requests, "Should make separate request for each user")
    assert_equals("beta-jwt-token", set_headers["x-harmonic-cerberus-jwt"], "Should set beta's token")
end)

-- ============================================================================
-- Error Handling Tests
-- ============================================================================

print("Error Handling Tests")
print("--------------------")

run_test("handles HTTP connection failure gracefully", function()
    local config = tbl_extend(base_config, {
        jwt_service_retries = 1, -- Only 1 attempt to speed up test
    })
    mock_consumer = { username = "test-user" }

    -- Don't set any mock response - simulates connection failure
    set_mock_http_failure(true, 999)

    cerberus.set_cerberus_jwt_header(config)

    -- Should log warning but not crash
    assert_nil(set_headers["x-harmonic-cerberus-jwt"], "Should not set header on failure")

    -- Check that warning was logged
    local found_warning = false
    for _, msg in ipairs(kong_log_messages) do
        if msg:find("WARN:") and msg:find("Failed to fetch backend JWT") then
            found_warning = true
            break
        end
    end
    assert_true(found_warning, "Should log warning on failure")
end)

run_test("handles non-200 HTTP status", function()
    local config = tbl_extend(base_config, {
        jwt_service_retries = 1,
    })
    mock_consumer = { username = "test-user" }

    set_mock_http_response("http://backend:8080/auth/jwt", {
        status = 401,
        body = "Unauthorized",
    })

    cerberus.set_cerberus_jwt_header(config)

    assert_nil(set_headers["x-harmonic-cerberus-jwt"], "Should not set header on 401")
end)

run_test("handles 500 error with retry", function()
    local config = tbl_extend(base_config, {
        jwt_service_retries = 3,
    })
    mock_consumer = { username = "test-user" }

    -- Return 500 error (will be retried)
    set_mock_http_response("http://backend:8080/auth/jwt", {
        status = 500,
        body = "Internal Server Error",
    })

    cerberus.set_cerberus_jwt_header(config)

    -- Should have made 3 attempts (initial + 2 retries)
    assert_equals(3, #http_requests, "Should retry on 500 errors")
    assert_nil(set_headers["x-harmonic-cerberus-jwt"], "Should not set header after all retries fail")
end)

run_test("handles empty response body", function()
    local config = tbl_extend(base_config, {
        jwt_service_retries = 1,
    })
    mock_consumer = { username = "test-user" }

    set_mock_http_response("http://backend:8080/auth/jwt", {
        status = 200,
        body = "",
    })

    cerberus.set_cerberus_jwt_header(config)

    assert_nil(set_headers["x-harmonic-cerberus-jwt"], "Should not set header with empty body")

    -- Check error was logged
    local found_error = false
    for _, msg in ipairs(kong_log_messages) do
        if msg:find("ERR:") and msg:find("missing JWT token") then
            found_error = true
            break
        end
    end
    assert_true(found_error, "Should log error for empty response")
end)

run_test("handles nil response body", function()
    local config = tbl_extend(base_config, {
        jwt_service_retries = 1,
    })
    mock_consumer = { username = "test-user" }

    set_mock_http_response("http://backend:8080/auth/jwt", {
        status = 200,
        body = nil,
    })

    cerberus.set_cerberus_jwt_header(config)

    assert_nil(set_headers["x-harmonic-cerberus-jwt"], "Should not set header with nil body")
end)

-- ============================================================================
-- Retry Logic Tests
-- ============================================================================

print("Retry Logic Tests")
print("-----------------")

run_test("retries on connection failure then succeeds", function()
    local config = tbl_extend(base_config, {
        jwt_service_retries = 3,
    })
    mock_consumer = { username = "test-user" }

    -- Fail first 2 attempts, succeed on 3rd
    set_mock_http_failure(true, 2)
    set_mock_http_response("http://backend:8080/auth/jwt", {
        status = 200,
        body = "success-after-retry",
    })

    cerberus.set_cerberus_jwt_header(config)

    assert_equals(3, #http_requests, "Should make 3 attempts")
    assert_equals("success-after-retry", set_headers["x-harmonic-cerberus-jwt"], "Should succeed on 3rd attempt")
end)

run_test("does not retry on 4xx errors", function()
    local config = tbl_extend(base_config, {
        jwt_service_retries = 3,
    })
    mock_consumer = { username = "test-user" }

    set_mock_http_response("http://backend:8080/auth/jwt", {
        status = 400,
        body = "Bad Request",
    })

    cerberus.set_cerberus_jwt_header(config)

    -- 4xx errors should not be retried
    assert_equals(1, #http_requests, "Should NOT retry on 4xx errors")
end)

run_test("uses configured retry count", function()
    local config = tbl_extend(base_config, {
        jwt_service_retries = 5,
    })
    mock_consumer = { username = "test-user" }

    -- Always fail
    set_mock_http_failure(true, 999)

    cerberus.set_cerberus_jwt_header(config)

    assert_equals(5, #http_requests, "Should make exactly 5 attempts")
end)

run_test("uses default retry count when not specified", function()
    local config = {
        jwt_service_url = "http://backend:8080/auth/jwt",
        cache_namespace = "test",
        -- jwt_service_retries not specified, defaults to 3
    }
    mock_consumer = { username = "test-user" }

    set_mock_http_failure(true, 999)

    cerberus.set_cerberus_jwt_header(config)

    assert_equals(3, #http_requests, "Should default to 3 retry attempts")
end)

-- ============================================================================
-- Request Method Tests
-- ============================================================================

print("Request Method Tests")
print("--------------------")

run_test("uses GET method for backend request", function()
    local config = tbl_extend(base_config)
    mock_consumer = { username = "test-user" }

    set_mock_http_response("http://backend:8080/auth/jwt", {
        status = 200,
        body = "jwt-token",
    })

    cerberus.set_cerberus_jwt_header(config)

    assert_equals(1, #http_requests, "Should make HTTP request")
    assert_equals("GET", http_requests[1].options.method, "Should use GET method")
end)

run_test("uses configured jwt_service_url", function()
    local config = tbl_extend(base_config, {
        jwt_service_url = "http://custom-service:9000/custom/path",
    })
    mock_consumer = { username = "test-user" }

    set_mock_http_response("http://custom-service:9000/custom/path", {
        status = 200,
        body = "jwt-token",
    })

    cerberus.set_cerberus_jwt_header(config)

    assert_equals(1, #http_requests, "Should make HTTP request")
    assert_equals("http://custom-service:9000/custom/path", http_requests[1].url, "Should use configured URL")
end)

-- ============================================================================
-- Test Summary
-- ============================================================================

print("")
print("Test Results")
print("============")
print("Passed: " .. tests_passed)
print("Failed: " .. tests_failed)
print("Total:  " .. (tests_passed + tests_failed))

if tests_failed > 0 then
    print("")
    print("Some tests failed!")
    os.exit(1)
else
    print("")
    print("All tests passed!")
    os.exit(0)
end
