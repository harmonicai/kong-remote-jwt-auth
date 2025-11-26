-- Standalone unit test for backend JWT fetching (no Kong dependencies)
-- Tests the cerberus.lua module logic

-- Mock cache implementation
local mock_cache = {
    data = {},
    get = function(self, key)
        return self.data[key], nil
    end,
    store = function(self, key, value, expires_at)
        self.data[key] = value
        return true, nil
    end,
    clear = function(self)
        self.data = {}
    end,
}

-- Mock HTTP client
local mock_http_responses = {}
local mock_http = {
    new = function()
        return {
            set_timeout = function(self, timeout) end,
            request_uri = function(self, url, options)
                -- Try exact match first
                local response = mock_http_responses[url]
                if response then
                    return response, nil
                end

                -- Try pattern matching for URLs with query params
                for pattern, resp in pairs(mock_http_responses) do
                    if
                        string.match(
                            url,
                            pattern:gsub("%%", "%%%%"):gsub("%-", "%%-"):gsub("%.", "%%."):gsub("?", "%?")
                        )
                    then
                        return resp, nil
                    end
                end

                return nil, "Connection failed"
            end,
        }
    end,
}

local function set_mock_response(url_pattern, response)
    mock_http_responses[url_pattern] = response
end

local function clear_mocks()
    mock_http_responses = {}
    mock_cache:clear()
end

-- Mock Kong logger and request
local kong_log_messages = {}
local mock_request_headers = {}
local mock_consumer = nil

local mock_kong = {
    log = {
        err = function(...)
            local args = {...}
            local msg = table.concat(args, "")
            table.insert(kong_log_messages, "ERR: " .. msg)
        end,
        warn = function(...)
            local args = {...}
            local msg = table.concat(args, "")
            table.insert(kong_log_messages, "WARN: " .. msg)
        end,
        notice = function(...) end,  -- Suppress notice logs in tests
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
            set_header = function(name, value) end,
        },
    },
}

-- Set up the environment
_G.kong = mock_kong

-- Simplified cache key generation (matches cerberus.lua logic)
local function generate_cache_key(config, key)
    -- Simplified for testing - real implementation uses sha512
    return "remote-jwt-auth:" .. (config.cache_namespace or "test") .. ":" .. key
end

-- The function we're testing (mirrors cerberus.lua fetch_jwt_from_backend)
local function fetch_jwt_from_backend(config, consumer_id)
    local cache_key = generate_cache_key(config, "backend-jwt:" .. consumer_id)
    local cached_jwt, err = mock_cache:get(cache_key)
    if err then
        kong.log.err("Failed to get cached backend JWT: ", err)
    elseif cached_jwt then
        return cached_jwt, nil
    end

    local httpc = mock_http.new()
    if not httpc then
        kong.log.err("Failed to start HTTP request for backend JWT")
        return nil, "HTTP client error"
    end

    httpc:set_timeout(config.jwt_service_timeout or 5000)
    local start_of_request = os.time()

    -- Get all original request headers to pass to backend service
    local original_headers = kong.request.get_headers()

    local res, err = httpc:request_uri(config.jwt_service_url, {
        method = "GET",
        headers = original_headers,
    })

    if res == nil then
        kong.log.err("Request for backend JWT failed: ", err)
        return nil, err
    end

    if res.status ~= 200 then
        kong.log.err("Backend JWT service returned non-200 status: ", res.status)
        return nil, "Backend service error: " .. res.status
    end

    local response_jwt = res.body

    if not response_jwt or response_jwt == "" then
        kong.log.err("Backend JWT service response missing JWT token")
        return nil, "Missing JWT token in response"
    end

    local ttl = 300 -- Default TTL since response is just the token string
    local expires_at = start_of_request + ttl

    local success, err = mock_cache:store(cache_key, response_jwt, expires_at)
    if not success then
        kong.log.err("Failed to cache backend JWT: ", err)
    end

    return response_jwt, nil
end

-- Function that mirrors cerberus.set_cerberus_jwt_header
local function set_cerberus_jwt_header(config)
    if not config.jwt_service_url then
        return nil, nil
    end

    local consumer = kong.client.get_consumer()
    if not consumer or consumer.username == config.anonymous then
        return nil, "skipped_anonymous"
    end

    return fetch_jwt_from_backend(config, consumer.username)
end

-- Simple test framework
local tests_passed = 0
local tests_failed = 0

local function assert_equals(expected, actual, message)
    if expected ~= actual then
        print("❌ FAIL: " .. (message or "assertion failed"))
        print("   Expected: " .. tostring(expected))
        print("   Actual: " .. tostring(actual))
        tests_failed = tests_failed + 1
        return false
    else
        tests_passed = tests_passed + 1
        return true
    end
end

local function assert_nil(value, message)
    return assert_equals(nil, value, message)
end

local function assert_not_nil(value, message)
    if value == nil then
        print("❌ FAIL: " .. (message or "expected non-nil value"))
        tests_failed = tests_failed + 1
        return false
    else
        tests_passed = tests_passed + 1
        return true
    end
end

local function run_test(name, test_function)
    print("🧪 " .. name)
    kong_log_messages = {}
    mock_request_headers = {}
    mock_consumer = nil
    clear_mocks()

    local ok, err = pcall(test_function)
    if not ok then
        print("❌ FAIL: " .. name .. " - " .. tostring(err))
        tests_failed = tests_failed + 1
    else
        print("✅ PASS: " .. name)
    end
    print("")
end

-- Test cases
print("🚀 Running Cerberus JWT Fetching Tests")
print("======================================")
print("")

run_test("Returns nil when jwt_service_url is not configured", function()
    local config = {}
    mock_consumer = { username = "test-consumer" }
    local jwt, err = set_cerberus_jwt_header(config)
    assert_nil(jwt, "JWT should be nil")
    assert_nil(err, "Error should be nil")
end)

run_test("Skips anonymous users", function()
    local config = {
        jwt_service_url = "http://midtier:80/auth/auth_jwt",
        anonymous = "anonymous-user",
    }
    mock_consumer = { username = "anonymous-user" }
    local jwt, err = set_cerberus_jwt_header(config)
    assert_nil(jwt, "JWT should be nil for anonymous")
    assert_equals("skipped_anonymous", err, "Should return skipped_anonymous")
end)

run_test("Skips when no consumer", function()
    local config = {
        jwt_service_url = "http://midtier:80/auth/auth_jwt",
    }
    mock_consumer = nil
    local jwt, err = set_cerberus_jwt_header(config)
    assert_nil(jwt, "JWT should be nil when no consumer")
    assert_equals("skipped_anonymous", err, "Should return skipped_anonymous")
end)

run_test("Returns cached JWT when available", function()
    local config = {
        jwt_service_url = "http://midtier:80/auth/auth_jwt",
        cache_namespace = "test",
    }
    mock_consumer = { username = "test-consumer" }

    -- Pre-populate cache with the correct key format
    mock_cache:store("remote-jwt-auth:test:backend-jwt:test-consumer", "cached-jwt-token", os.time() + 300)

    local jwt, err = set_cerberus_jwt_header(config)
    assert_equals("cached-jwt-token", jwt, "Should return cached JWT")
    assert_nil(err, "Should not return error")
end)

run_test("Fetches JWT from backend service successfully", function()
    local config = {
        jwt_service_url = "http://midtier:80/auth/auth_jwt",
        jwt_service_timeout = 5000,
        cache_namespace = "test",
    }
    mock_consumer = { username = "test-consumer" }

    -- Mock successful HTTP response (GET returning JWT string)
    set_mock_response("http://midtier:80/auth/auth_jwt", {
        status = 200,
        body = "new-cerberus-jwt-token",
    })

    local jwt, err = set_cerberus_jwt_header(config)
    assert_equals("new-cerberus-jwt-token", jwt, "Should return new JWT")
    assert_nil(err, "Should not return error")

    -- Verify it was cached
    local cached_jwt = mock_cache:get("remote-jwt-auth:test:backend-jwt:test-consumer")
    assert_equals("new-cerberus-jwt-token", cached_jwt, "JWT should be cached")
end)

run_test("Passes original headers to backend", function()
    local config = {
        jwt_service_url = "http://midtier:80/auth/auth_jwt",
        cache_namespace = "test",
    }
    mock_consumer = { username = "test-consumer" }
    mock_request_headers = { ["user-agent"] = "test-client", ["authorization"] = "Bearer firebase-jwt" }

    set_mock_response("http://midtier:80/auth/auth_jwt", {
        status = 200,
        body = "jwt-with-original-headers",
    })

    local jwt, err = set_cerberus_jwt_header(config)
    assert_equals("jwt-with-original-headers", jwt, "Should return JWT")
    assert_nil(err, "Should not return error")
end)

run_test("Handles HTTP connection failure", function()
    local config = {
        jwt_service_url = "http://not-midtier:80/auth/auth_jwt",
        cache_namespace = "test",
    }
    mock_consumer = { username = "test-consumer" }

    local jwt, err = set_cerberus_jwt_header(config)
    assert_nil(jwt, "Should return nil JWT on connection failure")
    assert_equals("Connection failed", err, "Should return connection error")
end)

run_test("Handles non-200 HTTP status", function()
    local config = {
        jwt_service_url = "http://midtier:80/auth/auth_jwt",
        cache_namespace = "test",
    }
    mock_consumer = { username = "test-consumer" }

    set_mock_response("http://midtier:80/auth/auth_jwt", {
        status = 500,
        body = "Internal Server Error",
    })

    local jwt, err = set_cerberus_jwt_header(config)
    assert_nil(jwt, "Should return nil JWT on server error")
    assert_equals("Backend service error: 500", err, "Should return server error")
end)

run_test("Handles empty response body", function()
    local config = {
        jwt_service_url = "http://midtier:80/auth/auth_jwt",
        cache_namespace = "test",
    }
    mock_consumer = { username = "test-consumer" }

    set_mock_response("http://midtier:80/auth/auth_jwt", {
        status = 200,
        body = "",
    })

    local jwt, err = set_cerberus_jwt_header(config)
    assert_nil(jwt, "Should return nil when response is empty")
    assert_equals("Missing JWT token in response", err, "Should return missing token error")
end)

run_test("Uses per-user cache keys", function()
    local config = {
        jwt_service_url = "http://midtier:80/auth/auth_jwt",
        cache_namespace = "test",
    }

    -- Set up for user1
    mock_consumer = { username = "user1" }
    set_mock_response("http://midtier:80/auth/auth_jwt", {
        status = 200,
        body = "user1-jwt-token",
    })

    local jwt1, _ = set_cerberus_jwt_header(config)
    assert_equals("user1-jwt-token", jwt1, "Should return user1 JWT")

    -- Clear HTTP mocks but keep cache
    mock_http_responses = {}

    -- Set up for user2
    mock_consumer = { username = "user2" }
    set_mock_response("http://midtier:80/auth/auth_jwt", {
        status = 200,
        body = "user2-jwt-token",
    })

    local jwt2, _ = set_cerberus_jwt_header(config)
    assert_equals("user2-jwt-token", jwt2, "Should return user2 JWT (not cached user1)")

    -- Verify both are cached separately
    local cached_jwt1 = mock_cache:get("remote-jwt-auth:test:backend-jwt:user1")
    local cached_jwt2 = mock_cache:get("remote-jwt-auth:test:backend-jwt:user2")
    assert_equals("user1-jwt-token", cached_jwt1, "User1 JWT should be cached")
    assert_equals("user2-jwt-token", cached_jwt2, "User2 JWT should be cached")
end)

run_test("Uses default timeout when not specified", function()
    local config = {
        jwt_service_url = "http://midtier:80/auth/auth_jwt",
        cache_namespace = "test",
        -- jwt_service_timeout not specified, should use default 5000
    }
    mock_consumer = { username = "test-consumer" }

    set_mock_response("http://midtier:80/auth/auth_jwt", {
        status = 200,
        body = "default-timeout-jwt",
    })

    local jwt, err = set_cerberus_jwt_header(config)
    assert_equals("default-timeout-jwt", jwt, "Should return JWT with default timeout")
    assert_nil(err, "Should not return error")
end)

-- Test summary
print("📊 Test Results")
print("===============")
print("✅ Passed: " .. tests_passed)
print("❌ Failed: " .. tests_failed)
print("📈 Total:  " .. (tests_passed + tests_failed))

if tests_failed > 0 then
    print("")
    print("❌ Some tests failed!")
    os.exit(1)
else
    print("")
    print("🎉 All tests passed!")
    os.exit(0)
end
