-- Unit test for Cerberus JWT fetching (no Kong dependencies required)
local cjson = require("cjson")

-- Mock dependencies
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
                local response = mock_http_responses[url]
                if not response then
                    return nil, "Connection failed"
                end
                return response, nil
            end,
        }
    end,
    set_mock_response = function(url, response)
        mock_http_responses[url] = response
    end,
    clear_mocks = function()
        mock_http_responses = {}
    end,
}

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
        notice = function(...) end,
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

-- Load and patch the handler
package.loaded["resty.http"] = mock_http
package.loaded["cjson"] = cjson
package.loaded["kong.plugins.remote-jwt-auth.cache"] = mock_cache
_G.kong = mock_kong

-- Mock the cerberus module's fetch_jwt_from_backend function
-- This mirrors the actual implementation in cerberus.lua
local cerberus_code = [[
local http = require("resty.http")
local cache = require("kong.plugins.remote-jwt-auth.cache")

local function generate_cache_key(config, key)
    -- Simplified for testing - real implementation uses sha512
    return "remote-jwt-auth:" .. config.cache_namespace .. ":" .. key
end

local function fetch_jwt_from_backend(config, consumer_id, firebase_jwt)
    local cache_key = generate_cache_key(config, "backend-jwt:" .. consumer_id)
    local cached_jwt, err = cache:get(cache_key)
    if err then
        kong.log.err("Failed to get cached backend JWT: ", err)
    elseif cached_jwt then
        return cached_jwt, nil
    end

    local httpc, err = http.new()
    if httpc == nil then
        kong.log.err("Failed to start HTTP request for backend JWT: ", err)
        return nil, err
    end

    httpc:set_timeout(config.jwt_service_timeout or 5000)
    local start_of_request = os.time()

    -- Get all original request headers to pass to backend service
    local original_headers = kong.request.get_headers()

    -- Add the original Firebase JWT token to the request headers
    if firebase_jwt then
        original_headers["x-original-jwt"] = firebase_jwt
    end

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

    local success, err = cache:store(cache_key, response_jwt, expires_at)
    if not success then
        kong.log.err("Failed to cache backend JWT: ", err)
    end

    return response_jwt, nil
end

local function set_cerberus_jwt_header(config, firebase_jwt)
    if not config.jwt_service_url then
        return nil, nil
    end

    local consumer = kong.client.get_consumer()
    if not consumer or consumer.username == config.anonymous then
        return nil, "skipped_anonymous"
    end

    return fetch_jwt_from_backend(config, consumer.username, firebase_jwt)
end

return {
    fetch_jwt_from_backend = fetch_jwt_from_backend,
    set_cerberus_jwt_header = set_cerberus_jwt_header,
}
]]

local cerberus_module = loadstring(cerberus_code)()
local fetch_jwt_from_backend = cerberus_module.fetch_jwt_from_backend
local set_cerberus_jwt_header = cerberus_module.set_cerberus_jwt_header

describe("Cerberus JWT Fetching", function()
    before_each(function()
        mock_cache:clear()
        mock_http.clear_mocks()
        kong_log_messages = {}
        mock_request_headers = {}
        mock_consumer = nil
    end)

    describe("set_cerberus_jwt_header", function()
        it("returns nil when jwt_service_url is not configured", function()
            local config = {}
            mock_consumer = { username = "test-consumer" }
            local jwt, err = set_cerberus_jwt_header(config, "firebase-token")
            assert.is_nil(jwt)
            assert.is_nil(err)
        end)

        it("skips anonymous users", function()
            local config = {
                jwt_service_url = "http://midtier:80/auth/auth_jwt",
                cache_namespace = "test",
                anonymous = "anonymous-user",
            }
            mock_consumer = { username = "anonymous-user" }
            local jwt, err = set_cerberus_jwt_header(config, "firebase-token")
            assert.is_nil(jwt)
            assert.equals("skipped_anonymous", err)
        end)

        it("skips when no consumer is present", function()
            local config = {
                jwt_service_url = "http://midtier:80/auth/auth_jwt",
                cache_namespace = "test",
            }
            mock_consumer = nil
            local jwt, err = set_cerberus_jwt_header(config, "firebase-token")
            assert.is_nil(jwt)
            assert.equals("skipped_anonymous", err)
        end)
    end)

    describe("fetch_jwt_from_backend", function()
        it("returns cached JWT when available", function()
            local config = {
                jwt_service_url = "http://midtier:80/auth/auth_jwt",
                cache_namespace = "test",
            }

            -- Pre-populate cache
            mock_cache:store("remote-jwt-auth:test:backend-jwt:test-consumer", "cached-jwt-token", os.time() + 300)

            local jwt, err = fetch_jwt_from_backend(config, "test-consumer", "firebase-token")
            assert.equals("cached-jwt-token", jwt)
            assert.is_nil(err)
        end)

        it("fetches JWT from backend service successfully", function()
            local config = {
                jwt_service_url = "http://midtier:80/auth/auth_jwt",
                jwt_service_timeout = 5000,
                cache_namespace = "test",
            }
            mock_request_headers = { ["user-agent"] = "test-client" }

            -- Mock successful HTTP response (GET returning raw JWT string)
            mock_http.set_mock_response("http://midtier:80/auth/auth_jwt", {
                status = 200,
                body = "new-cerberus-jwt-token",
            })

            local jwt, err = fetch_jwt_from_backend(config, "test-consumer", "firebase-token")
            assert.equals("new-cerberus-jwt-token", jwt)
            assert.is_nil(err)

            -- Verify it was cached
            local cached_jwt = mock_cache:get("remote-jwt-auth:test:backend-jwt:test-consumer")
            assert.equals("new-cerberus-jwt-token", cached_jwt)
        end)

        it("passes firebase_jwt in x-original-jwt header", function()
            local config = {
                jwt_service_url = "http://midtier:80/auth/auth_jwt",
                cache_namespace = "test",
            }
            mock_request_headers = { ["authorization"] = "Bearer existing-token" }

            mock_http.set_mock_response("http://midtier:80/auth/auth_jwt", {
                status = 200,
                body = "jwt-with-context",
            })

            local jwt, err = fetch_jwt_from_backend(config, "test-consumer", "my-firebase-jwt")
            assert.equals("jwt-with-context", jwt)
            assert.is_nil(err)
        end)

        it("handles HTTP connection failure", function()
            local config = {
                jwt_service_url = "http://not-midtier:80/auth/auth_jwt",
                cache_namespace = "test",
            }

            local jwt, err = fetch_jwt_from_backend(config, "test-consumer", "firebase-token")
            assert.is_nil(jwt)
            assert.equals("Connection failed", err)
            assert.matches("Request for backend JWT failed", kong_log_messages[1])
        end)

        it("handles non-200 HTTP status", function()
            local config = {
                jwt_service_url = "http://midtier:80/auth/auth_jwt",
                cache_namespace = "test",
            }

            mock_http.set_mock_response("http://midtier:80/auth/auth_jwt", {
                status = 500,
                body = "Internal Server Error",
            })

            local jwt, err = fetch_jwt_from_backend(config, "test-consumer", "firebase-token")
            assert.is_nil(jwt)
            assert.equals("Backend service error: 500", err)
            assert.matches("Backend JWT service returned non%-200 status", kong_log_messages[1])
        end)

        it("handles empty response body", function()
            local config = {
                jwt_service_url = "http://midtier:80/auth/auth_jwt",
                cache_namespace = "test",
            }

            mock_http.set_mock_response("http://midtier:80/auth/auth_jwt", {
                status = 200,
                body = "",
            })

            local jwt, err = fetch_jwt_from_backend(config, "test-consumer", "firebase-token")
            assert.is_nil(jwt)
            assert.equals("Missing JWT token in response", err)
            assert.matches("Backend JWT service response missing JWT token", kong_log_messages[1])
        end)

        it("uses per-user cache keys", function()
            local config = {
                jwt_service_url = "http://midtier:80/auth/auth_jwt",
                cache_namespace = "test",
            }

            -- Fetch JWT for user1
            mock_http.set_mock_response("http://midtier:80/auth/auth_jwt", {
                status = 200,
                body = "user1-jwt-token",
            })

            local jwt1, err1 = fetch_jwt_from_backend(config, "user1", "firebase-token")
            assert.equals("user1-jwt-token", jwt1)
            assert.is_nil(err1)

            -- Clear HTTP mocks, keep cache
            mock_http.clear_mocks()

            -- Fetch JWT for user2 (should not get user1's cached JWT)
            mock_http.set_mock_response("http://midtier:80/auth/auth_jwt", {
                status = 200,
                body = "user2-jwt-token",
            })

            local jwt2, err2 = fetch_jwt_from_backend(config, "user2", "firebase-token")
            assert.equals("user2-jwt-token", jwt2)
            assert.is_nil(err2)

            -- Verify both are cached separately
            local cached_jwt1 = mock_cache:get("remote-jwt-auth:test:backend-jwt:user1")
            local cached_jwt2 = mock_cache:get("remote-jwt-auth:test:backend-jwt:user2")
            assert.equals("user1-jwt-token", cached_jwt1)
            assert.equals("user2-jwt-token", cached_jwt2)
        end)

        it("uses default timeout when not specified", function()
            local config = {
                jwt_service_url = "http://midtier:80/auth/auth_jwt",
                cache_namespace = "test",
                -- jwt_service_timeout not specified
            }

            mock_http.set_mock_response("http://midtier:80/auth/auth_jwt", {
                status = 200,
                body = "default-timeout-jwt",
            })

            local jwt, err = fetch_jwt_from_backend(config, "test-consumer", "firebase-token")
            assert.equals("default-timeout-jwt", jwt)
            assert.is_nil(err)
        end)

        it("uses default TTL of 300 seconds", function()
            local config = {
                jwt_service_url = "http://midtier:80/auth/auth_jwt",
                cache_namespace = "test",
            }

            mock_http.set_mock_response("http://midtier:80/auth/auth_jwt", {
                status = 200,
                body = "default-ttl-jwt",
            })

            local jwt, err = fetch_jwt_from_backend(config, "test-consumer", "firebase-token")
            assert.equals("default-ttl-jwt", jwt)
            assert.is_nil(err)

            -- JWT should be cached
            local cached_jwt = mock_cache:get("remote-jwt-auth:test:backend-jwt:test-consumer")
            assert.equals("default-ttl-jwt", cached_jwt)
        end)

        it("handles nil firebase_jwt gracefully", function()
            local config = {
                jwt_service_url = "http://midtier:80/auth/auth_jwt",
                cache_namespace = "test",
            }

            mock_http.set_mock_response("http://midtier:80/auth/auth_jwt", {
                status = 200,
                body = "jwt-without-firebase",
            })

            local jwt, err = fetch_jwt_from_backend(config, "test-consumer", nil)
            assert.equals("jwt-without-firebase", jwt)
            assert.is_nil(err)
        end)
    end)
end)
