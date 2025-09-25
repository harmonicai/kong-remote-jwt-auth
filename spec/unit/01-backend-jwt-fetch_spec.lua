local helpers = require "spec.helpers"
local cjson = require "cjson"

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
  end
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
      end
    }
  end,
  set_mock_response = function(url, response)
    mock_http_responses[url] = response
  end,
  clear_mocks = function()
    mock_http_responses = {}
  end
}

-- Mock Kong logger
local kong_log_messages = {}
local mock_kong = {
  log = {
    err = function(msg, ...)
      table.insert(kong_log_messages, "ERR: " .. string.format(msg, ...))
    end,
    warn = function(msg, ...)
      table.insert(kong_log_messages, "WARN: " .. string.format(msg, ...))
    end
  }
}

-- Load and patch the handler
package.loaded["resty.http"] = mock_http
package.loaded["cjson"] = cjson
package.loaded["kong.plugins.remote-jwt-auth.cache"] = mock_cache
_G.kong = mock_kong

-- Mock the handler's dependencies and extract the function
local handler_code = [[
local http = require("resty.http")
local cjson = require("cjson")
local cache = require("kong.plugins.remote-jwt-auth.cache")
local sha512 = require("resty.sha512")
local to_hex = require("resty.string").to_hex

local function generate_cache_key(config, key)
    -- Simplified for testing
    return config.cache_namespace .. ":" .. key
end

local function fetch_jwt_from_backend(config, consumer_id)
    if not config.jwt_service_url then
        return nil, nil
    end

    local cache_key = generate_cache_key(config, "backend-jwt:" .. (consumer_id or "anonymous"))
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

    local request_body = cjson.encode({
        consumer_id = consumer_id or "anonymous",
        timestamp = start_of_request
    })

    local res, err = httpc:request_uri(config.jwt_service_url, {
        method = "POST",
        body = request_body,
        headers = {
            ["Content-Type"] = "application/json"
        }
    })

    if res == nil then
        kong.log.err("Request for backend JWT failed: ", err)
        return nil, err
    end

    if res.status ~= 200 then
        kong.log.err("Backend JWT service returned status: ", res.status)
        return nil, "Backend service error: " .. res.status
    end

    local response_body = cjson.decode(res.body)
    local jwt_token = response_body.jwt or response_body.token

    if not jwt_token then
        kong.log.err("Backend JWT service response missing JWT token")
        return nil, "Missing JWT token in response"
    end

    local ttl = response_body.expires_in or 300
    local expires_at = start_of_request + ttl

    local success, err = cache:store(cache_key, jwt_token, expires_at)
    if not success then
        kong.log.err("Failed to cache backend JWT: ", err)
    end

    return jwt_token, nil
end

return { fetch_jwt_from_backend = fetch_jwt_from_backend }
]]

-- Mock sha512 and to_hex for testing
package.loaded["resty.sha512"] = {}
package.loaded["resty.string"] = { to_hex = function(s) return s end }

local handler_module = loadstring(handler_code)()
local fetch_jwt_from_backend = handler_module.fetch_jwt_from_backend

describe("Backend JWT Fetching", function()

  before_each(function()
    mock_cache:clear()
    mock_http.clear_mocks()
    kong_log_messages = {}
  end)

  describe("fetch_jwt_from_backend", function()

    it("returns nil when jwt_service_url is not configured", function()
      local config = {}
      local jwt, err = fetch_jwt_from_backend(config, "test-consumer")
      assert.is_nil(jwt)
      assert.is_nil(err)
    end)

    it("returns cached JWT when available", function()
      local config = {
        jwt_service_url = "http://backend.com/jwt",
        cache_namespace = "test"
      }

      -- Pre-populate cache
      mock_cache:store("test:backend-jwt:test-consumer", "cached-jwt-token", os.time() + 300)

      local jwt, err = fetch_jwt_from_backend(config, "test-consumer")
      assert.equals("cached-jwt-token", jwt)
      assert.is_nil(err)
    end)

    it("fetches JWT from backend service successfully", function()
      local config = {
        jwt_service_url = "http://backend.com/jwt",
        jwt_service_timeout = 5000,
        cache_namespace = "test"
      }

      -- Mock successful HTTP response
      mock_http.set_mock_response("http://backend.com/jwt", {
        status = 200,
        body = cjson.encode({
          jwt = "new-jwt-token",
          expires_in = 600
        })
      })

      local jwt, err = fetch_jwt_from_backend(config, "test-consumer")
      assert.equals("new-jwt-token", jwt)
      assert.is_nil(err)

      -- Verify it was cached
      local cached_jwt = mock_cache:get("test:backend-jwt:test-consumer")
      assert.equals("new-jwt-token", cached_jwt)
    end)

    it("handles backend service returning 'token' field", function()
      local config = {
        jwt_service_url = "http://backend.com/jwt",
        cache_namespace = "test"
      }

      mock_http.set_mock_response("http://backend.com/jwt", {
        status = 200,
        body = cjson.encode({
          token = "token-field-jwt",
          expires_in = 300
        })
      })

      local jwt, err = fetch_jwt_from_backend(config, "test-consumer")
      assert.equals("token-field-jwt", jwt)
      assert.is_nil(err)
    end)

    it("handles HTTP connection failure", function()
      local config = {
        jwt_service_url = "http://unreachable.com/jwt",
        cache_namespace = "test"
      }

      local jwt, err = fetch_jwt_from_backend(config, "test-consumer")
      assert.is_nil(jwt)
      assert.equals("Connection failed", err)
      assert.matches("Request for backend JWT failed", kong_log_messages[1])
    end)

    it("handles non-200 HTTP status", function()
      local config = {
        jwt_service_url = "http://backend.com/jwt",
        cache_namespace = "test"
      }

      mock_http.set_mock_response("http://backend.com/jwt", {
        status = 500,
        body = "Internal Server Error"
      })

      local jwt, err = fetch_jwt_from_backend(config, "test-consumer")
      assert.is_nil(jwt)
      assert.equals("Backend service error: 500", err)
      assert.matches("Backend JWT service returned status: 500", kong_log_messages[1])
    end)

    it("handles missing JWT token in response", function()
      local config = {
        jwt_service_url = "http://backend.com/jwt",
        cache_namespace = "test"
      }

      mock_http.set_mock_response("http://backend.com/jwt", {
        status = 200,
        body = cjson.encode({
          message = "success",
          expires_in = 300
        })
      })

      local jwt, err = fetch_jwt_from_backend(config, "test-consumer")
      assert.is_nil(jwt)
      assert.equals("Missing JWT token in response", err)
      assert.matches("Backend JWT service response missing JWT token", kong_log_messages[1])
    end)

    it("handles anonymous consumer", function()
      local config = {
        jwt_service_url = "http://backend.com/jwt",
        cache_namespace = "test"
      }

      mock_http.set_mock_response("http://backend.com/jwt", {
        status = 200,
        body = cjson.encode({
          jwt = "anonymous-jwt-token",
          expires_in = 300
        })
      })

      local jwt, err = fetch_jwt_from_backend(config, nil)
      assert.equals("anonymous-jwt-token", jwt)
      assert.is_nil(err)

      -- Verify cache key uses "anonymous"
      local cached_jwt = mock_cache:get("test:backend-jwt:anonymous")
      assert.equals("anonymous-jwt-token", cached_jwt)
    end)

    it("uses default timeout when not specified", function()
      local config = {
        jwt_service_url = "http://backend.com/jwt",
        cache_namespace = "test"
      }

      mock_http.set_mock_response("http://backend.com/jwt", {
        status = 200,
        body = cjson.encode({
          jwt = "default-timeout-jwt",
          expires_in = 300
        })
      })

      local jwt, err = fetch_jwt_from_backend(config, "test-consumer")
      assert.equals("default-timeout-jwt", jwt)
      assert.is_nil(err)
    end)

    it("uses default TTL when expires_in not provided", function()
      local config = {
        jwt_service_url = "http://backend.com/jwt",
        cache_namespace = "test"
      }

      mock_http.set_mock_response("http://backend.com/jwt", {
        status = 200,
        body = cjson.encode({
          jwt = "default-ttl-jwt"
        })
      })

      local jwt, err = fetch_jwt_from_backend(config, "test-consumer")
      assert.equals("default-ttl-jwt", jwt)
      assert.is_nil(err)

      -- JWT should still be cached despite missing expires_in
      local cached_jwt = mock_cache:get("test:backend-jwt:test-consumer")
      assert.equals("default-ttl-jwt", cached_jwt)
    end)
  end)
end)