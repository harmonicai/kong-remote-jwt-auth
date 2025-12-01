local http = require("resty.http")
local sha512 = require("resty.sha512")
local to_hex = require("resty.string").to_hex
local cache = require("kong.plugins.remote-jwt-auth.cache")

local _M = {}

local HARMONIC_CERBERUS_JWT = "x-harmonic-cerberus-jwt"

local function generate_cache_key(config, key)
    local digest = sha512:new()
    assert(digest:update(config.cache_namespace))
    assert(digest:update(key))
    return "remote-jwt-auth:" .. to_hex(digest:final())
end

local function fetch_jwt_from_backend(config, consumer_id)
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

    -- Log the request details at debug level
    if kong.log.is_debug_enabled() then
        kong.log.debug("Making request to JWT backend service:")
        kong.log.debug("  URL: ", config.jwt_service_url)
        kong.log.debug("  Method: GET")
        kong.log.debug("  Headers:")
        for name, value in pairs(original_headers) do
            -- Truncate long header values for readability
            local display_value = type(value) == "string" and value:len() > 100 and (value:sub(1, 100) .. "...")
                or tostring(value)
            kong.log.debug("    ", name, ": ", display_value)
        end
    end

    local res, err = httpc:request_uri(config.jwt_service_url, {
        method = "GET",
        headers = original_headers,
    })

    -- Log the response details
    if res == nil then
        kong.log.err("Request for backend JWT failed: ", err)
        return nil, err
    end

    if kong.log.is_debug_enabled() then
        kong.log.debug("Backend JWT service response:")
        kong.log.debug("  Status: ", res.status)
        kong.log.debug("  Headers:")
        if res.headers then
            for name, value in pairs(res.headers) do
                kong.log.debug("    ", name, ": ", tostring(value))
            end
        end
        -- Truncate response body for logging
        local body_preview = res.body and (res.body:len() > 200 and (res.body:sub(1, 200) .. "...") or res.body)
            or "nil"
        kong.log.debug("  Body: ", body_preview)
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

-- Fetch Cerberus JWT from backend and set in header
-- Skips if user is anonymous or jwt_service_url is not configured
-- @param config Plugin configuration
function _M.set_cerberus_jwt_header(config)
    if not config.jwt_service_url then
        return
    end

    local consumer = kong.client.get_consumer()
    if not consumer or consumer.username == config.anonymous then
        return
    end

    local backend_jwt, err = fetch_jwt_from_backend(config, consumer.username)

    if backend_jwt then
        kong.service.request.set_header(HARMONIC_CERBERUS_JWT, backend_jwt)
        kong.log.debug("Set ", HARMONIC_CERBERUS_JWT, " header with JWT: ", backend_jwt:sub(1, 50), "...")
    elseif err then
        kong.log.warn("Failed to fetch backend JWT (request will continue): ", err)
    end
end

return _M
