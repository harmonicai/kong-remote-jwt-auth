local http = require("resty.http")
local sha256 = require("resty.sha256")
local to_hex = require("resty.string").to_hex
local cache = require("kong.plugins.remote-jwt-auth.cache")

local _M = {}

local HARMONIC_CERBERUS_JWT = "x-harmonic-cerberus-jwt"

-- Retry HTTP request with exponential backoff and jitter
-- Only retries on connection errors and 5xx responses
local function request_with_retry(httpc, url, opts, max_retries, base_delay_ms)
    local res, err

    for attempt = 1, max_retries do
        res, err = httpc:request_uri(url, opts)

        if res then
            -- Success - return if not a server error
            if res.status < 500 then
                return res, nil
            end
            -- 5xx response - treat as retryable error
            err = "server error: " .. res.status
        end

        -- Don't sleep after the last attempt
        if attempt < max_retries then
            -- Exponential backoff with jitter: random delay in [0, 2^(attempt-1) * base_delay)
            local max_delay = math.pow(2, attempt - 1) * base_delay_ms
            local delay_ms = math.random(0, max_delay)
            local delay_s = delay_ms / 1000
            ngx.sleep(delay_s)
            kong.log.debug("JWT service retry attempt ", attempt, "/", max_retries, " after ", delay_ms, "ms: ", err)
        end
    end

    return res, err
end

local function generate_cache_key(config, key)
    local digest = sha256:new()
    assert(digest:update(config.cache_namespace))
    assert(digest:update(key))
    return "remote-jwt-auth:" .. to_hex(digest:final())
end

local function fetch_jwt_from_backend(config, consumer_id)
    local cache_key = generate_cache_key(config, "backend-jwt:" .. consumer_id)
    -- These headers set by the firebase.lua logic
    local user_id = kong.service.request.get_header("X-Token-User-Id")
    local user_email = kong.service.request.get_header("X-Token-User-Email")
    kong.log.debug(
        "Checking cache for backend JWT for consumer: ",
        consumer_id,
        " Cache key: ",
        cache_key,
        " User ID: ",
        user_id,
        " User Email: ",
        user_email
    )
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

    -- If JWT came from query params, add it to headers for the backend
    local query_jwt = kong.request.get_query_arg("jwt")
    if query_jwt and not original_headers["Authorization"] then
        original_headers["Authorization"] = "Bearer " .. query_jwt
    end

    -- Log the request details at debug level
    if kong.configuration.log_level == "debug" then
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

    local max_retries = config.jwt_service_retries or 3
    local base_delay_ms = config.jwt_service_retry_base_delay or 100

    local res, err = request_with_retry(httpc, config.jwt_service_url, {
        method = "GET",
        headers = original_headers,
    }, max_retries, base_delay_ms)

    -- Log the response details
    if res == nil then
        kong.log.err("Request for backend JWT failed after ", max_retries, " attempts: ", err)
        return nil, err
    end

    if kong.configuration.log_level == "debug" then
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

    -- Response is a JSON string (quoted), so strip quotes and whitespace
    local response_jwt = res.body and res.body:gsub('^%s*"?(.-)%s*"?%s*$', "%1") or nil

    -- Debug logging for JWT response
    kong.log.debug("Parsed backend JWT: ", response_jwt)

    if not response_jwt or response_jwt == "" then
        kong.log.err("Backend JWT service response missing JWT token")
        return nil, "Missing JWT token in response"
    end

    local ttl = 240 -- Cache TTL of 4 minutes (Cerberus JWT is valid for 5 minutes)
    local expires_at = start_of_request + ttl

    kong.log.debug(
        "Caching backend JWT for consumer: ",
        consumer_id,
        " Cache key: ",
        cache_key,
        " Expires at: ",
        expires_at
    )
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
        -- Clients (e.g. frontend) calling API gateway should not be setting the Cerberus header - clear it
        kong.service.request.clear_header(HARMONIC_CERBERUS_JWT)
        kong.log.debug("Setting Cerberus JWT header to nil - jwt_service_url not configured")
        return
    end

    local consumer = kong.client.get_consumer()
    if not consumer or consumer.username == config.anonymous then
        return
    end

    local backend_jwt, err = fetch_jwt_from_backend(config, consumer.username)

    if backend_jwt then
        -- TODO: Clear Authorization header after updating downstreams to only read Cerberus JWT
        kong.service.request.set_header(HARMONIC_CERBERUS_JWT, backend_jwt)
        kong.log.debug("Set ", HARMONIC_CERBERUS_JWT, " header with JWT: ", backend_jwt:sub(1, 50), "...")
    elseif err then
        kong.log.warn("Failed to fetch backend JWT (request will continue): ", err)
    end
end

return _M
