local http = require("resty.http")
local cjson = require("cjson")
local ssl = require("ngx.ssl")
local x509 = require("resty.openssl.x509")
local sha512 = require("resty.sha512")
local to_hex = require("resty.string").to_hex
local jwt_decoder = require("kong.plugins.jwt.jwt_parser")
local cache = require("kong.plugins.remote-jwt-auth.cache")

local _M = {}

local AUTHORIZATION = "authorization"
local PROXY_AUTHORIZATION = "proxy-authorization"
local TOKEN_USER_ID = "X-Token-User-Id"
local TOKEN_USER_EMAIL = "X-Token-User-Email"

local function generate_cache_key(config, key)
    local digest = sha512:new()
    assert(digest:update(config.cache_namespace))
    assert(digest:update(key))
    return "remote-jwt-auth:" .. to_hex(digest:final())
end

local function fetch_signing_certificates(config, url)
    local httpc, err = http.new()
    if httpc == nil then
        kong.log.err("Failed to start a http request: ", err)
        return nil, err
    end
    httpc:set_timeout(config.timeout)
    local start_of_request = os.time()
    local res, err = httpc:request_uri(url, {})
    if res == nil then
        kong.log.err("Request for certificate failed: ", err)
        return nil, err
    end

    local cache_control_header = res.headers["Cache-Control"]
    if cache_control_header == nil then
        kong.log.err("Could not find cache control header")
        return nil, "Could not find cache control header"
    end
    local _, _, max_age_string = string.find(cache_control_header, "max%-age=(%d+)")
    if max_age_string == nil then
        kong.log.err("Could not find max-age string in cache control")
        return nil, "Could not find max-age string in cache control"
    end
    local max_age = tonumber(max_age_string)
    local expires_at = start_of_request + max_age

    local response_body = cjson.decode(res.body)

    local valid_certs = {}
    for kid, cert in pairs(response_body) do
        local parsed_cert_chain, err = ssl.parse_pem_cert(cert)
        if parsed_cert_chain == nil then
            kong.log.err("Failed to parse cert ", err)
            return nil, err
        end
        valid_certs[kid] = cert
        local success, err = cache:store(generate_cache_key(config, kid), cert, expires_at)
        if not success then
            kong.log.err("Failed writing to the cache: ", err)
            return nil, err
        end
    end
    return valid_certs
end

local function get_signing_certificates(config, target_kid)
    local jwt_cache_key = generate_cache_key(config, target_kid)
    local cached_cert, err = cache:get(jwt_cache_key)
    if err then
        kong.log.err("Failed to get cached cert ", err)
        return nil, err
    end
    if cached_cert then
        local parsed_cert_chain, err = ssl.parse_pem_cert(cached_cert)
        if parsed_cert_chain == nil then
            kong.log.err("Failed to parse cert ", err)
            return nil, err
        end
        return cached_cert
    end

    -- call fetch signing certificates
    for _, url in ipairs(config.signing_urls) do
        local valid_certs, err = fetch_signing_certificates(config, url)
        if err then
            kong.log.err("Error fetching certs from ", url, ": ", err)
        else
            local parsed_cert = valid_certs[target_kid]
            if parsed_cert then
                return parsed_cert
            end
        end
    end

    kong.log.err("No certs matching kid ", target_kid, " found in the signing_urls.")
    return nil, "No matching kid found."
end

local function list_contains(haystack, needle)
    for _, hay in ipairs(haystack) do
        if hay == needle then
            return true
        end
    end
    return false
end

-- Extract JWT from request headers (Authorization, Proxy-Authorization) or query params (?jwt=)
-- Returns: jwt_token (without Bearer prefix), or nil if not found
function _M.extract_jwt_from_request()
    local authorization_value = kong.request.get_header(AUTHORIZATION)
    local proxy_authorization_value = kong.request.get_header(PROXY_AUTHORIZATION)
    local args = kong.request.get_query()
    local query_authorization_value = args["jwt"]

    if not (authorization_value or proxy_authorization_value or query_authorization_value) then
        return nil
    end

    local jwt_value
    if authorization_value then
        jwt_value = authorization_value
    elseif proxy_authorization_value then
        jwt_value = proxy_authorization_value
    else
        jwt_value = query_authorization_value
    end

    local without_bearer = string.gsub(jwt_value, "^[Bb]earer ", "")
    return without_bearer
end

-- Validate Firebase JWT: verify signature and claims
-- Returns: (true, jwt_token) on success, (false, error_response) on failure
function _M.validate_jwt(config)
    -- Clear user info headers to prevent spoofing - they will be set from valid JWT claims
    kong.service.request.set_header(TOKEN_USER_ID, nil)
    kong.service.request.set_header(TOKEN_USER_EMAIL, nil)

    local jwt_token = _M.extract_jwt_from_request()

    if not jwt_token then
        return false, { status = 401, message = "Unauthorized" }
    end

    local jwt, err = jwt_decoder:new(jwt_token)
    if err then
        kong.log("Not a valid JWT: ", err)
        return false, { status = 401, message = "Bad token" }
    end

    local kid = jwt.header.kid
    if not kid then
        return false, { status = 401, message = "Unauthorized" }
    end

    local signing_cert, err = get_signing_certificates(config, kid)
    if not signing_cert then
        kong.log.err("Failed to get signing certificate.")
        return false, { status = 401, message = "Unauthorized" }
    end

    local parsed_signing_cert, err = x509.new(signing_cert)
    if not parsed_signing_cert then
        kong.log.err("Failed to parse signing cert.")
        return false, { status = 401, message = "Unauthorized" }
    end

    if not jwt:verify_signature(parsed_signing_cert:get_pubkey():tostring()) then
        kong.log.err("Invalid signature.")
        return false, { status = 401, message = "Invalid signature" }
    end

    -- Validate token expiry
    local now = os.time()
    if jwt.claims.exp and jwt.claims.exp < now then
        kong.log("JWT has expired")
        return false, { status = 401, message = "Token expired" }
    end
    if jwt.claims.nbf and jwt.claims.nbf > now then
        kong.log("JWT not yet valid (nbf)")
        return false, { status = 401, message = "Token not yet valid" }
    end

    for _, claim_to_verify in ipairs(config.claims_to_verify) do
        local claim_in_jwt = jwt.claims[claim_to_verify.name]
        if not claim_in_jwt then
            kong.log("JWT lacks a ", claim_to_verify.name, " name.")
            return false, { status = 401, message = "Unauthorized" }
        end

        if not list_contains(claim_to_verify.allowed_values, claim_in_jwt) then
            kong.log("Disallowed value for claim ", claim_to_verify.name, ": ", claim_in_jwt)
            return false, { status = 401, message = "Unauthorized" }
        end
    end

    -- Set user info headers from JWT claims
    local set_header = kong.service.request.set_header
    if jwt.claims.sub then
        set_header(TOKEN_USER_ID, jwt.claims.sub)
    end
    if jwt.claims.email then
        set_header(TOKEN_USER_EMAIL, jwt.claims.email)
    end

    return true, jwt_token
end

return _M
