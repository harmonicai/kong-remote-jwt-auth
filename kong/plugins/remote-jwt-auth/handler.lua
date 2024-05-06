local http = require("resty.http")
local cjson = require("cjson")
local ssl = require("ngx.ssl")
local x509 = require("resty.openssl.x509")
local sha512 = require("resty.sha512")
local to_hex = require("resty.string").to_hex
local constants = require("kong.constants")
local jwt_decoder = require("kong.plugins.jwt.jwt_parser")
local cache = require("kong.plugins.remote-jwt-auth.cache")
local assert = assert

local PubSubHandler = {
    VERSION = "1.0.0",
    PRIORITY = 1500,
}

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

local function do_authentication(config)
    -- If both headers are missing, return 401
    local authorization_value = kong.request.get_header(AUTHORIZATION)
    local proxy_authorization_value = kong.request.get_header(PROXY_AUTHORIZATION)
    -- local args = kong.request.get_query()
    -- local query_authorization_value = args and args["jwt"]

    if not (authorization_value or proxy_authorization_value or query_authorization_value) then
        return false,
            {
                status = 401,
                message = "Unauthorized",
                headers = {
                    ["WWW-Authenticate"] = realm,
                },
            }
    end

    local jwt_value = authorization_value and authorization_value or proxy_authorization_value
    -- if (authorization_value) then
    --     jwt_value = authorization_value
    -- elseif (proxy_authorization_value) then
    --     jwt_value = proxy_authorization_value
    -- else
    --     jwt_value = query_authorization_value
    -- end
    local without_bearer = string.gsub(jwt_value, "^[Bb]earer ", "")
    local jwt, err = jwt_decoder:new(without_bearer)
    if err then
        kong.log("Not a valid JWT: ", err)
        return false, { status = 401, message = "Bad token" }
    end
    local kid = jwt.header.kid
    if not kid then
        return false,
            {
                status = 401,
                message = "Unauthorized",
                headers = {
                    ["WWW-Authenticate"] = realm,
                },
            }
    end

    local signing_cert, err = get_signing_certificates(config, kid)
    if not signing_cert then
        kong.log.err("Failed to get signing certificate.")
        return false,
            {
                status = 401,
                message = "Unauthorized",
                headers = {
                    ["WWW-Authenticate"] = realm,
                },
            }
    end

    local parsed_signing_cert, err = x509.new(signing_cert)
    if not parsed_signing_cert then
        kong.log.err("Failed to parse signing cert.")
        return false,
            {
                status = 401,
                message = "Unauthorized",
                headers = {
                    ["WWW-Authenticate"] = realm,
                },
            }
    end

    if not jwt:verify_signature(parsed_signing_cert:get_pubkey():tostring()) then
        kong.log.err("Invalid signature.")
        return false, { status = 401, message = "Invalid signature" }
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

    local set_header = kong.service.request.set_header
    local pl_sub = jwt.claims.sub
    if pl_sub then
        set_header(TOKEN_USER_ID, pl_sub)
    end

    local user_email = jwt.claims.email
    if user_email then
        set_header(TOKEN_USER_EMAIL, user_email)
    end

    return true
end

local function set_consumer(consumer, config)
    if not consumer or consumer.username == config.anonymous then
        kong.client.authenticate(consumer)
    else
        kong.client.authenticate(consumer, {})
    end

    local set_header = kong.service.request.set_header
    local clear_header = kong.service.request.clear_header

    if consumer and consumer.id then
        set_header(constants.HEADERS.CONSUMER_ID, consumer.id)
    else
        clear_header(constants.HEADERS.CONSUMER_ID)
    end

    if consumer and consumer.custom_id then
        set_header(constants.HEADERS.CONSUMER_CUSTOM_ID, consumer.custom_id)
    else
        clear_header(constants.HEADERS.CONSUMER_CUSTOM_ID)
    end

    if consumer and consumer.username then
        set_header(constants.HEADERS.CONSUMER_USERNAME, consumer.username)
    else
        clear_header(constants.HEADERS.CONSUMER_USERNAME)
    end

    if not consumer or consumer.username == config.anonymous then
        set_header(constants.HEADERS.ANONYMOUS, true)
    else
        clear_header(constants.HEADERS.ANONYMOUS)
    end
end

function PubSubHandler:access(config)
    if config.anonymous and kong.client.get_credential() then
        -- we're already authenticated, and we're configured for using anonymous,
        -- hence we're in a logical OR between auth methods and we're already done.
        return
    end

    local ok, err = do_authentication(config)
    if not ok then
        if config.anonymous then
            -- get anonymous user
            local consumer_cache_key = kong.db.consumers:cache_key(config.anonymous)
            local consumer, err =
                kong.cache:get(consumer_cache_key, nil, kong.client.load_consumer, config.anonymous, true)
            if err then
                return error(err)
            end

            set_consumer(consumer, config)
        else
            return kong.response.exit(err.status, { message = err.message })
        end
    else
        local consumer_cache_key = kong.db.consumers:cache_key(config.authenticated_consumer)
        local consumer, err =
            kong.cache:get(consumer_cache_key, nil, kong.client.load_consumer, config.authenticated_consumer, true)
        if err then
            return error(err)
        end
        set_consumer(consumer, config)
    end
end

return PubSubHandler
