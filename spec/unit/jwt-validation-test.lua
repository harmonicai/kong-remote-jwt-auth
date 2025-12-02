-- JWT Token Validation Tests
-- Tests actual JWT signing and validation with generated keys
-- Run with: pongo run spec/unit/jwt-validation-test.lua

local cjson = require("cjson")

-- ============================================================================
-- RSA Key and Certificate Generation Utilities
-- ============================================================================

local function generate_rsa_key_pair()
    local pkey = require("resty.openssl.pkey")
    local key, err = pkey.new({ type = "RSA", bits = 2048 })
    if not key then
        error("Failed to generate RSA key: " .. tostring(err))
    end
    return key
end

local function generate_self_signed_certificate(private_key, kid)
    local x509 = require("resty.openssl.x509")
    local name = require("resty.openssl.x509.name")

    local cert, err = x509.new()
    if not cert then
        error("Failed to create certificate: " .. tostring(err))
    end

    -- Set subject and issuer
    local subject = name.new()
    subject:add("CN", "Test JWT Signing Certificate")
    subject:add("O", "Test Organization")
    cert:set_subject_name(subject)
    cert:set_issuer_name(subject)

    -- Set validity period (1 year)
    local now = os.time()
    cert:set_not_before(now - 86400) -- Valid from yesterday
    cert:set_not_after(now + 365 * 86400) -- Valid for 1 year

    -- Set serial number
    cert:set_serial_number(require("resty.openssl.bn").new(math.random(1, 1000000)))

    -- Set public key
    cert:set_pubkey(private_key)

    -- Sign the certificate
    local ok, err = cert:sign(private_key)
    if not ok then
        error("Failed to sign certificate: " .. tostring(err))
    end

    return cert
end

-- ============================================================================
-- JWT Creation Utilities
-- ============================================================================

local function base64url_encode(input)
    local b64 = require("ngx.base64")
    local encoded = b64.encode_base64url(input)
    return encoded
end

local function base64url_decode(input)
    local b64 = require("ngx.base64")
    return b64.decode_base64url(input)
end

local function create_jwt_header(kid, alg)
    alg = alg or "RS256"
    return cjson.encode({
        alg = alg,
        typ = "JWT",
        kid = kid,
    })
end

local function create_jwt_payload(claims)
    local now = os.time()
    local default_claims = {
        iat = now,
        exp = now + 3600, -- 1 hour from now
        nbf = now - 60, -- Valid from 1 minute ago
    }

    -- Merge default claims with provided claims
    for k, v in pairs(claims or {}) do
        default_claims[k] = v
    end

    return cjson.encode(default_claims)
end

local function sign_jwt_rs256(private_key, header_b64, payload_b64)
    local digest = require("resty.openssl.digest")
    local signing_input = header_b64 .. "." .. payload_b64

    -- Create SHA256 digest and sign
    local d = digest.new("SHA256")
    d:update(signing_input)

    local signature, err = private_key:sign(d)
    if not signature then
        error("Failed to sign JWT: " .. tostring(err))
    end

    return base64url_encode(signature)
end

local function create_signed_jwt(private_key, kid, claims, alg)
    local header = create_jwt_header(kid, alg)
    local payload = create_jwt_payload(claims)

    local header_b64 = base64url_encode(header)
    local payload_b64 = base64url_encode(payload)

    local signature_b64 = sign_jwt_rs256(private_key, header_b64, payload_b64)

    return header_b64 .. "." .. payload_b64 .. "." .. signature_b64
end

-- ============================================================================
-- Mock Infrastructure
-- ============================================================================

local mock_certificates = {} -- kid -> PEM certificate string
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

-- Mock HTTP responses for certificate fetching
local mock_http_responses = {}

local function set_mock_certificate_response(url, certificates)
    -- certificates is a table of { kid = pem_cert_string, ... }
    mock_http_responses[url] = {
        status = 200,
        headers = {
            ["Cache-Control"] = "max-age=3600",
        },
        body = cjson.encode(certificates),
    }
end

local mock_http = {
    new = function()
        return {
            set_timeout = function(self, timeout) end,
            request_uri = function(self, url, options)
                local response = mock_http_responses[url]
                if response then
                    return response, nil
                end
                return nil, "No mock response for URL: " .. url
            end,
        }
    end,
}

-- Mock Kong globals
local kong_log_messages = {}
local mock_request_headers = {}
local mock_query_args = {}
local set_headers = {}

-- Helper function to concatenate args with tostring
local function concat_args(...)
    local args = { ... }
    local result = {}
    for i, v in ipairs(args) do
        result[i] = tostring(v)
    end
    return table.concat(result, "")
end

local mock_kong = {
    log = setmetatable({
        err = function(...)
            table.insert(kong_log_messages, "ERR: " .. concat_args(...))
        end,
        warn = function(...)
            table.insert(kong_log_messages, "WARN: " .. concat_args(...))
        end,
        notice = function(...) end,
        debug = function(...) end,
    }, {
        __call = function(self, ...)
            table.insert(kong_log_messages, "LOG: " .. concat_args(...))
        end,
    }),
    request = {
        get_header = function(name)
            return mock_request_headers[string.lower(name)]
        end,
        get_headers = function()
            return mock_request_headers
        end,
        get_query = function()
            return mock_query_args
        end,
    },
    service = {
        request = {
            set_header = function(name, value)
                set_headers[name] = value
            end,
        },
    },
}

-- Set up global mocks
_G.kong = mock_kong

-- ============================================================================
-- Firebase JWT Validation Logic (mirrors firebase.lua)
-- ============================================================================

local sha512 = require("resty.sha512")
local to_hex = require("resty.string").to_hex
local ssl = require("ngx.ssl")
local x509_lib = require("resty.openssl.x509")

local function generate_cache_key(config, key)
    local digest = sha512:new()
    assert(digest:update(config.cache_namespace))
    assert(digest:update(key))
    return "remote-jwt-auth:" .. to_hex(digest:final())
end

local function fetch_signing_certificates(config, url)
    local httpc = mock_http.new()
    if httpc == nil then
        kong.log.err("Failed to start a http request")
        return nil, "HTTP client error"
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
        local success, err = mock_cache:store(generate_cache_key(config, kid), cert, expires_at)
        if not success then
            kong.log.err("Failed writing to the cache: ", err)
            return nil, err
        end
    end
    return valid_certs
end

local function get_signing_certificates(config, target_kid)
    local jwt_cache_key = generate_cache_key(config, target_kid)
    local cached_cert, err = mock_cache:get(jwt_cache_key)
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

-- Validate JWT - mirrors firebase.validate_jwt
local function validate_jwt(config, jwt_token)
    if not jwt_token then
        return false, { status = 401, message = "Unauthorized" }
    end

    local jwt_decoder = require("kong.plugins.jwt.jwt_parser")
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

    local parsed_signing_cert, err = x509_lib.new(signing_cert)
    if not parsed_signing_cert then
        kong.log.err("Failed to parse signing cert.")
        return false, { status = 401, message = "Unauthorized" }
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

    -- Set user info headers from JWT claims
    if jwt.claims.sub then
        kong.service.request.set_header("X-Token-User-Id", jwt.claims.sub)
    end
    if jwt.claims.email then
        kong.service.request.set_header("X-Token-User-Email", jwt.claims.email)
    end

    return true, jwt_token
end

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

local function assert_contains(haystack, needle, message)
    if type(haystack) == "string" and string.find(haystack, needle, 1, true) then
        tests_passed = tests_passed + 1
        return true
    end
    print("   FAIL: " .. (message or "string does not contain expected value"))
    print("   Looking for: " .. tostring(needle))
    print("   In: " .. tostring(haystack))
    tests_failed = tests_failed + 1
    return false
end

local function reset_test_state()
    kong_log_messages = {}
    mock_request_headers = {}
    mock_query_args = {}
    set_headers = {}
    mock_cache:clear()
    mock_http_responses = {}
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
print("JWT Token Validation Tests")
print("==========================")
print("")

-- Generate test keys and certificates once
print("Generating test RSA key pair and certificate...")
local test_private_key = generate_rsa_key_pair()
local test_kid = "test-key-id-001"
local test_certificate = generate_self_signed_certificate(test_private_key, test_kid)
local test_cert_pem = test_certificate:to_PEM()
print("  Key and certificate generated successfully")
print("")

-- Generate a second key pair for testing wrong key scenarios
local wrong_private_key = generate_rsa_key_pair()
local wrong_kid = "wrong-key-id-002"
local wrong_certificate = generate_self_signed_certificate(wrong_private_key, wrong_kid)
local wrong_cert_pem = wrong_certificate:to_PEM()

-- Helper function to shallow copy and merge tables (replaces vim.tbl_extend)
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

-- Base config for tests
local base_config = {
    signing_urls = { "https://test.example.com/certs" },
    cache_namespace = "test-validation",
    claims_to_verify = {},
    timeout = 5000,
}

-- ============================================================================
-- Signature Validation Tests
-- ============================================================================

print("Signature Validation Tests")
print("--------------------------")

run_test("validates correctly signed JWT token", function()
    local config = tbl_extend(base_config)
    set_mock_certificate_response("https://test.example.com/certs", {
        [test_kid] = test_cert_pem,
    })

    local jwt = create_signed_jwt(test_private_key, test_kid, {
        sub = "user-123",
        email = "test@example.com",
        iss = "https://test.example.com",
        aud = "test-audience",
    })

    local ok, result = validate_jwt(config, jwt)
    assert_true(ok, "Should validate correctly signed JWT")
    assert_equals(jwt, result, "Should return the JWT token")
end)

run_test("rejects JWT signed with wrong key", function()
    local config = tbl_extend(base_config)
    -- Set up cert endpoint with CORRECT certificate
    set_mock_certificate_response("https://test.example.com/certs", {
        [test_kid] = test_cert_pem,
    })

    -- Sign JWT with WRONG private key but use the correct kid
    local jwt = create_signed_jwt(wrong_private_key, test_kid, {
        sub = "user-123",
    })

    local ok, result = validate_jwt(config, jwt)
    assert_false(ok, "Should reject JWT signed with wrong key")
    assert_equals(401, result.status, "Should return 401 status")
    assert_equals("Invalid signature", result.message, "Should return Invalid signature message")
end)

run_test("rejects JWT with unknown kid", function()
    local config = tbl_extend(base_config)
    set_mock_certificate_response("https://test.example.com/certs", {
        [test_kid] = test_cert_pem,
    })

    local jwt = create_signed_jwt(test_private_key, "unknown-kid", {
        sub = "user-123",
    })

    local ok, result = validate_jwt(config, jwt)
    assert_false(ok, "Should reject JWT with unknown kid")
    assert_equals(401, result.status, "Should return 401 status")
end)

run_test("rejects JWT with missing kid header", function()
    local config = tbl_extend(base_config)
    set_mock_certificate_response("https://test.example.com/certs", {
        [test_kid] = test_cert_pem,
    })

    -- Manually create JWT without kid
    local header = base64url_encode(cjson.encode({ alg = "RS256", typ = "JWT" }))
    local payload = base64url_encode(cjson.encode({ sub = "user-123", exp = os.time() + 3600 }))
    local signature = sign_jwt_rs256(test_private_key, header, payload)
    local jwt = header .. "." .. payload .. "." .. signature

    local ok, result = validate_jwt(config, jwt)
    assert_false(ok, "Should reject JWT without kid header")
    assert_equals(401, result.status, "Should return 401 status")
end)

run_test("rejects tampered JWT payload", function()
    local config = tbl_extend(base_config)
    set_mock_certificate_response("https://test.example.com/certs", {
        [test_kid] = test_cert_pem,
    })

    -- Create valid JWT
    local jwt = create_signed_jwt(test_private_key, test_kid, {
        sub = "user-123",
        role = "user",
    })

    -- Tamper with the payload (change role to admin)
    local parts = {}
    for part in string.gmatch(jwt, "[^.]+") do
        table.insert(parts, part)
    end

    local tampered_payload = base64url_encode(cjson.encode({
        sub = "user-123",
        role = "admin", -- Tampered!
        exp = os.time() + 3600,
        iat = os.time(),
        nbf = os.time() - 60,
    }))

    local tampered_jwt = parts[1] .. "." .. tampered_payload .. "." .. parts[3]

    local ok, result = validate_jwt(config, tampered_jwt)
    assert_false(ok, "Should reject tampered JWT")
    assert_equals(401, result.status, "Should return 401 status")
end)

-- ============================================================================
-- Claims Verification Tests
-- ============================================================================

print("Claims Verification Tests")
print("-------------------------")

run_test("validates JWT with required claim present and allowed", function()
    local config = tbl_extend(base_config, {
        claims_to_verify = {
            { name = "aud", allowed_values = { "test-audience", "other-audience" } },
        },
    })
    set_mock_certificate_response("https://test.example.com/certs", {
        [test_kid] = test_cert_pem,
    })

    local jwt = create_signed_jwt(test_private_key, test_kid, {
        sub = "user-123",
        aud = "test-audience",
    })

    local ok, result = validate_jwt(config, jwt)
    assert_true(ok, "Should validate JWT with correct claim value")
end)

run_test("rejects JWT with disallowed claim value", function()
    local config = tbl_extend(base_config, {
        claims_to_verify = {
            { name = "aud", allowed_values = { "allowed-audience" } },
        },
    })
    set_mock_certificate_response("https://test.example.com/certs", {
        [test_kid] = test_cert_pem,
    })

    local jwt = create_signed_jwt(test_private_key, test_kid, {
        sub = "user-123",
        aud = "wrong-audience",
    })

    local ok, result = validate_jwt(config, jwt)
    assert_false(ok, "Should reject JWT with disallowed claim value")
    assert_equals(401, result.status, "Should return 401 status")
end)

run_test("rejects JWT missing required claim", function()
    local config = tbl_extend(base_config, {
        claims_to_verify = {
            { name = "aud", allowed_values = { "test-audience" } },
        },
    })
    set_mock_certificate_response("https://test.example.com/certs", {
        [test_kid] = test_cert_pem,
    })

    local jwt = create_signed_jwt(test_private_key, test_kid, {
        sub = "user-123",
        -- aud claim missing
    })

    local ok, result = validate_jwt(config, jwt)
    assert_false(ok, "Should reject JWT missing required claim")
    assert_equals(401, result.status, "Should return 401 status")
end)

run_test("validates JWT with multiple claim requirements", function()
    local config = tbl_extend(base_config, {
        claims_to_verify = {
            { name = "aud", allowed_values = { "test-audience" } },
            { name = "iss", allowed_values = { "https://auth.example.com", "https://test.example.com" } },
        },
    })
    set_mock_certificate_response("https://test.example.com/certs", {
        [test_kid] = test_cert_pem,
    })

    local jwt = create_signed_jwt(test_private_key, test_kid, {
        sub = "user-123",
        aud = "test-audience",
        iss = "https://auth.example.com",
    })

    local ok, result = validate_jwt(config, jwt)
    assert_true(ok, "Should validate JWT with all required claims")
end)

run_test("rejects JWT when one of multiple claims is invalid", function()
    local config = tbl_extend(base_config, {
        claims_to_verify = {
            { name = "aud", allowed_values = { "test-audience" } },
            { name = "iss", allowed_values = { "https://auth.example.com" } },
        },
    })
    set_mock_certificate_response("https://test.example.com/certs", {
        [test_kid] = test_cert_pem,
    })

    local jwt = create_signed_jwt(test_private_key, test_kid, {
        sub = "user-123",
        aud = "test-audience", -- Valid
        iss = "https://wrong-issuer.com", -- Invalid
    })

    local ok, result = validate_jwt(config, jwt)
    assert_false(ok, "Should reject JWT with any invalid claim")
    assert_equals(401, result.status, "Should return 401 status")
end)

-- ============================================================================
-- User Headers Tests
-- ============================================================================

print("User Header Extraction Tests")
print("----------------------------")

run_test("sets X-Token-User-Id header from sub claim", function()
    local config = tbl_extend(base_config)
    set_mock_certificate_response("https://test.example.com/certs", {
        [test_kid] = test_cert_pem,
    })

    local jwt = create_signed_jwt(test_private_key, test_kid, {
        sub = "user-456",
    })

    local ok, _ = validate_jwt(config, jwt)
    assert_true(ok, "Should validate JWT")
    assert_equals("user-456", set_headers["X-Token-User-Id"], "Should set X-Token-User-Id header")
end)

run_test("sets X-Token-User-Email header from email claim", function()
    local config = tbl_extend(base_config)
    set_mock_certificate_response("https://test.example.com/certs", {
        [test_kid] = test_cert_pem,
    })

    local jwt = create_signed_jwt(test_private_key, test_kid, {
        sub = "user-789",
        email = "user@example.com",
    })

    local ok, _ = validate_jwt(config, jwt)
    assert_true(ok, "Should validate JWT")
    assert_equals("user@example.com", set_headers["X-Token-User-Email"], "Should set X-Token-User-Email header")
end)

run_test("does not set email header when email claim is missing", function()
    local config = tbl_extend(base_config)
    set_mock_certificate_response("https://test.example.com/certs", {
        [test_kid] = test_cert_pem,
    })

    local jwt = create_signed_jwt(test_private_key, test_kid, {
        sub = "user-no-email",
    })

    local ok, _ = validate_jwt(config, jwt)
    assert_true(ok, "Should validate JWT")
    assert_nil(set_headers["X-Token-User-Email"], "Should not set X-Token-User-Email when email missing")
end)

-- ============================================================================
-- Malformed Token Tests
-- ============================================================================

print("Malformed Token Tests")
print("---------------------")

run_test("rejects nil token", function()
    local config = tbl_extend(base_config)
    local ok, result = validate_jwt(config, nil)
    assert_false(ok, "Should reject nil token")
    assert_equals(401, result.status, "Should return 401 status")
end)

run_test("rejects empty string token", function()
    local config = tbl_extend(base_config)
    local ok, result = validate_jwt(config, "")
    assert_false(ok, "Should reject empty token")
    assert_equals(401, result.status, "Should return 401 status")
end)

run_test("rejects completely invalid token format", function()
    local config = tbl_extend(base_config)
    local ok, result = validate_jwt(config, "not-a-jwt")
    assert_false(ok, "Should reject invalid token format")
    assert_equals(401, result.status, "Should return 401 status")
end)

run_test("rejects token with only two parts", function()
    local config = tbl_extend(base_config)
    local ok, result = validate_jwt(config, "header.payload")
    assert_false(ok, "Should reject token with only two parts")
    assert_equals(401, result.status, "Should return 401 status")
end)

run_test("rejects token with invalid base64 encoding", function()
    local config = tbl_extend(base_config)
    local ok, result = validate_jwt(config, "!!!invalid!!!.!!!base64!!!.!!!encoding!!!")
    assert_false(ok, "Should reject token with invalid base64")
    assert_equals(401, result.status, "Should return 401 status")
end)

-- ============================================================================
-- Certificate Fetching Tests
-- ============================================================================

print("Certificate Fetching Tests")
print("--------------------------")

run_test("caches certificates after first fetch", function()
    local config = tbl_extend(base_config)
    set_mock_certificate_response("https://test.example.com/certs", {
        [test_kid] = test_cert_pem,
    })

    -- First validation - should fetch cert
    local jwt1 = create_signed_jwt(test_private_key, test_kid, { sub = "user-1" })
    local ok1, _ = validate_jwt(config, jwt1)
    assert_true(ok1, "First validation should succeed")

    -- Clear the mock response to prove cache is being used
    mock_http_responses = {}

    -- Second validation - should use cached cert
    local jwt2 = create_signed_jwt(test_private_key, test_kid, { sub = "user-2" })
    local ok2, _ = validate_jwt(config, jwt2)
    assert_true(ok2, "Second validation should succeed using cached cert")
end)

run_test("handles certificate fetch failure gracefully", function()
    local config = tbl_extend(base_config)
    -- Don't set any mock response - simulates network failure

    local jwt = create_signed_jwt(test_private_key, test_kid, { sub = "user-123" })
    local ok, result = validate_jwt(config, jwt)
    assert_false(ok, "Should fail when certificate cannot be fetched")
    assert_equals(401, result.status, "Should return 401 status")
end)

run_test("supports multiple signing URLs with fallback", function()
    local config = tbl_extend(base_config, {
        signing_urls = {
            "https://primary.example.com/certs",
            "https://secondary.example.com/certs",
        },
    })

    -- Only secondary URL has the certificate
    set_mock_certificate_response("https://secondary.example.com/certs", {
        [test_kid] = test_cert_pem,
    })

    local jwt = create_signed_jwt(test_private_key, test_kid, { sub = "user-123" })
    local ok, _ = validate_jwt(config, jwt)
    assert_true(ok, "Should find certificate from secondary URL")
end)

run_test("handles multiple key IDs from same endpoint", function()
    local config = tbl_extend(base_config)

    -- Both keys available from same endpoint
    set_mock_certificate_response("https://test.example.com/certs", {
        [test_kid] = test_cert_pem,
        [wrong_kid] = wrong_cert_pem,
    })

    -- Validate token signed with first key
    local jwt1 = create_signed_jwt(test_private_key, test_kid, { sub = "user-1" })
    local ok1, _ = validate_jwt(config, jwt1)
    assert_true(ok1, "Should validate token with first key")

    -- Validate token signed with second key
    local jwt2 = create_signed_jwt(wrong_private_key, wrong_kid, { sub = "user-2" })
    local ok2, _ = validate_jwt(config, jwt2)
    assert_true(ok2, "Should validate token with second key")
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
