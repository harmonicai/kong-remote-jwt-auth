-- JWT Token Validation Tests
-- Tests actual JWT signing and validation with generated keys
-- Run with: pongo run spec/unit/jwt-validation-test.lua
--
-- This test imports the REAL firebase.lua module and mocks only the external
-- dependencies (HTTP client, cache, Kong globals) to test actual validation logic.

local cjson = require("cjson")

-- ============================================================================
-- Mock Infrastructure (must be set up BEFORE requiring firebase.lua)
-- ============================================================================

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

-- Mock HTTP client (resty.http)
package.loaded["resty.http"] = {
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

_G.kong = {
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
            clear_header = function(name)
                set_headers[name] = nil
            end,
        },
    },
}

-- ============================================================================
-- Now require the REAL firebase module (after mocks are set up)
-- ============================================================================

local firebase = require("kong.plugins.remote-jwt-auth.firebase")

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

-- Helper to set up mock request with JWT in Authorization header
local function set_mock_request_jwt(jwt_token)
    mock_request_headers["authorization"] = "Bearer " .. jwt_token
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
    set_mock_request_jwt(jwt)

    local ok, result = firebase.validate_jwt(config)
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
    set_mock_request_jwt(jwt)

    local ok, result = firebase.validate_jwt(config)
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
    set_mock_request_jwt(jwt)

    local ok, result = firebase.validate_jwt(config)
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
    set_mock_request_jwt(jwt)

    local ok, result = firebase.validate_jwt(config)
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
    set_mock_request_jwt(tampered_jwt)

    local ok, result = firebase.validate_jwt(config)
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
    set_mock_request_jwt(jwt)

    local ok, result = firebase.validate_jwt(config)
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
    set_mock_request_jwt(jwt)

    local ok, result = firebase.validate_jwt(config)
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
    set_mock_request_jwt(jwt)

    local ok, result = firebase.validate_jwt(config)
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
    set_mock_request_jwt(jwt)

    local ok, result = firebase.validate_jwt(config)
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
    set_mock_request_jwt(jwt)

    local ok, result = firebase.validate_jwt(config)
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
    set_mock_request_jwt(jwt)

    local ok, _ = firebase.validate_jwt(config)
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
    set_mock_request_jwt(jwt)

    local ok, _ = firebase.validate_jwt(config)
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
    set_mock_request_jwt(jwt)

    local ok, _ = firebase.validate_jwt(config)
    assert_true(ok, "Should validate JWT")
    assert_nil(set_headers["X-Token-User-Email"], "Should not set X-Token-User-Email when email missing")
end)

run_test("clears spoofed user headers on validation failure", function()
    local config = tbl_extend(base_config)
    -- Pre-set spoofed headers (simulating malicious client)
    set_headers["X-Token-User-Id"] = "spoofed-admin"
    set_headers["X-Token-User-Email"] = "admin@evil.com"

    -- Don't set any mock cert response - validation will fail
    set_mock_request_jwt("invalid-token")

    local ok, result = firebase.validate_jwt(config)
    assert_false(ok, "Should reject invalid token")
    assert_nil(set_headers["X-Token-User-Id"], "Should clear spoofed user ID")
    assert_nil(set_headers["X-Token-User-Email"], "Should clear spoofed email")
end)

-- ============================================================================
-- Token Expiry Tests
-- ============================================================================

print("Token Expiry Tests")
print("------------------")

run_test("rejects expired JWT token", function()
    local config = tbl_extend(base_config)
    set_mock_certificate_response("https://test.example.com/certs", {
        [test_kid] = test_cert_pem,
    })

    local jwt = create_signed_jwt(test_private_key, test_kid, {
        sub = "user-123",
        exp = os.time() - 3600, -- Expired 1 hour ago
    })
    set_mock_request_jwt(jwt)

    local ok, result = firebase.validate_jwt(config)
    assert_false(ok, "Should reject expired JWT")
    assert_equals(401, result.status, "Should return 401 status")
    assert_equals("Token expired", result.message, "Should return Token expired message")
end)

run_test("accepts JWT that has not yet expired", function()
    local config = tbl_extend(base_config)
    set_mock_certificate_response("https://test.example.com/certs", {
        [test_kid] = test_cert_pem,
    })

    local jwt = create_signed_jwt(test_private_key, test_kid, {
        sub = "user-123",
        exp = os.time() + 3600, -- Expires in 1 hour
    })
    set_mock_request_jwt(jwt)

    local ok, _ = firebase.validate_jwt(config)
    assert_true(ok, "Should accept non-expired JWT")
end)

run_test("rejects JWT with nbf in the future", function()
    local config = tbl_extend(base_config)
    set_mock_certificate_response("https://test.example.com/certs", {
        [test_kid] = test_cert_pem,
    })

    local jwt = create_signed_jwt(test_private_key, test_kid, {
        sub = "user-123",
        nbf = os.time() + 3600, -- Not valid until 1 hour from now
    })
    set_mock_request_jwt(jwt)

    local ok, result = firebase.validate_jwt(config)
    assert_false(ok, "Should reject JWT with future nbf")
    assert_equals(401, result.status, "Should return 401 status")
    assert_equals("Token not yet valid", result.message, "Should return Token not yet valid message")
end)

run_test("accepts JWT with nbf in the past", function()
    local config = tbl_extend(base_config)
    set_mock_certificate_response("https://test.example.com/certs", {
        [test_kid] = test_cert_pem,
    })

    local jwt = create_signed_jwt(test_private_key, test_kid, {
        sub = "user-123",
        nbf = os.time() - 3600, -- Valid since 1 hour ago
    })
    set_mock_request_jwt(jwt)

    local ok, _ = firebase.validate_jwt(config)
    assert_true(ok, "Should accept JWT with past nbf")
end)

run_test("accepts JWT without exp claim", function()
    local config = tbl_extend(base_config)
    set_mock_certificate_response("https://test.example.com/certs", {
        [test_kid] = test_cert_pem,
    })

    -- Create JWT without exp claim by overriding defaults
    local header = base64url_encode(cjson.encode({ alg = "RS256", typ = "JWT", kid = test_kid }))
    local payload = base64url_encode(cjson.encode({
        sub = "user-123",
        iat = os.time(),
        -- No exp claim
    }))
    local signature = sign_jwt_rs256(test_private_key, header, payload)
    local jwt = header .. "." .. payload .. "." .. signature
    set_mock_request_jwt(jwt)

    local ok, _ = firebase.validate_jwt(config)
    assert_true(ok, "Should accept JWT without exp claim")
end)

-- ============================================================================
-- Malformed Token Tests
-- ============================================================================

print("Malformed Token Tests")
print("---------------------")

run_test("rejects when no token provided", function()
    local config = tbl_extend(base_config)
    -- Don't set any Authorization header
    mock_request_headers = {}

    local ok, result = firebase.validate_jwt(config)
    assert_false(ok, "Should reject when no token")
    assert_equals(401, result.status, "Should return 401 status")
end)

run_test("rejects completely invalid token format", function()
    local config = tbl_extend(base_config)
    set_mock_request_jwt("not-a-jwt")

    local ok, result = firebase.validate_jwt(config)
    assert_false(ok, "Should reject invalid token format")
    assert_equals(401, result.status, "Should return 401 status")
end)

run_test("rejects token with only two parts", function()
    local config = tbl_extend(base_config)
    set_mock_request_jwt("header.payload")

    local ok, result = firebase.validate_jwt(config)
    assert_false(ok, "Should reject token with only two parts")
    assert_equals(401, result.status, "Should return 401 status")
end)

run_test("rejects token with invalid base64 encoding", function()
    local config = tbl_extend(base_config)
    set_mock_request_jwt("!!!invalid!!!.!!!base64!!!.!!!encoding!!!")

    local ok, result = firebase.validate_jwt(config)
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
    set_mock_request_jwt(jwt1)
    local ok1, _ = firebase.validate_jwt(config)
    assert_true(ok1, "First validation should succeed")

    -- Clear the mock response to prove cache is being used
    mock_http_responses = {}

    -- Second validation - should use cached cert
    local jwt2 = create_signed_jwt(test_private_key, test_kid, { sub = "user-2" })
    set_mock_request_jwt(jwt2)
    local ok2, _ = firebase.validate_jwt(config)
    assert_true(ok2, "Second validation should succeed using cached cert")
end)

run_test("handles certificate fetch failure gracefully", function()
    local config = tbl_extend(base_config)
    -- Don't set any mock response - simulates network failure

    local jwt = create_signed_jwt(test_private_key, test_kid, { sub = "user-123" })
    set_mock_request_jwt(jwt)

    local ok, result = firebase.validate_jwt(config)
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
    set_mock_request_jwt(jwt)

    local ok, _ = firebase.validate_jwt(config)
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
    set_mock_request_jwt(jwt1)
    local ok1, _ = firebase.validate_jwt(config)
    assert_true(ok1, "Should validate token with first key")

    -- Clear cache to force re-fetch for second key
    mock_cache:clear()

    -- Validate token signed with second key
    local jwt2 = create_signed_jwt(wrong_private_key, wrong_kid, { sub = "user-2" })
    set_mock_request_jwt(jwt2)
    local ok2, _ = firebase.validate_jwt(config)
    assert_true(ok2, "Should validate token with second key")
end)

-- ============================================================================
-- JWT Extraction Tests
-- ============================================================================

print("JWT Extraction Tests")
print("--------------------")

run_test("extracts JWT from Authorization header with Bearer prefix", function()
    local config = tbl_extend(base_config)
    set_mock_certificate_response("https://test.example.com/certs", {
        [test_kid] = test_cert_pem,
    })

    local jwt = create_signed_jwt(test_private_key, test_kid, { sub = "user-auth" })
    mock_request_headers["authorization"] = "Bearer " .. jwt

    local ok, _ = firebase.validate_jwt(config)
    assert_true(ok, "Should extract JWT from Authorization header")
end)

run_test("extracts JWT from Proxy-Authorization header", function()
    local config = tbl_extend(base_config)
    set_mock_certificate_response("https://test.example.com/certs", {
        [test_kid] = test_cert_pem,
    })

    local jwt = create_signed_jwt(test_private_key, test_kid, { sub = "user-proxy" })
    mock_request_headers["proxy-authorization"] = "Bearer " .. jwt

    local ok, _ = firebase.validate_jwt(config)
    assert_true(ok, "Should extract JWT from Proxy-Authorization header")
end)

run_test("extracts JWT from query parameter", function()
    local config = tbl_extend(base_config)
    set_mock_certificate_response("https://test.example.com/certs", {
        [test_kid] = test_cert_pem,
    })

    local jwt = create_signed_jwt(test_private_key, test_kid, { sub = "user-query" })
    mock_query_args["jwt"] = jwt

    local ok, _ = firebase.validate_jwt(config)
    assert_true(ok, "Should extract JWT from query parameter")
end)

run_test("prefers Authorization header over Proxy-Authorization", function()
    local config = tbl_extend(base_config)
    set_mock_certificate_response("https://test.example.com/certs", {
        [test_kid] = test_cert_pem,
    })

    local jwt_auth = create_signed_jwt(test_private_key, test_kid, { sub = "user-auth-header" })
    local jwt_proxy = create_signed_jwt(test_private_key, test_kid, { sub = "user-proxy-header" })

    mock_request_headers["authorization"] = "Bearer " .. jwt_auth
    mock_request_headers["proxy-authorization"] = "Bearer " .. jwt_proxy

    local ok, _ = firebase.validate_jwt(config)
    assert_true(ok, "Should validate successfully")
    assert_equals("user-auth-header", set_headers["X-Token-User-Id"], "Should use Authorization header JWT")
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
