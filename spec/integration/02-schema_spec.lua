local schema_def = require("kong.plugins.remote-jwt-auth.schema")
local validate_entity = require("spec.helpers").validate_plugin_config_schema
local cjson = require("cjson")

-- Helper to convert error table to string for pattern matching
local function err_to_string(err)
    if type(err) == "string" then
        return err
    elseif type(err) == "table" then
        return cjson.encode(err)
    end
    return tostring(err)
end

describe("Plugin: remote-jwt-auth (schema)", function()
    describe("schema validation", function()
        it("validates a minimal valid configuration", function()
            local config = {
                authenticated_consumer = "test-consumer",
            }
            local ok, err = validate_entity(config, schema_def)
            assert.truthy(ok)
            assert.is_nil(err)
        end)

        it("validates configuration with all original fields", function()
            local config = {
                authenticated_consumer = "test-consumer",
                anonymous = "anonymous-consumer",
                signing_urls = {
                    "https://www.googleapis.com/oauth2/v1/certs",
                    "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com",
                },
                cache_namespace = "custom-namespace",
                claims_to_verify = {
                    {
                        name = "iss",
                        allowed_values = { "expected-issuer" },
                    },
                    {
                        name = "aud",
                        allowed_values = { "expected-audience" },
                    },
                },
                timeout = 15000,
            }
            local ok, err = validate_entity(config, schema_def)
            assert.truthy(ok)
            assert.is_nil(err)
        end)

        it("validates configuration with new JWT service fields", function()
            local config = {
                authenticated_consumer = "test-consumer",
                jwt_service_url = "https://backend.example.com/get-jwt",
                jwt_service_timeout = 3000,
            }
            local ok, err = validate_entity(config, schema_def)
            assert.truthy(ok)
            assert.is_nil(err)
        end)

        it("validates configuration with all fields including JWT service", function()
            local config = {
                authenticated_consumer = "test-consumer",
                anonymous = "anonymous-consumer",
                signing_urls = {
                    "https://www.googleapis.com/oauth2/v1/certs",
                },
                cache_namespace = "full-config-test",
                claims_to_verify = {
                    {
                        name = "iss",
                        allowed_values = { "test-issuer" },
                    },
                },
                timeout = 10000,
                jwt_service_url = "https://backend.example.com/get-jwt",
                jwt_service_timeout = 5000,
            }
            local ok, err = validate_entity(config, schema_def)
            assert.truthy(ok)
            assert.is_nil(err)
        end)

        it("accepts configuration with jwt_service_url but no jwt_service_timeout (uses default)", function()
            local config = {
                authenticated_consumer = "test-consumer",
                jwt_service_url = "https://backend.example.com/get-jwt",
            }
            local ok, err = validate_entity(config, schema_def)
            assert.truthy(ok)
            assert.is_nil(err)
        end)

        it("accepts configuration with jwt_service_timeout but no jwt_service_url", function()
            local config = {
                authenticated_consumer = "test-consumer",
                jwt_service_timeout = 8000,
            }
            local ok, err = validate_entity(config, schema_def)
            assert.truthy(ok)
            assert.is_nil(err)
        end)

        it("rejects configuration without authenticated_consumer", function()
            local config = {
                jwt_service_url = "https://backend.example.com/get-jwt",
            }
            local ok, err = validate_entity(config, schema_def)
            assert.falsy(ok)
            assert.matches("authenticated_consumer", err_to_string(err))
        end)

        it("rejects invalid jwt_service_url type", function()
            local config = {
                authenticated_consumer = "test-consumer",
                jwt_service_url = 12345, -- should be string
            }
            local ok, err = validate_entity(config, schema_def)
            assert.falsy(ok)
            assert.matches("jwt_service_url", err_to_string(err))
        end)

        it("rejects invalid jwt_service_timeout type", function()
            local config = {
                authenticated_consumer = "test-consumer",
                jwt_service_timeout = "not-a-number", -- should be number
            }
            local ok, err = validate_entity(config, schema_def)
            assert.falsy(ok)
            assert.matches("jwt_service_timeout", err_to_string(err))
        end)

        it("accepts nil jwt_service_url (optional field)", function()
            local config = {
                authenticated_consumer = "test-consumer",
                -- jwt_service_url not provided (nil)
            }
            local ok, err = validate_entity(config, schema_def)
            assert.truthy(ok)
            assert.is_nil(err)
        end)

        it("validates that original schema fields still work", function()
            local config = {
                authenticated_consumer = "test-consumer",
                signing_urls = "not-an-array", -- should be array
            }
            local ok, err = validate_entity(config, schema_def)
            assert.falsy(ok)
            assert.matches("signing_urls", err_to_string(err))
        end)

        it("validates claims_to_verify structure with new fields present", function()
            local config = {
                authenticated_consumer = "test-consumer",
                jwt_service_url = "https://backend.example.com/get-jwt",
                claims_to_verify = {
                    {
                        name = "iss",
                        allowed_values = { "test-issuer" },
                    },
                    {
                        -- missing name field - should fail
                        allowed_values = { "test-value" },
                    },
                },
            }
            local ok, err = validate_entity(config, schema_def)
            assert.falsy(ok)
            assert.matches("name", err_to_string(err))
        end)
    end)

    describe("default values", function()
        -- Test default values by checking the schema definition directly
        local function get_field_default(field_name)
            for _, field in ipairs(schema_def.fields) do
                if field.config then
                    for _, config_field in ipairs(field.config.fields) do
                        if config_field[field_name] then
                            return config_field[field_name].default
                        end
                    end
                end
            end
            return nil
        end

        it("has correct default for jwt_service_timeout", function()
            local default = get_field_default("jwt_service_timeout")
            assert.equals(5000, default)
        end)

        it("has correct default for cache_namespace", function()
            local default = get_field_default("cache_namespace")
            assert.equals("remote-jwt-auth", default)
        end)

        it("has correct default for timeout", function()
            local default = get_field_default("timeout")
            assert.equals(10000, default)
        end)

        it("has correct default for uri_param_names", function()
            local default = get_field_default("uri_param_names")
            assert.same({ "jwt" }, default)
        end)

        it("has correct default for claims_to_verify", function()
            local default = get_field_default("claims_to_verify")
            assert.same({}, default)
        end)

        it("has correct default for signing_urls", function()
            local default = get_field_default("signing_urls")
            assert.same({}, default)
        end)
    end)
end)
