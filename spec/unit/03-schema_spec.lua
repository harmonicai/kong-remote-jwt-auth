local schema_def = require("kong.plugins.remote-jwt-auth.schema")
local validate_entity = require("spec.helpers").validate_plugin_config_schema

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
            assert.matches("authenticated_consumer", err)
        end)

        it("rejects invalid jwt_service_url type", function()
            local config = {
                authenticated_consumer = "test-consumer",
                jwt_service_url = 12345, -- should be string
            }
            local ok, err = validate_entity(config, schema_def)
            assert.falsy(ok)
            assert.matches("jwt_service_url", err)
        end)

        it("rejects invalid jwt_service_timeout type", function()
            local config = {
                authenticated_consumer = "test-consumer",
                jwt_service_timeout = "not-a-number", -- should be number
            }
            local ok, err = validate_entity(config, schema_def)
            assert.falsy(ok)
            assert.matches("jwt_service_timeout", err)
        end)

        it("accepts empty jwt_service_url string", function()
            local config = {
                authenticated_consumer = "test-consumer",
                jwt_service_url = "",
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
            assert.matches("signing_urls", err)
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
            assert.matches("name", err)
        end)
    end)

    describe("default values", function()
        it("uses default jwt_service_timeout when not specified", function()
            local config = {
                authenticated_consumer = "test-consumer",
                jwt_service_url = "https://backend.example.com/get-jwt",
            }
            local ok, processed_config = validate_entity(config, schema_def)
            assert.truthy(ok)
            assert.equals(5000, processed_config.jwt_service_timeout)
        end)

        it("preserves original default values", function()
            local config = {
                authenticated_consumer = "test-consumer",
            }
            local ok, processed_config = validate_entity(config, schema_def)
            assert.truthy(ok)
            assert.equals("remote-jwt-auth", processed_config.cache_namespace)
            assert.equals(10000, processed_config.timeout)
            assert.same({ "jwt" }, processed_config.uri_param_names)
            assert.same({}, processed_config.claims_to_verify)
            assert.same({}, processed_config.signing_urls)
        end)
    end)
end)
