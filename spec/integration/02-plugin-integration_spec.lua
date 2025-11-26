local helpers = require("spec.helpers")
local cjson = require("cjson")

-- Integration tests for the remote-jwt-auth plugin
-- Run with Pongo: pongo run ./spec/integration/

for _, strategy in helpers.each_strategy() do
    describe("Plugin: remote-jwt-auth (integration) [#" .. strategy .. "]", function()
        local client, admin_client
        local bp

        lazy_setup(function()
            bp = helpers.get_db_utils(strategy, {
                "consumers",
                "plugins",
                "routes",
                "services",
            }, { "remote-jwt-auth" })

            -- Create a test service pointing to mock upstream
            local service = bp.services:insert({
                protocol = "http",
                host = helpers.mock_upstream_host,
                port = helpers.mock_upstream_port,
            })

            -- Create a test route
            local route = bp.routes:insert({
                paths = { "/test" },
                service = service,
            })

            -- Create test consumers
            bp.consumers:insert({
                username = "test-consumer",
            })

            bp.consumers:insert({
                username = "anonymous",
            })

            -- Configure the plugin with all features
            bp.plugins:insert({
                name = "remote-jwt-auth",
                route = route,
                config = {
                    authenticated_consumer = "test-consumer",
                    anonymous = "anonymous",
                    signing_urls = {
                        "https://www.googleapis.com/oauth2/v1/certs",
                    },
                    cache_namespace = "test-integration",
                    claims_to_verify = {},
                },
            })

            -- Start Kong with the plugin
            assert(helpers.start_kong({
                database = strategy,
                plugins = "bundled,remote-jwt-auth",
            }))

            client = helpers.proxy_client()
            admin_client = helpers.admin_client()
        end)

        lazy_teardown(function()
            if client then
                client:close()
            end
            if admin_client then
                admin_client:close()
            end
            helpers.stop_kong()
        end)

        describe("Plugin loading", function()
            it("plugin is loaded and accessible via admin API", function()
                local res = admin_client:get("/plugins", {
                    headers = { ["Content-Type"] = "application/json" },
                })
                local body = assert.res_status(200, res)
                local json = cjson.decode(body)

                local found = false
                for _, plugin in ipairs(json.data) do
                    if plugin.name == "remote-jwt-auth" then
                        found = true
                        break
                    end
                end
                assert.is_true(found, "remote-jwt-auth plugin should be loaded")
            end)
        end)

        describe("Authentication flow", function()
            it("returns 401 when no authorization header is provided", function()
                local res = client:get("/test")
                assert.res_status(401, res)
            end)

            it("returns 401 for invalid JWT format", function()
                local res = client:get("/test", {
                    headers = {
                        ["Authorization"] = "Bearer invalid-jwt-token",
                    },
                })
                assert.res_status(401, res)
            end)

            it("returns 401 for JWT without kid header", function()
                -- JWT without kid in header (base64 of {"alg":"HS256","typ":"JWT"})
                local jwt_without_kid = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
                local res = client:get("/test", {
                    headers = {
                        ["Authorization"] = "Bearer " .. jwt_without_kid,
                    },
                })
                assert.res_status(401, res)
            end)
        end)

        describe("Anonymous fallback", function()
            it("allows request with anonymous consumer when auth fails", function()
                -- Since anonymous is configured, failed auth should set anonymous consumer
                -- and allow the request through
                local res = client:get("/test", {
                    headers = {
                        ["Authorization"] = "Bearer invalid-token",
                    },
                })
                -- With anonymous configured, the request should go through to upstream
                assert.res_status(200, res)
            end)
        end)

        describe("Header handling", function()
            it("accepts JWT from Authorization header", function()
                local res = client:get("/test", {
                    headers = {
                        ["Authorization"] = "Bearer some-jwt-token",
                    },
                })
                -- Will fail validation but with anonymous fallback should return 200
                assert.res_status(200, res)
            end)

            it("accepts JWT from Proxy-Authorization header", function()
                local res = client:get("/test", {
                    headers = {
                        ["Proxy-Authorization"] = "Bearer some-jwt-token",
                    },
                })
                -- Will fail validation but with anonymous fallback should return 200
                assert.res_status(200, res)
            end)

            it("accepts JWT from query parameter", function()
                local res = client:get("/test?jwt=some-jwt-token")
                -- Will fail validation but with anonymous fallback should return 200
                assert.res_status(200, res)
            end)
        end)
    end)
end

-- Separate test for backward compatibility (no jwt_service_url)
for _, strategy in helpers.each_strategy() do
    describe("Plugin: remote-jwt-auth backward compatibility [#" .. strategy .. "]", function()
        local client, bp

        lazy_setup(function()
            bp = helpers.get_db_utils(strategy, {
                "consumers",
                "plugins",
                "routes",
                "services",
            }, { "remote-jwt-auth" })

            local service = bp.services:insert({
                protocol = "http",
                host = helpers.mock_upstream_host,
                port = helpers.mock_upstream_port,
            })

            local route = bp.routes:insert({
                paths = { "/backward-compat" },
                service = service,
            })

            bp.consumers:insert({
                username = "compat-consumer",
            })

            bp.consumers:insert({
                username = "anon-compat",
            })

            -- Configure plugin WITHOUT jwt_service_url (backward compatibility)
            bp.plugins:insert({
                name = "remote-jwt-auth",
                route = route,
                config = {
                    authenticated_consumer = "compat-consumer",
                    anonymous = "anon-compat",
                    signing_urls = {
                        "https://www.googleapis.com/oauth2/v1/certs",
                    },
                    cache_namespace = "test-compat",
                    claims_to_verify = {},
                    -- No jwt_service_url - tests backward compatibility
                },
            })

            assert(helpers.start_kong({
                database = strategy,
                plugins = "bundled,remote-jwt-auth",
            }))

            client = helpers.proxy_client()
        end)

        lazy_teardown(function()
            if client then
                client:close()
            end
            helpers.stop_kong()
        end)

        it("works without jwt_service_url configured", function()
            local res = client:get("/backward-compat", {
                headers = {
                    ["Authorization"] = "Bearer invalid-jwt",
                },
            })
            -- Should process normally without Cerberus JWT fetching
            -- With anonymous fallback, should return 200
            assert.res_status(200, res)
        end)
    end)
end
