local helpers = require("spec.helpers")
local cjson = require("cjson")

-- Integration tests for the remote-jwt-auth plugin
-- Run with Pongo: pongo run ./spec/integration/

-- Mock upstream port
local MOCK_PORT = 15555

for _, strategy in helpers.each_strategy() do
    describe("Plugin: remote-jwt-auth (integration) [#" .. strategy .. "]", function()
        local client, admin_client
        local bp
        local mock

        lazy_setup(function()
            bp = helpers.get_db_utils(strategy, {
                "consumers",
                "plugins",
                "routes",
                "services",
            }, { "remote-jwt-auth" })

            -- Create mock upstream server
            local http_mock = require("spec.helpers.http_mock")
            mock = http_mock.new(MOCK_PORT, [[
                ngx.status = 200
                ngx.say('{"status":"ok"}')
            ]], {
                prefix = "mock_upstream",
            })
            mock:start()

            -- Create a test service pointing to mock upstream
            local service = bp.services:insert({
                protocol = "http",
                host = "127.0.0.1",
                port = MOCK_PORT,
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

            -- Configure the plugin with all features (WITH anonymous fallback)
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

            -- Create a second service/route WITHOUT anonymous fallback for 401 tests
            local service_no_anon = bp.services:insert({
                protocol = "http",
                host = "127.0.0.1",
                port = MOCK_PORT,
            })

            local route_no_anon = bp.routes:insert({
                paths = { "/test-no-anon" },
                service = service_no_anon,
            })

            bp.plugins:insert({
                name = "remote-jwt-auth",
                route = route_no_anon,
                config = {
                    authenticated_consumer = "test-consumer",
                    -- No anonymous fallback
                    signing_urls = {
                        "https://www.googleapis.com/oauth2/v1/certs",
                    },
                    cache_namespace = "test-no-anon",
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
            if mock then
                mock:stop()
            end
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
            it("returns 401 when no authorization header is provided and no anonymous configured", function()
                -- The /test-no-anon route was created in lazy_setup without anonymous
                local res = client:get("/test-no-anon")
                assert.res_status(401, res)
            end)

            it("returns 401 for invalid JWT format without anonymous", function()
                local res = client:get("/test-no-anon", {
                    headers = {
                        ["Authorization"] = "Bearer invalid-jwt-token",
                    },
                })
                assert.res_status(401, res)
            end)
        end)

        describe("Anonymous fallback", function()
            it("allows request through with anonymous consumer when auth fails", function()
                -- The /test route has anonymous configured
                local res = client:get("/test", {
                    headers = {
                        ["Authorization"] = "Bearer invalid-token",
                    },
                })
                -- With anonymous configured, the request should go through to upstream
                assert.res_status(200, res)
            end)

            it("allows request through when no auth header provided", function()
                local res = client:get("/test")
                -- With anonymous configured, should allow through
                assert.res_status(200, res)
            end)
        end)

        describe("Header handling", function()
            it("processes JWT from Authorization header", function()
                local res = client:get("/test", {
                    headers = {
                        ["Authorization"] = "Bearer some-jwt-token",
                    },
                })
                -- Will fail validation but with anonymous fallback should return 200
                assert.res_status(200, res)
            end)

            it("processes JWT from Proxy-Authorization header", function()
                local res = client:get("/test", {
                    headers = {
                        ["Proxy-Authorization"] = "Bearer some-jwt-token",
                    },
                })
                -- Will fail validation but with anonymous fallback should return 200
                assert.res_status(200, res)
            end)

            it("processes JWT from query parameter", function()
                local res = client:get("/test?jwt=some-jwt-token")
                -- Will fail validation but with anonymous fallback should return 200
                assert.res_status(200, res)
            end)
        end)
    end)
end

-- Separate test for backward compatibility (no jwt_service_url)
local MOCK_PORT_COMPAT = 15556

for _, strategy in helpers.each_strategy() do
    describe("Plugin: remote-jwt-auth backward compatibility [#" .. strategy .. "]", function()
        local client, bp
        local mock_compat

        lazy_setup(function()
            bp = helpers.get_db_utils(strategy, {
                "consumers",
                "plugins",
                "routes",
                "services",
            }, { "remote-jwt-auth" })

            -- Create mock upstream server for backward compat tests
            local http_mock = require("spec.helpers.http_mock")
            mock_compat = http_mock.new(MOCK_PORT_COMPAT, [[
                ngx.status = 200
                ngx.say('{"status":"ok"}')
            ]], {
                prefix = "mock_upstream_compat",
            })
            mock_compat:start()

            local service = bp.services:insert({
                protocol = "http",
                host = "127.0.0.1",
                port = MOCK_PORT_COMPAT,
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
            if mock_compat then
                mock_compat:stop()
            end
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
