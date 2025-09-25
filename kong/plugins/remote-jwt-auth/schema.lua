local typedefs = require("kong.db.schema.typedefs")

return {
    name = "remote-jwt-auth",
    fields = {
        {
            consumer = typedefs.no_consumer,
        },
        {
            protocols = typedefs.protocols_http,
        },
        {
            config = {
                type = "record",
                fields = {
                    { anonymous = { type = "string" } },
                    { authenticated_consumer = { type = "string", required = true } },
                    {
                        uri_param_names = {
                            type = "set",
                            elements = { type = "string" },
                            default = { "jwt" },
                        },
                    },
                    {
                        signing_urls = {
                            type = "array",
                            elements = { type = "string" },
                            default = {
                                -- Pub/Sub:
                                -- "https://www.googleapis.com/oauth2/v1/certs",
                                --
                                -- Firebase:
                                -- "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com",
                            },
                        },
                    },
                    {
                        cache_namespace = {
                            type = "string",
                            required = true,
                            default = "remote-jwt-auth",
                        },
                    },
                    {
                        claims_to_verify = {
                            type = "array",
                            elements = {
                                type = "record",
                                fields = {
                                    {
                                        name = {
                                            type = "string",
                                            required = true,
                                        },
                                    },
                                    {
                                        allowed_values = {
                                            type = "array",
                                            required = true,
                                            elements = { type = "string" },
                                        },
                                    },
                                },
                            },
                            default = {},
                        },
                    },
                    { timeout = { type = "number", default = 10000 } },
                    {
                        jwt_service_url = {
                            type = "string",
                            required = false,
                        },
                    },
                    {
                        jwt_service_timeout = {
                            type = "number",
                            default = 5000,
                        },
                    },
                },
            },
        },
    },
}
