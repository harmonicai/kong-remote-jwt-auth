local constants = require("kong.constants")
local firebase = require("kong.plugins.remote-jwt-auth.firebase")
local cerberus = require("kong.plugins.remote-jwt-auth.cerberus")

local PubSubHandler = {
    VERSION = "2.0.3",
    PRIORITY = 1500,
}

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

    -- Validate Firebase JWT from authorization header (present for frontend requests)
    local ok, jwt_token_or_err = firebase.validate_jwt(config)

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
            return kong.response.exit(jwt_token_or_err.status, { message = jwt_token_or_err.message })
        end
    else
        local consumer_cache_key = kong.db.consumers:cache_key(config.authenticated_consumer)
        local consumer, err =
            kong.cache:get(consumer_cache_key, nil, kong.client.load_consumer, config.authenticated_consumer, true)
        if err then
            return error(err)
        end
        set_consumer(consumer, config)

        -- Fetch Cerberus JWT from backend service (only for authenticated users)
        cerberus.set_cerberus_jwt_header(config)
    end
end

return PubSubHandler
