local shared = ngx.shared
local max = math.max

local _M = {}

function _M:store(key, obj, expire_at)
    local ttl = max(1, expire_at - os.time())
    local success, err = shared.remote_jwt_auth:set(key, obj, ttl)
    if success then
        return true
    else
        return nil, err
    end
end

function _M:get(key)
    local obj, err = shared.remote_jwt_auth:get(key)
    if not obj then
        if not err then
            return nil, nil
        else
            kong.log("Error when reading cache ", err)
            return nil, err
        end
    end
    return obj
end

return _M
