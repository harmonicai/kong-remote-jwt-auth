-- Mock Backend JWT Service for Testing
-- Usage: lua spec/fixtures/mock-jwt-backend.lua [port]

local http_server = require "resty.http_server"
local cjson = require "cjson"
local port = tonumber(arg and arg[1]) or 9999

-- Mock JWT responses for different consumers
local mock_responses = {
  ["test-consumer"] = {
    jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0LWlzc3VlciIsInN1YiI6InRlc3QtY29uc3VtZXIiLCJhdWQiOiJ0ZXN0LWF1ZGllbmNlIiwiZXhwIjoxNjQwOTk1MjAwLCJpYXQiOjE2NDA5OTE2MDB9.test-signature",
    expires_in = 3600
  },
  ["anonymous"] = {
    jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0LWlzc3VlciIsInN1YiI6ImFub255bW91cyIsImF1ZCI6InRlc3QtYXVkaWVuY2UiLCJleHAiOjE2NDA5OTUyMDAsImlhdCI6MTY0MDk5MTYwMH0.anonymous-signature",
    expires_in = 1800
  },
  ["premium-user"] = {
    token = "premium-jwt-token-with-extended-access",
    expires_in = 7200
  }
}

-- Special responses for testing error conditions
local special_responses = {
  ["error-consumer"] = function()
    return nil, 500, "Internal Server Error"
  end,
  ["timeout-consumer"] = function()
    -- Simulate slow response
    os.execute("sleep 10")
    return { jwt = "timeout-jwt" }
  end,
  ["invalid-json-consumer"] = function()
    return "not-json-response", 200
  end,
  ["missing-jwt-consumer"] = function()
    return { message = "success", user_id = "123" }, 200
  end
}

local function handle_jwt_request(method, uri, headers, body)
  print("Received " .. method .. " request to " .. uri)

  if method ~= "POST" then
    return cjson.encode({ error = "Method not allowed" }), 405
  end

  if uri ~= "/get-jwt" then
    return cjson.encode({ error = "Not found" }), 404
  end

  local content_type = headers["content-type"] or headers["Content-Type"] or ""
  if not string.match(content_type, "application/json") then
    return cjson.encode({ error = "Content-Type must be application/json" }), 400
  end

  local ok, request_data = pcall(cjson.decode, body)
  if not ok then
    return cjson.encode({ error = "Invalid JSON body" }), 400
  end

  local consumer_id = request_data.consumer_id or "unknown"
  print("Request for consumer: " .. consumer_id)
  print("Request timestamp: " .. tostring(request_data.timestamp or "not provided"))

  -- Check for special error conditions
  if special_responses[consumer_id] then
    local response, status, error_body = special_responses[consumer_id]()
    if not response then
      return error_body or "Error", status or 500
    else
      return cjson.encode(response), status or 200
    end
  end

  -- Return mock response for known consumers
  local response = mock_responses[consumer_id]
  if response then
    print("Returning JWT for consumer: " .. consumer_id)
    return cjson.encode(response), 200
  else
    print("Unknown consumer, returning generic JWT")
    return cjson.encode({
      jwt = "generic-jwt-token-for-" .. consumer_id,
      expires_in = 300
    }), 200
  end
end

-- Simple HTTP server implementation for testing
local function start_server()
  local socket = require "socket"
  local server = assert(socket.bind("localhost", port))
  local ip, port = server:getsockname()
  print("Mock JWT Backend Server listening on " .. ip .. ":" .. port)
  print("Endpoints:")
  print("  POST /get-jwt - Get JWT token")
  print("")
  print("Test consumers:")
  for consumer, _ in pairs(mock_responses) do
    print("  " .. consumer)
  end
  print("")
  print("Special test consumers:")
  for consumer, _ in pairs(special_responses) do
    print("  " .. consumer .. " (triggers error condition)")
  end
  print("")

  while true do
    local client = server:accept()
    if client then
      client:settimeout(10)

      -- Read HTTP request
      local request_line = client:receive()
      if request_line then
        local method, uri, version = request_line:match("^(%S+)%s+(%S+)%s+(%S+)$")

        local headers = {}
        local content_length = 0

        -- Read headers
        while true do
          local header_line = client:receive()
          if not header_line or header_line == "" then
            break
          end

          local name, value = header_line:match("^([^:]+):%s*(.*)$")
          if name and value then
            headers[name:lower()] = value
            if name:lower() == "content-length" then
              content_length = tonumber(value) or 0
            end
          end
        end

        -- Read body if present
        local body = ""
        if content_length > 0 then
          body = client:receive(content_length)
        end

        -- Handle request
        local response_body, status = handle_jwt_request(method, uri, headers, body or "")

        -- Send response
        local status_line = "HTTP/1.1 " .. (status or 200) .. " OK"
        local response_headers = {
          "Content-Type: application/json",
          "Content-Length: " .. #response_body,
          "Connection: close"
        }

        client:send(status_line .. "\r\n")
        for _, header in ipairs(response_headers) do
          client:send(header .. "\r\n")
        end
        client:send("\r\n")
        client:send(response_body)
      end

      client:close()
    end
  end
end

-- Start the server
print("Starting Mock JWT Backend Server...")
start_server()