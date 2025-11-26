#!/bin/bash

# Test runner for Kong Remote JWT Auth Plugin
set -e

echo "Kong Remote JWT Auth Plugin - Test Suite"
echo "========================================"

# Prefer LuaJIT version of busted (in ~/.luarocks/bin) over system version
if [ -x "$HOME/.luarocks/bin/busted" ]; then
    BUSTED="$HOME/.luarocks/bin/busted"
elif command -v busted &> /dev/null; then
    BUSTED="busted"
else
    echo "❌ 'busted' testing framework is not installed."
    echo "Install with: luarocks install busted"
    exit 1
fi

echo "Using busted: $BUSTED"

# Check if Kong testing helpers are available
if ! luajit -e "require('spec.helpers')" &> /dev/null; then
    echo "⚠️  Kong testing helpers not found. Integration tests will be skipped."
    echo "To run integration tests, ensure Kong is installed and KONG_PREFIX is set."
    SKIP_INTEGRATION=true
else
    SKIP_INTEGRATION=false
fi

echo ""
echo "Running unit tests..."
echo "--------------------"

# Run unit tests
if $BUSTED spec/unit/ --verbose; then
    echo "✅ Unit tests passed"
else
    echo "❌ Unit tests failed"
    exit 1
fi

if [ "$SKIP_INTEGRATION" = false ]; then
    echo ""
    echo "Running integration tests..."
    echo "----------------------------"

    # Start mock backend server in background
    luajit spec/fixtures/mock-jwt-backend.lua 9999 &
    BACKEND_PID=$!

    # Give the server time to start
    sleep 2

    # Run integration tests
    if $BUSTED spec/integration/ --verbose; then
        echo "✅ Integration tests passed"
        INTEGRATION_RESULT=0
    else
        echo "❌ Integration tests failed"
        INTEGRATION_RESULT=1
    fi

    # Stop mock backend server
    kill $BACKEND_PID 2>/dev/null || true

    if [ $INTEGRATION_RESULT -ne 0 ]; then
        exit 1
    fi
else
    echo ""
    echo "⚠️  Integration tests skipped (Kong not available)"
fi

echo ""
echo "🎉 All tests completed successfully!"
echo ""
echo "Manual Testing:"
echo "---------------"
echo "1. Start mock backend server:"
echo "   luajit spec/fixtures/mock-jwt-backend.lua 9999"
echo ""
echo "2. Test backend JWT fetching:"
echo "   curl -X POST http://localhost:9999/get-jwt \\"
echo "     -H 'Content-Type: application/json' \\"
echo "     -d '{\"consumer_id\": \"test-consumer\", \"timestamp\": 1640991600}'"
echo ""
echo "3. Configure Kong with jwt_service_url: http://localhost:9999/get-jwt"
echo ""