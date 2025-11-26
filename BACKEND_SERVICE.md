# Backend JWT Service Integration

This document describes how the Kong Remote JWT Auth Plugin integrates with your backend JWT service.

## Overview

The plugin has been extended to fetch additional JWT tokens from your backend service after successful JWT validation. This allows you to:

1. **Validate incoming JWTs** (existing functionality - unchanged)
2. **Fetch additional JWTs** from your backend service
3. **Set custom headers** with the fetched JWT (`x-harmonic-cerberus-jwt`)

## Backend Service Requirements

### Endpoint Specification

Your backend service should provide a simple GET endpoint:

**Method**: `GET`
**URL**: Configurable via `jwt_service_url`
**Authentication**: Works purely based on existing JWT token headers from the original request

### Request Format

The plugin makes a simple GET request to your configured endpoint with **all original request headers forwarded**:

```bash
GET /your-jwt-endpoint HTTP/1.1
Host: your-backend.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Proxy-Authorization: Bearer another-jwt-token
User-Agent: kong-http-client/1.0
X-Forwarded-For: 192.168.1.100
# ... all other original request headers
```

**Header forwarding**: All original request headers are automatically passed to your backend service, including:
- `Authorization` and `Proxy-Authorization` headers (containing JWTs)
- Custom headers from the client
- Kong-added headers (X-Forwarded-*, etc.)

**No query parameters or request body are sent** - your service works purely based on the forwarded headers.

### Response Format

Your backend service should return the JWT token as a **plain string** (not JSON):

```
HTTP/1.1 200 OK
Content-Type: text/plain

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

**Response Details**:
- **Content-Type**: Can be `text/plain`, `application/jwt`, or any other content type
- **Body**: Just the JWT token string (no JSON wrapper)
- **Cache TTL**: Fixed at 300 seconds (5 minutes) - not configurable via response

### HTTP Status Codes

- **200 OK**: Success - JWT will be extracted and cached
- **Any other status**: Treated as error - request continues without setting the header

## Kong Configuration

Add the new configuration fields to your Kong plugin:

```yaml
plugins:
  - name: remote-jwt-auth
    config:
      # Existing configuration (unchanged)
      authenticated_consumer: "your-consumer"
      signing_urls:
        - "https://www.googleapis.com/oauth2/v1/certs"
      claims_to_verify:
        - name: iss
          allowed_values: ["expected-issuer"]

      # New backend JWT service configuration
      jwt_service_url: "https://your-backend.com/get-jwt"  # Required for backend integration
      jwt_service_timeout: 5000  # Optional, defaults to 5000ms
```

## Behavior

### Normal Flow
1. **JWT Validation**: Original Firebase JWT validation runs as before
2. **Consumer Check**: Verifies user is not anonymous (anonymous users skip backend call)
3. **Backend Call**: If validation succeeds and `jwt_service_url` is configured:
   - Makes GET request to your backend service
   - Passes through all original headers (including `Authorization` with the validated JWT)
   - Caches the response JWT per-user
4. **Header Setting**: Sets `x-harmonic-cerberus-jwt` header with the fetched JWT
5. **Request Forwarding**: Original request continues to your upstream service

### Error Handling
- **Backend service unavailable**: Request continues without the additional header (non-blocking)
- **Invalid response**: Logged as warning, request continues
- **Timeout**: Respects `jwt_service_timeout`, request continues on timeout

### Caching
- **Cache key**: Per-user based on consumer username (each user has their own cached JWT)
- **Cache TTL**: Fixed at 300 seconds (5 minutes)
- **Cache benefits**: Reduces load on backend service for subsequent requests from the same user
- **Cache isolation**: Different users cannot access each other's cached JWTs

## Example Implementation

Here's a simple example of what your backend service might look like:

```javascript
app.get('/get-jwt', (req, res) => {
  // The validated Firebase JWT is in the Authorization header
  const authHeader = req.headers.authorization;
  const firebaseJWT = authHeader?.replace(/^Bearer /i, '');

  // Your service has access to ALL original request headers
  const proxyAuth = req.headers['proxy-authorization'];
  const userAgent = req.headers['user-agent'];
  const customHeader = req.headers['x-custom-client-id'];

  console.log('Firebase JWT:', firebaseJWT);
  console.log('All headers:', req.headers);

  // Generate/fetch JWT based on the Firebase JWT or other headers
  const customJWT = generateCustomJWT({
    firebaseJWT,
    proxyAuth,
    userAgent,
    customHeader
  });

  // Return just the JWT string
  res.setHeader('Content-Type', 'text/plain');
  res.send(customJWT);
});
```

## Testing

Test your backend service integration:

```bash
# Test your backend service directly
curl -X GET https://your-backend.com/get-jwt \
  -H "Authorization: Bearer your-firebase-jwt" \
  -H "X-Custom-Client-ID: client-123" \
  -H "User-Agent: MyApp/1.0"

# Your backend will receive ALL these headers

# Expected response (just the JWT string):
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

## Backward Compatibility

- **Without `jwt_service_url`**: Plugin works exactly as before (100% backward compatible)
- **With `jwt_service_url`**: Adds backend JWT fetching functionality
- **All existing features preserved**: JWT validation, consumer setting, header extraction

## Security Considerations

- **Original JWT validation**: Still required - backend service is only called after successful Firebase JWT validation
- **Anonymous user protection**: Anonymous users are automatically skipped (no backend call made)
- **Per-user cache isolation**: Each user's JWT is cached separately, preventing cross-user data leakage
- **Header forwarding**: All original headers are passed to backend service
- **Error handling**: Backend failures don't compromise request security
- **Caching**: JWTs are cached in Kong's shared memory (not persistent)