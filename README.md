# Frank Auth Go SDK

A comprehensive Go SDK for integrating with Frank Auth - a multi-tenant authentication SaaS platform. This SDK provides middleware for both standard HTTP handlers and the Huma framework, supporting JWT, API keys, session-based authentication, and comprehensive RBAC.

## Features

- **Multiple Authentication Methods**: JWT, API keys, session tokens, OAuth2
- **Three-Tier User System**: Internal users, external users, and end users
- **Multi-Tenant Architecture**: Organization-scoped permissions and isolation
- **Comprehensive RBAC**: Role-based access control with context-aware permissions
- **Framework Support**: Standard HTTP handlers and Huma framework integration
- **Flexible Configuration**: Environment variables, manual config, or hybrid approaches
- **Advanced Permission Checking**: Resource-scoped and context-aware permission validation
- **Optional Authentication**: Support for both authenticated and anonymous users
- **Custom Error Handling**: Configurable error responses and handling
- **Production Ready**: Caching, logging, retries, and error handling

## Installation

```bash
go get github.com/your-org/frank-go-sdk
```

## Quick Start

### 1. Environment Configuration

Set up your environment variables:

```bash
export FRANK_AUTH_BASE_URL="https://api.frankauth.com"
export FRANK_AUTH_API_KEY="your-api-key-here"
```

### 2. Basic HTTP Server

```go
package main

import (
    "encoding/json"
    "log"
    "net/http"

    "github.com/go-chi/chi/v5"
    "github.com/frank-go-sdk/frank"
    "github.com/frank-go-sdk/middleware"
)

func main() {
    // Initialize Frank Auth SDK
    sdk, err := frank.NewFromEnv()
    if err != nil {
        log.Fatal("Failed to initialize Frank Auth SDK:", err)
    }

    r := chi.NewRouter()

    // Public routes
    r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
        json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
    })

    // Protected routes
    r.Route("/api", func(r chi.Router) {
        r.Use(sdk.Middleware())

        r.Get("/profile", func(w http.ResponseWriter, r *http.Request) {
            user := middleware.GetUser(r)
            json.NewEncoder(w).Encode(user)
        })
    })

    log.Fatal(http.ListenAndServe(":8080", r))
}
```

### 3. Huma Framework Integration

```go
package main

import (
    "context"
    "log"
    "net/http"

    "github.com/danielgtaylor/huma/v2"
    "github.com/danielgtaylor/huma/v2/adapters/humachi"
    "github.com/go-chi/chi/v5"
    "github.com/frank-go-sdk/frank"
    frankHuma "github.com/frank-go-sdk/huma"
)

func main() {
    sdk, err := frank.NewFromEnv()
    if err != nil {
        log.Fatal(err)
    }

    router := chi.NewMux()
    config := huma.DefaultConfig("My API", "1.0.0")
    api := huma.NewAPI(config, humachi.New(router))

    // Protected group
    protectedGroup := huma.NewGroup(api, "/api")
    protectedGroup.UseMiddleware(sdk.HumaMiddleware(api))

    huma.Register(protectedGroup, huma.Operation{
        OperationID: "getProfile",
        Method:      http.MethodGet,
        Path:        "/profile",
        Summary:     "Get user profile",
    }, func(ctx context.Context, input *struct{}) (*UserOutput, error) {
        humaCtx := ctx.Value("huma_context").(huma.Context)
        user := frankHuma.GetUser(humaCtx)
        return &UserOutput{Body: user}, nil
    })

    log.Fatal(http.ListenAndServe(":8080", router))
}
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FRANK_AUTH_BASE_URL` | Frank Auth API base URL | `https://api.frankauth.com` |
| `FRANK_AUTH_API_KEY` | API key for server-to-server auth | - |
| `FRANK_AUTH_TIMEOUT` | HTTP request timeout | `30s` |
| `FRANK_AUTH_OPTIONAL` | Allow requests without auth | `false` |
| `FRANK_AUTH_REQUIRED_ROLES` | Required roles (comma-separated) | - |
| `FRANK_AUTH_REQUIRED_PERMISSIONS` | Required permissions (comma-separated) | - |
| `FRANK_AUTH_REQUIRE_ORGANIZATION` | Require organization context | `false` |
| `FRANK_AUTH_REQUIRED_USER_TYPE` | Required user type | - |
| `FRANK_AUTH_SKIP_PATHS` | Paths to skip auth (comma-separated) | - |
| `FRANK_AUTH_CACHE_ENABLED` | Enable response caching | `true` |
| `FRANK_AUTH_CACHE_TTL` | Cache TTL | `5m` |
| `FRANK_AUTH_LOG_LEVEL` | Log level | `info` |
| `FRANK_AUTH_LOG_REQUESTS` | Log all requests | `false` |

### Manual Configuration

```go
cfg := &config.Config{
    BaseURL:             "https://api.frankauth.com",
    APIKey:              "your-api-key",
    Optional:            false,
    RequiredPermissions: []string{"read:profile"},
    RequiredRoles:       []string{"member"},
    RequireOrganization: true,
    RequiredUserType:    "external",
    SkipPaths:           []string{"/health", "/metrics"},
    CacheEnabled:        true,
    LogRequests:         true,
}

sdk, err := frank.New(cfg)
```

## Authentication Methods

The SDK supports multiple authentication methods that can be used simultaneously:

### 1. JWT Bearer Token

```bash
curl -H "Authorization: Bearer your-jwt-token" https://api.example.com/api/profile
```

### 2. API Key

```bash
curl -H "X-API-Key: your-api-key" https://api.example.com/api/profile
```

### 3. Session Token (Cookie)

```bash
curl -b "session_token=your-session-token" https://api.example.com/api/profile
```

### 4. Session Token (Header)

```bash
curl -H "X-Session-Token: your-session-token" https://api.example.com/api/profile
```

## Permission System

### Basic Permission Checking

```go
// Require specific permissions
r.Use(sdk.RequirePermissions("read:users", "write:users"))

// Check permissions in handlers
if !middleware.HasPermission(r, "delete:users") {
    http.Error(w, "Insufficient permissions", http.StatusForbidden)
    return
}
```

### Advanced Permission Checking

```go
// Dynamic permission checking with context
checker := sdk.PermissionChecker()
canRead, err := checker.Check(r.Context(), userID, "read:user",
    permissions.WithResource("user"),
    permissions.WithResourceID("user-123"),
    permissions.WithOrganizationContext(orgID),
)
```

### Role-Based Access

```go
// Require specific roles
r.Use(sdk.RequireRoles("admin", "manager"))

// Check roles in handlers
if !middleware.HasRole(r, "admin") {
    http.Error(w, "Admin access required", http.StatusForbidden)
    return
}
```

### User Type Restrictions

```go
// Require specific user types
r.Use(sdk.RequireUserType("internal"))  // Internal users only
r.Use(sdk.RequireUserType("external"))  // External users only
r.Use(sdk.RequireUserType("end_user"))  // End users only
```

## Multi-Tenant Support

### Organization Context

```go
// Require organization context
r.Use(sdk.RequireOrganization())

// Access organization in handlers
func handler(w http.ResponseWriter, r *http.Request) {
    org := middleware.GetOrganization(r)
    if org == nil {
        http.Error(w, "Organization required", http.StatusForbidden)
        return
    }
    
    // Use organization-scoped data
    fmt.Printf("Organization: %s\n", org.Name)
}
```

### Permission Context

```go
// Check permissions within organization context
checker := sdk.PermissionChecker()
allowed, err := checker.Check(ctx, userID, "manage:users",
    permissions.WithOrganizationContext(orgID),
)
```

## Huma Framework Integration

### Basic Setup

```go
// Apply authentication middleware
protectedGroup := huma.NewGroup(api, "/api")
protectedGroup.UseMiddleware(sdk.HumaMiddleware(api))

// Permission-based endpoints
adminGroup := huma.NewGroup(protectedGroup, "/admin")
adminGroup.UseMiddleware(sdk.HumaRequirePermissions(api, "admin:access"))
```

### Permission Middleware

```go
// Flexible permission checking with resource context
userGroup := huma.NewGroup(protectedGroup, "/users")
userGroup.UseMiddleware(sdk.HumaPermissionMiddleware(api, 
    "read:user",     // permission
    "user",          // resource type
    "userId",        // path parameter for resource ID
))
```

### Context Access

```go
func handler(ctx context.Context, input *Input) (*Output, error) {
    humaCtx := ctx.Value("huma_context").(huma.Context)
    
    // Get authentication context
    user := frankHuma.GetUser(humaCtx)
    org := frankHuma.GetOrganization(humaCtx)
    
    // Check permissions
    if !frankHuma.HasPermission(humaCtx, "read:data") {
        return nil, huma.Error403Forbidden("Insufficient permissions")
    }
    
    return &Output{Body: "success"}, nil
}
```

## Optional Authentication

Support both authenticated and anonymous users:

```go
r.Route("/api", func(r chi.Router) {
    r.Use(sdk.OptionalMiddleware())

    r.Get("/content", func(w http.ResponseWriter, r *http.Request) {
        user := middleware.GetUser(r)
        
        if user != nil {
            // Authenticated user - premium content
            json.NewEncoder(w).Encode(map[string]interface{}{
                "content": "Premium content",
                "user":    user.Email,
            })
        } else {
            // Anonymous user - basic content
            json.NewEncoder(w).Encode(map[string]interface{}{
                "content": "Basic content",
                "message": "Login for premium features",
            })
        }
    })
})
```

## Error Handling

### Custom Error Handler

```go
customErrorHandler := func(w http.ResponseWriter, r *http.Request, err error) {
    w.Header().Set("Content-Type", "application/json")
    
    if authErr, ok := err.(*middleware.AuthError); ok {
        response := map[string]interface{}{
            "error": map[string]interface{}{
                "code":    authErr.Code,
                "message": authErr.Message,
                "path":    r.URL.Path,
            },
        }

        switch authErr.Code {
        case "no_auth":
            w.WriteHeader(http.StatusUnauthorized)
            response["error"].(map[string]interface{})["hint"] = "Include Authorization header"
        case "insufficient_permissions":
            w.WriteHeader(http.StatusForbidden)
            response["error"].(map[string]interface{})["hint"] = "Contact administrator"
        }

        json.NewEncoder(w).Encode(response)
        return
    }

    // Generic error
    w.WriteHeader(http.StatusInternalServerError)
    json.NewEncoder(w).Encode(map[string]interface{}{
        "error": "Internal server error",
    })
}

// Use custom error handler
cfg := config.LoadFromEnv()
middlewareConfig := cfg.ToMiddlewareConfig(sdk.Client())
middlewareConfig.ErrorHandler = customErrorHandler

r.Use(middleware.Auth(middlewareConfig))
```

## Context Utilities

### HTTP Request Context

```go
// Get authentication context
authCtx := middleware.GetAuthContext(r)
user := middleware.GetUser(r)
org := middleware.GetOrganization(r)
userID := middleware.GetUserID(r)
orgID := middleware.GetOrganizationID(r)

// Check authentication status
if middleware.IsAuthenticated(r) {
    // User is authenticated
}

// Check user type
if middleware.IsUserType(r, "admin") {
    // User is admin type
}

// Check permissions and roles
if middleware.HasPermission(r, "read:data") {
    // User has permission
}

if middleware.HasRole(r, "manager") {
    // User has role
}
```

### Huma Context

```go
// Get authentication context
user := frankHuma.GetUser(ctx)
org := frankHuma.GetOrganization(ctx)
userID := frankHuma.GetUserID(ctx)
orgID := frankHuma.GetOrganizationID(ctx)

// Check authentication status
if frankHuma.IsAuthenticated(ctx) {
    // User is authenticated
}

// Check permissions and roles
if frankHuma.HasPermission(ctx, "read:data") {
    // User has permission
}
```

## Advanced Usage

### Multiple SDK Instances

```go
// Different configurations for different route groups
publicSDK, _ := frank.New(&config.Config{
    BaseURL:  frankAuthURL,
    APIKey:   apiKey,
    Optional: true,
})

memberSDK, _ := frank.New(&config.Config{
    BaseURL:         frankAuthURL,
    APIKey:          apiKey,
    RequiredRoles:   []string{"member"},
})

adminSDK, _ := frank.New(&config.Config{
    BaseURL:           frankAuthURL,
    APIKey:            apiKey,
    RequiredUserType:  "internal",
    RequiredRoles:     []string{"admin"},
})

// Use different SDKs for different routes
r.Route("/public", func(r chi.Router) {
    r.Use(publicSDK.OptionalMiddleware())
    // Public routes
})

r.Route("/member", func(r chi.Router) {
    r.Use(memberSDK.Middleware())
    // Member routes
})

r.Route("/admin", func(r chi.Router) {
    r.Use(adminSDK.Middleware())
    // Admin routes
})
```

### Direct Client Usage

```go
// Use the client directly for custom operations
client := sdk.Client()

// Verify tokens manually
authResult, err := client.VerifyJWT(ctx, token)
if err != nil {
    return err
}

// Check permissions
checkResult, err := client.CheckPermission(ctx, client.PermissionCheckRequest{
    UserID:     userID,
    Permission: "read:users",
    Resource:   "user",
    ResourceID: "user-123",
})

// Get user information
user, err := client.GetUser(ctx, userID)
org, err := client.GetOrganization(ctx, orgID)
roles, err := client.GetUserRoles(ctx, userID, &orgID)
permissions, err := client.GetUserPermissions(ctx, userID, &orgID)
```

## Best Practices

### 1. Environment-Based Configuration

Use environment variables for different deployment environments:

```bash
# Development
export FRANK_AUTH_BASE_URL="https://dev-api.frankauth.com"
export FRANK_AUTH_LOG_LEVEL="debug"
export FRANK_AUTH_LOG_REQUESTS="true"

# Production
export FRANK_AUTH_BASE_URL="https://api.frankauth.com"
export FRANK_AUTH_LOG_LEVEL="warn"
export FRANK_AUTH_CACHE_ENABLED="true"
```

### 2. Path-Based Authentication

Skip authentication for specific paths:

```bash
export FRANK_AUTH_SKIP_PATHS="/health,/metrics,/public/*"
```

### 3. Graceful Error Handling

Always provide meaningful error messages and appropriate HTTP status codes.

### 4. Permission Granularity

Use specific permissions rather than broad roles when possible:

```go
// Good
r.Use(sdk.RequirePermissions("read:user", "write:user"))

// Less specific
r.Use(sdk.RequireRoles("admin"))
```

### 5. Organization Context

Always verify organization context for multi-tenant applications:

```go
r.Use(sdk.Middleware())
r.Use(sdk.RequireOrganization())
```

## Troubleshooting

### Common Issues

1. **Invalid API Key**: Ensure your API key is correctly set and has the required permissions
2. **Network Issues**: Check if your application can reach the Frank Auth API
3. **Permission Denied**: Verify that the user has the required permissions or roles
4. **Organization Context**: Ensure the user belongs to the required organization

### Debug Logging

Enable debug logging to troubleshoot issues:

```bash
export FRANK_AUTH_LOG_LEVEL="debug"
export FRANK_AUTH_LOG_REQUESTS="true"
```

### Testing Authentication

Test different authentication methods:

```bash
# Test JWT
curl -H "Authorization: Bearer $JWT_TOKEN" http://localhost:8080/api/profile

# Test API Key
curl -H "X-API-Key: $API_KEY" http://localhost:8080/api/profile

# Test Session
curl -b "session_token=$SESSION_TOKEN" http://localhost:8080/api/profile
```

## Examples

See the `examples/` directory for comprehensive examples including:

- Basic HTTP server integration
- Huma framework integration
- Advanced permission checking
- Multi-tenant applications
- Custom error handling
- Optional authentication
- Configuration management

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

- Documentation: [https://docs.frankauth.com/go-sdk](https://docs.frankauth.com/go-sdk)
- Issues: [https://github.com/your-org/frank-go-sdk/issues](https://github.com/your-org/frank-go-sdk/issues)
- Support: [support@frankauth.com](mailto:support@frankauth.com)