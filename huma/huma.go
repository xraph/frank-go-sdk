package huma

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/rs/xid"
)

// HumaMiddleware provides Huma middleware functions for Frank Auth
type HumaMiddleware struct {
	client *frank.Client
	config *frank.Config
	api    huma.API
}

// NewHumaMiddleware creates a new Huma middleware instance
func NewHumaMiddleware(client *frank.Client, api huma.API) *HumaMiddleware {
	return &HumaMiddleware{
		client: client,
		config: client.GetConfig(),
		api:    api,
	}
}

func (m *HumaMiddleware) SetAPI(api huma.API) {
	m.api = api
}

func (m *HumaMiddleware) GetAPI() huma.API {
	return m.api
}

// RequireAuth creates a Huma middleware that requires authentication
func (m *HumaMiddleware) RequireAuth() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		r, _ := humachi.Unwrap(ctx)
		rctx := ctx.Context()

		// Try different authentication methods in order of preference
		authenticated := false

		// 1. Try JWT authentication
		if user, err := m.authenticateJWT(rctx, r); err == nil && user != nil {
			ctx = m.setUserContext(ctx, user, frank.AuthMethodJWT)
			authenticated = true
		}

		// 2. Try API Key authentication
		if !authenticated {
			if apiKey, user, err := m.authenticateAPIKey(rctx, r); err == nil && apiKey != nil && user != nil {
				ctx = m.setUserContext(ctx, user, frank.AuthMethodAPIKey)
				ctx = m.setAPIKeyContext(ctx, apiKey)
				authenticated = true
			}
		}

		// 3. Try Session authentication
		if !authenticated {
			if session, user, err := m.authenticateSession(rctx, r); err == nil && session != nil && user != nil {
				ctx = m.setUserContext(ctx, user, frank.AuthMethodSession)
				ctx = m.setSessionContext(ctx, session)
				authenticated = true
			}
		}

		if !authenticated {
			m.respondUnauthorized(ctx, "authentication required")
			return
		}

		// Add request metadata
		ctx = m.addRequestMetadata(ctx, r)

		fmt.Println("session token: logged in finally")

		next(ctx)
	}
}

// OptionalAuth creates a Huma middleware that optionally authenticates users
func (m *HumaMiddleware) OptionalAuth() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		r, _ := humachi.Unwrap(ctx)
		rctx := ctx.Context()

		// Try different authentication methods in order of preference
		authenticated := false

		// 1. Try JWT authentication
		if user, err := m.authenticateJWT(rctx, r); err == nil && user != nil {
			ctx = m.setUserContext(ctx, user, frank.AuthMethodJWT)
			authenticated = true
		}

		// 2. Try API Key authentication
		if !authenticated {
			if apiKey, user, err := m.authenticateAPIKey(rctx, r); err == nil && apiKey != nil && user != nil {
				ctx = m.setUserContext(ctx, user, frank.AuthMethodAPIKey)
				ctx = m.setAPIKeyContext(ctx, apiKey)
				authenticated = true
			}
		}

		// 3. Try Session authentication
		if !authenticated {
			if session, user, err := m.authenticateSession(rctx, r); err == nil && session != nil && user != nil {
				ctx = m.setUserContext(ctx, user, frank.AuthMethodSession)
				ctx = m.setSessionContext(ctx, session)
				authenticated = true
			}
		}

		if !authenticated {
			ctx = m.setAuthMethodContext(ctx, frank.AuthMethodNone)
		}

		// Add request metadata
		ctx = m.addRequestMetadata(ctx, r)

		next(ctx)
	}
}

// RequirePermission creates a Huma middleware that requires a specific permission
func (m *HumaMiddleware) RequirePermission(permission string) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		user := GetUserFromHumaContext(ctx)
		if user == nil {
			m.respondUnauthorized(ctx, "authentication required")
			return
		}

		// Check permission
		hasPermission, err := m.client.CheckUserPermission(ctx.Context(), user.ID, permission, user.OrganizationID)
		if err != nil {
			m.respondError(ctx, http.StatusInternalServerError, "PERMISSION_CHECK_FAILED", "Failed to check permission", err)
			return
		}

		if !hasPermission {
			m.respondForbidden(ctx, "insufficient permissions")
			return
		}

		next(ctx)
	}
}

// RequireRole creates a Huma middleware that requires a specific role
func (m *HumaMiddleware) RequireRole(role string) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		user := GetUserFromHumaContext(ctx)
		if user == nil {
			m.respondUnauthorized(ctx, "authentication required")
			return
		}

		// Check if user has the required role
		hasRole := false
		for _, userRole := range user.Roles {
			if userRole.Name == role {
				hasRole = true
				break
			}
		}

		if !hasRole {
			m.respondForbidden(ctx, "insufficient role")
			return
		}

		next(ctx)
	}
}

// RequireUserType creates a Huma middleware that requires a specific user type
func (m *HumaMiddleware) RequireUserType(userType frank.UserType) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		user := GetUserFromHumaContext(ctx)
		if user == nil {
			m.respondUnauthorized(ctx, "authentication required")
			return
		}

		if user.UserType != userType {
			m.respondForbidden(ctx, "insufficient user type")
			return
		}

		next(ctx)
	}
}

// RequireOrganization creates a Huma middleware that requires organization membership
func (m *HumaMiddleware) RequireOrganization() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		user := GetUserFromHumaContext(ctx)
		if user == nil {
			m.respondUnauthorized(ctx, "authentication required")
			return
		}

		r, _ := humachi.Unwrap(ctx)

		// Extract organization ID from URL parameter
		orgIDStr := chi.URLParam(r, "orgId")
		if orgIDStr == "" {
			orgIDStr = chi.URLParam(r, "organizationId")
		}

		if orgIDStr == "" {
			m.respondError(ctx, http.StatusBadRequest, "MISSING_ORGANIZATION_ID", "Organization ID is required", nil)
			return
		}

		orgID, err := xid.FromString(orgIDStr)
		if err != nil {
			m.respondError(ctx, http.StatusBadRequest, "INVALID_ORGANIZATION_ID", "Invalid organization ID format", err)
			return
		}

		// Check if user belongs to the organization
		if user.OrganizationID == nil || *user.OrganizationID != orgID {
			m.respondForbidden(ctx, "access to organization not allowed")
			return
		}

		// Add organization to context
		ctx = m.setOrganizationIDContext(ctx, orgID)

		next(ctx)
	}
}

// RequirePermissionWithPath creates middleware that checks permissions with dynamic resource IDs from path
func (m *HumaMiddleware) RequirePermissionWithPath(permission, resourceParam string) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		user := GetUserFromHumaContext(ctx)
		if user == nil {
			m.respondUnauthorized(ctx, "authentication required")
			return
		}

		r, _ := humachi.Unwrap(ctx)

		// Extract resource ID from URL parameter
		resourceID := chi.URLParam(r, resourceParam)
		if resourceID == "" {
			m.respondError(ctx, http.StatusBadRequest, "MISSING_RESOURCE_ID", fmt.Sprintf("Resource ID parameter '%s' is required", resourceParam), nil)
			return
		}

		// For now, we just check the base permission
		// In a more advanced implementation, you could check resource-specific permissions
		hasPermission, err := m.client.CheckUserPermission(ctx.Context(), user.ID, permission, user.OrganizationID)
		if err != nil {
			m.respondError(ctx, http.StatusInternalServerError, "PERMISSION_CHECK_FAILED", "Failed to check permission", err)
			return
		}

		if !hasPermission {
			m.respondForbidden(ctx, "insufficient permissions")
			return
		}

		next(ctx)
	}
}

// Chain creates a chain of Huma middleware functions
func (m *HumaMiddleware) Chain(middlewares ...func(huma.Context, func(huma.Context))) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		// Execute middlewares in reverse order to maintain proper execution flow
		handler := next
		for i := len(middlewares) - 1; i >= 0; i-- {
			middleware := middlewares[i]
			currentHandler := handler
			handler = func(ctx huma.Context) {
				middleware(ctx, currentHandler)
			}
		}
		handler(ctx)
	}
}

// Authentication methods (reuse from regular middleware)

func (m *HumaMiddleware) authenticateJWT(ctx context.Context, r *http.Request) (*frank.User, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, &frank.Error{Code: "NO_AUTH_HEADER", Message: "no authorization header"}
	}

	// Extract Bearer token
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return nil, &frank.Error{Code: "INVALID_AUTH_HEADER", Message: "invalid authorization header format"}
	}

	tokenString := parts[1]

	// If JWT secret is configured, verify locally
	if m.config.JWTSecret != "" {
		user, err := m.verifyJWTLocally(tokenString)
		if err == nil {
			return user, nil
		}
		// Fall through to remote verification if local verification fails
	}

	// Verify with Frank Auth service
	user, err := m.client.VerifyJWT(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (m *HumaMiddleware) authenticateAPIKey(ctx context.Context, r *http.Request) (*frank.APIKey, *frank.User, error) {
	// Try X-API-Key header first
	apiKey := r.Header.Get("X-API-Key")
	if apiKey == "" {
		// Try Authorization header with "ApiKey" scheme
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 && strings.ToLower(parts[0]) == "apikey" {
				apiKey = parts[1]
			}
		}
	}

	if apiKey == "" {
		return nil, nil, &frank.Error{Code: "NO_API_KEY", Message: "no API key provided"}
	}

	// Verify with Frank Auth service
	keyInfo, user, err := m.client.VerifyAPIKey(ctx, apiKey)
	if err != nil {
		return nil, nil, err
	}

	return keyInfo, user, nil
}

func (m *HumaMiddleware) authenticateSession(ctx context.Context, r *http.Request) (*frank.Session, *frank.User, error) {
	// Try session token from cookie first
	sessionToken := ""
	if cookie, err := r.Cookie(m.client.GetConfig().SessionCookieName); err == nil {
		sessionToken = cookie.Value
	}

	// Try Authorization header with "Session" scheme
	if sessionToken == "" {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 && strings.ToLower(parts[0]) == "session" {
				sessionToken = parts[1]
			}
		}
	}

	// Try X-Session-Token header
	if sessionToken == "" {
		sessionToken = r.Header.Get("X-Session-Token")
	}

	if sessionToken == "" {
		return nil, nil, &frank.Error{Code: "NO_SESSION_TOKEN", Message: "no session token provided"}
	}

	// Verify with Frank Auth service, forwarding all cookies from the original request
	session, user, err := m.client.VerifySessionWithCookies(ctx, sessionToken, r.Cookies())
	if err != nil {
		return nil, nil, err
	}

	return session, user, nil
}

func (m *HumaMiddleware) verifyJWTLocally(tokenString string) (*frank.User, error) {
	middleware := frank.NewMiddlewareWithConfig(m.client, m.config)
	return middleware.VerifyJWTLocally(tokenString)
}

// Context setters for Huma

func (m *HumaMiddleware) setUserContext(ctx huma.Context, user *frank.User, method frank.AuthMethod) huma.Context {
	newCtx := frank.SetUser(ctx.Context(), user)
	newCtx = frank.SetAuthMethod(newCtx, method)
	return huma.WithContext(ctx, newCtx)
}

func (m *HumaMiddleware) setAPIKeyContext(ctx huma.Context, apiKey *frank.APIKey) huma.Context {
	newCtx := frank.SetAPIKey(ctx.Context(), apiKey)
	return huma.WithContext(ctx, newCtx)
}

func (m *HumaMiddleware) setSessionContext(ctx huma.Context, session *frank.Session) huma.Context {
	newCtx := frank.SetSession(ctx.Context(), session)
	return huma.WithContext(ctx, newCtx)
}

func (m *HumaMiddleware) setAuthMethodContext(ctx huma.Context, method frank.AuthMethod) huma.Context {
	newCtx := frank.SetAuthMethod(ctx.Context(), method)
	return huma.WithContext(ctx, newCtx)
}

func (m *HumaMiddleware) setOrganizationIDContext(ctx huma.Context, orgID xid.ID) huma.Context {
	newCtx := frank.SetOrganizationID(ctx.Context(), orgID)
	return huma.WithContext(ctx, newCtx)
}

func (m *HumaMiddleware) addRequestMetadata(ctx huma.Context, r *http.Request) huma.Context {
	newCtx := frank.SetIPAddress(ctx.Context(), m.getClientIP(r))
	newCtx = frank.SetUserAgent(newCtx, r.UserAgent())
	newCtx = frank.SetRequestID(newCtx, r.Header.Get("X-Request-ID"))
	return huma.WithContext(ctx, newCtx)
}

func (m *HumaMiddleware) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return strings.Split(r.RemoteAddr, ":")[0]
}

// Response helpers for Huma

func (m *HumaMiddleware) respondUnauthorized(ctx huma.Context, message string) {
	m.respondError(ctx, http.StatusUnauthorized, "UNAUTHORIZED", message, nil)
}

func (m *HumaMiddleware) respondForbidden(ctx huma.Context, message string) {
	m.respondError(ctx, http.StatusForbidden, "FORBIDDEN", message, nil)
}

func (m *HumaMiddleware) respondError(ctx huma.Context, statusCode int, code, message string, err error) {
	errorResp := &frank.Error{
		Code:    code,
		Message: message,
	}

	if err != nil && m.config.Debug {
		errorResp.Details = map[string]interface{}{
			"debug_error": err.Error(),
		}
	}

	ctx.SetStatus(statusCode)
	huma.WriteErr(m.api, ctx, statusCode, errorResp.Error())
}
