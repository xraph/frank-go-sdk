package frank

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/xid"
)

// AuthMethod represents the authentication method used
type AuthMethod string

const (
	AuthMethodJWT     AuthMethod = "jwt"
	AuthMethodAPIKey  AuthMethod = "api_key"
	AuthMethodSession AuthMethod = "session"
	AuthMethodNone    AuthMethod = "none"
)

// Middleware provides Chi middleware functions for Frank Auth
type Middleware struct {
	client *Client
	config *Config
}

// NewMiddlewareWithConfig creates a new middleware instance
func NewMiddlewareWithConfig(client *Client, config *Config) *Middleware {
	return &Middleware{
		client: client,
		config: config,
	}
}

// NewMiddleware creates a new middleware instance
func NewMiddleware(client *Client) *Middleware {
	return &Middleware{
		client: client,
		config: client.config,
	}
}

// RequireAuth middleware that requires authentication via JWT, API key, or session
func (m *Middleware) RequireAuth() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Try different authentication methods in order of preference
			authenticated := false

			// 1. Try JWT authentication
			if user, err := m.authenticateJWT(ctx, r); err == nil && user != nil {
				ctx = SetUser(ctx, user)
				ctx = SetAuthMethod(ctx, AuthMethodJWT)
				authenticated = true
			}

			// 2. Try API Key authentication
			if !authenticated {
				if apiKey, user, err := m.authenticateAPIKey(ctx, r); err == nil && apiKey != nil && user != nil {
					ctx = SetUser(ctx, user)
					ctx = SetAPIKey(ctx, apiKey)
					ctx = SetAuthMethod(ctx, AuthMethodAPIKey)
					authenticated = true
				}
			}

			// 3. Try Session authentication
			if !authenticated {
				if session, user, err := m.authenticateSession(ctx, r); err == nil && session != nil && user != nil {
					ctx = SetUser(ctx, user)
					ctx = SetSession(ctx, session)
					ctx = SetAuthMethod(ctx, AuthMethodSession)
					authenticated = true
				}
			}

			if !authenticated {
				m.respondUnauthorized(w, r, "authentication required")
				return
			}

			// Add request metadata
			ctx = m.addRequestMetadata(ctx, r)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// OptionalAuth middleware that optionally authenticates users
func (m *Middleware) OptionalAuth() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Try different authentication methods in order of preference
			authenticated := false

			// 1. Try JWT authentication
			if user, err := m.authenticateJWT(ctx, r); err == nil && user != nil {
				ctx = SetUser(ctx, user)
				ctx = SetAuthMethod(ctx, AuthMethodJWT)
				authenticated = true
			}

			// 2. Try API Key authentication
			if !authenticated {
				if apiKey, user, err := m.authenticateAPIKey(ctx, r); err == nil && apiKey != nil && user != nil {
					ctx = SetUser(ctx, user)
					ctx = SetAPIKey(ctx, apiKey)
					ctx = SetAuthMethod(ctx, AuthMethodAPIKey)
					authenticated = true
				}
			}

			// 3. Try Session authentication
			if !authenticated {
				if session, user, err := m.authenticateSession(ctx, r); err == nil && session != nil && user != nil {
					ctx = SetUser(ctx, user)
					ctx = SetSession(ctx, session)
					ctx = SetAuthMethod(ctx, AuthMethodSession)
					authenticated = true
				}
			}

			if !authenticated {
				ctx = SetAuthMethod(ctx, AuthMethodNone)
			}

			// Add request metadata
			ctx = m.addRequestMetadata(ctx, r)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequirePermission middleware that requires a specific permission
func (m *Middleware) RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			user := GetUser(ctx)
			if user == nil {
				m.respondUnauthorized(w, r, "authentication required")
				return
			}

			// Check permission
			hasPermission, err := m.client.CheckUserPermission(ctx, user.ID, permission, user.OrganizationID)
			if err != nil {
				m.respondError(w, r, http.StatusInternalServerError, "PERMISSION_CHECK_FAILED", "Failed to check permission", err)
				return
			}

			if !hasPermission {
				m.respondForbidden(w, r, "insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole middleware that requires a specific role
func (m *Middleware) RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			user := GetUser(ctx)
			if user == nil {
				m.respondUnauthorized(w, r, "authentication required")
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
				m.respondForbidden(w, r, "insufficient role")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireUserType middleware that requires a specific user type
func (m *Middleware) RequireUserType(userType UserType) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			user := GetUser(ctx)
			if user == nil {
				m.respondUnauthorized(w, r, "authentication required")
				return
			}

			if user.UserType != userType {
				m.respondForbidden(w, r, "insufficient user type")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireOrganization middleware that requires the user to belong to a specific organization
func (m *Middleware) RequireOrganization() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			user := GetUser(ctx)
			if user == nil {
				m.respondUnauthorized(w, r, "authentication required")
				return
			}

			// Extract organization ID from URL parameter
			orgIDStr := chi.URLParam(r, "orgId")
			if orgIDStr == "" {
				orgIDStr = chi.URLParam(r, "organizationId")
			}

			if orgIDStr == "" {
				m.respondError(w, r, http.StatusBadRequest, "MISSING_ORGANIZATION_ID", "Organization ID is required", nil)
				return
			}

			orgID, err := xid.FromString(orgIDStr)
			if err != nil {
				m.respondError(w, r, http.StatusBadRequest, "INVALID_ORGANIZATION_ID", "Invalid organization ID format", err)
				return
			}

			// Check if user belongs to the organization
			if user.OrganizationID == nil || *user.OrganizationID != orgID {
				m.respondForbidden(w, r, "access to organization not allowed")
				return
			}

			// Add organization to context
			ctx = SetOrganizationID(ctx, orgID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// AuthenticateJWT attempts to authenticate using JWT token
func (m *Middleware) authenticateJWT(ctx context.Context, r *http.Request) (*User, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, &Error{Code: "NO_AUTH_HEADER", Message: "no authorization header"}
	}

	// Extract Bearer token
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return nil, &Error{Code: "INVALID_AUTH_HEADER", Message: "invalid authorization header format"}
	}

	tokenString := parts[1]

	// If JWT secret is configured, verify locally
	if m.config.JWTSecret != "" {
		user, err := m.VerifyJWTLocally(tokenString)
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

// AuthenticateAPIKey attempts to authenticate using API key
func (m *Middleware) authenticateAPIKey(ctx context.Context, r *http.Request) (*APIKey, *User, error) {
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
		return nil, nil, &Error{Code: "NO_API_KEY", Message: "no API key provided"}
	}

	// Verify with Frank Auth service
	keyInfo, user, err := m.client.VerifyAPIKey(ctx, apiKey)
	if err != nil {
		return nil, nil, err
	}

	return keyInfo, user, nil
}

// AuthenticateSession attempts to authenticate using session token
func (m *Middleware) authenticateSession(ctx context.Context, r *http.Request) (*Session, *User, error) {
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
		return nil, nil, &Error{Code: "NO_SESSION_TOKEN", Message: "no session token provided"}
	}

	// Verify with Frank Auth service
	session, user, err := m.client.VerifySessionWithCookies(ctx, sessionToken, r.Cookies())
	if err != nil {
		return nil, nil, err
	}

	return session, user, nil
}

// VerifyJWTLocally verifies JWT locally using the configured secret
func (m *Middleware) VerifyJWTLocally(tokenString string) (*User, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, &Error{
				Code:    "INVALID_SIGNING_METHOD",
				Message: "invalid signing method",
			}
		}
		return []byte(m.config.JWTSecret), nil
	})

	if err != nil {
		return nil, &Error{
			Code:    "INVALID_JWT",
			Message: "invalid JWT token",
			Details: map[string]interface{}{"error": err.Error()},
		}
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, &Error{
			Code:    "INVALID_JWT_CLAIMS",
			Message: "invalid JWT claims",
		}
	}

	// Verify issuer
	if m.config.JWTIssuer != "" && claims.Issuer != m.config.JWTIssuer {
		return nil, &Error{
			Code:    "INVALID_JWT_ISSUER",
			Message: "invalid JWT issuer",
		}
	}

	// Verify audience
	if len(m.config.JWTAudience) > 0 {
		validAudience := false
		for _, audience := range claims.Audience {
			for _, expectedAudience := range m.config.JWTAudience {
				if audience == expectedAudience {
					validAudience = true
					break
				}
			}
			if validAudience {
				break
			}
		}
		if !validAudience {
			return nil, &Error{
				Code:    "INVALID_JWT_AUDIENCE",
				Message: "invalid JWT audience",
			}
		}
	}

	// Create user from claims
	user := &User{
		ID:             claims.UserID,
		UserType:       UserType(claims.UserType),
		OrganizationID: claims.OrganizationID,
		Permissions:    claims.Permissions,
		Active:         true,
	}

	return user, nil
}

// AddRequestMetadata adds request metadata to context
func (m *Middleware) addRequestMetadata(ctx context.Context, r *http.Request) context.Context {
	ctx = SetIPAddress(ctx, m.getClientIP(r))
	ctx = SetUserAgent(ctx, r.UserAgent())
	ctx = SetRequestID(ctx, r.Header.Get("X-Request-ID"))
	return ctx
}

// GetClientIP extracts the client IP address from the request
func (m *Middleware) getClientIP(r *http.Request) string {
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

// Response helpers

func (m *Middleware) respondUnauthorized(w http.ResponseWriter, r *http.Request, message string) {
	m.respondError(w, r, http.StatusUnauthorized, "UNAUTHORIZED", message, nil)
}

func (m *Middleware) respondForbidden(w http.ResponseWriter, r *http.Request, message string) {
	m.respondError(w, r, http.StatusForbidden, "FORBIDDEN", message, nil)
}

func (m *Middleware) respondError(w http.ResponseWriter, r *http.Request, statusCode int, code, message string, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	errorResp := ErrorResponse{
		Error: &Error{
			Code:      code,
			Message:   message,
			Timestamp: time.Now(),
		},
	}

	if err != nil && m.config.Debug {
		errorResp.Error.Details = map[string]interface{}{
			"debug_error": err.Error(),
		}
	}

	json.NewEncoder(w).Encode(errorResp)
}
