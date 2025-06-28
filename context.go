package frank

import (
	"context"

	"github.com/rs/xid"
)

// Context keys for storing authentication data
type contextKey string

const (
	contextKeyUser           contextKey = "frank_user"
	contextKeyAuthMethod     contextKey = "frank_auth_method"
	contextKeyAPIKey         contextKey = "frank_api_key"
	contextKeySession        contextKey = "frank_session"
	contextKeyOrganization   contextKey = "frank_organization"
	contextKeyOrganizationID contextKey = "frank_organization_id"
	contextKeyIPAddress      contextKey = "frank_ip_address"
	contextKeyUserAgent      contextKey = "frank_user_agent"
	contextKeyRequestID      contextKey = "frank_request_id"
	contextKeyPermissions    contextKey = "frank_permissions"
	HTTPRequestContextKey    contextKey = "frank_http_request"
)

// Context setters

// SetUser sets the authenticated user in the context
func SetUser(ctx context.Context, user *User) context.Context {
	return context.WithValue(ctx, contextKeyUser, user)
}

// SetAuthMethod sets the authentication method in the context
func SetAuthMethod(ctx context.Context, method AuthMethod) context.Context {
	return context.WithValue(ctx, contextKeyAuthMethod, method)
}

// SetAPIKey sets the API key information in the context
func SetAPIKey(ctx context.Context, apiKey *APIKey) context.Context {
	return context.WithValue(ctx, contextKeyAPIKey, apiKey)
}

// SetSession sets the session information in the context
func SetSession(ctx context.Context, session *Session) context.Context {
	return context.WithValue(ctx, contextKeySession, session)
}

// SetOrganization sets the organization information in the context
func SetOrganization(ctx context.Context, org *Organization) context.Context {
	return context.WithValue(ctx, contextKeyOrganization, org)
}

// SetOrganizationID sets the organization ID in the context
func SetOrganizationID(ctx context.Context, orgID xid.ID) context.Context {
	return context.WithValue(ctx, contextKeyOrganizationID, orgID)
}

// SetIPAddress sets the client IP address in the context
func SetIPAddress(ctx context.Context, ipAddress string) context.Context {
	return context.WithValue(ctx, contextKeyIPAddress, ipAddress)
}

// SetUserAgent sets the user agent in the context
func SetUserAgent(ctx context.Context, userAgent string) context.Context {
	return context.WithValue(ctx, contextKeyUserAgent, userAgent)
}

// SetRequestID sets the request ID in the context
func SetRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, contextKeyRequestID, requestID)
}

// SetPermissions sets the user permissions in the context
func SetPermissions(ctx context.Context, permissions []string) context.Context {
	return context.WithValue(ctx, contextKeyPermissions, permissions)
}

// Context getters

// GetUser retrieves the authenticated user from the context
func GetUser(ctx context.Context) *User {
	if user, ok := ctx.Value(contextKeyUser).(*User); ok {
		return user
	}
	return nil
}

// GetAuthMethod retrieves the authentication method from the context
func GetAuthMethod(ctx context.Context) AuthMethod {
	if method, ok := ctx.Value(contextKeyAuthMethod).(AuthMethod); ok {
		return method
	}
	return AuthMethodNone
}

// GetAPIKey retrieves the API key information from the context
func GetAPIKey(ctx context.Context) *APIKey {
	if apiKey, ok := ctx.Value(contextKeyAPIKey).(*APIKey); ok {
		return apiKey
	}
	return nil
}

// GetSession retrieves the session information from the context
func GetSession(ctx context.Context) *Session {
	if session, ok := ctx.Value(contextKeySession).(*Session); ok {
		return session
	}
	return nil
}

// GetOrganization retrieves the organization information from the context
func GetOrganization(ctx context.Context) *Organization {
	if org, ok := ctx.Value(contextKeyOrganization).(*Organization); ok {
		return org
	}
	return nil
}

// GetOrganizationID retrieves the organization ID from the context
func GetOrganizationID(ctx context.Context) *xid.ID {
	if orgID, ok := ctx.Value(contextKeyOrganizationID).(xid.ID); ok {
		return &orgID
	}
	return nil
}

// GetIPAddress retrieves the client IP address from the context
func GetIPAddress(ctx context.Context) string {
	if ipAddress, ok := ctx.Value(contextKeyIPAddress).(string); ok {
		return ipAddress
	}
	return ""
}

// GetUserAgent retrieves the user agent from the context
func GetUserAgent(ctx context.Context) string {
	if userAgent, ok := ctx.Value(contextKeyUserAgent).(string); ok {
		return userAgent
	}
	return ""
}

// GetRequestID retrieves the request ID from the context
func GetRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value(contextKeyRequestID).(string); ok {
		return requestID
	}
	return ""
}

// GetPermissions retrieves the user permissions from the context
func GetPermissions(ctx context.Context) []string {
	if permissions, ok := ctx.Value(contextKeyPermissions).([]string); ok {
		return permissions
	}
	return nil
}

// Convenience methods

// IsAuthenticated checks if the context has an authenticated user
func IsAuthenticated(ctx context.Context) bool {
	return GetUser(ctx) != nil
}

// GetUserID retrieves the user ID from the context
func GetUserID(ctx context.Context) *xid.ID {
	if user := GetUser(ctx); user != nil {
		return &user.ID
	}
	return nil
}

// GetUserType retrieves the user type from the context
func GetUserType(ctx context.Context) UserType {
	if user := GetUser(ctx); user != nil {
		return user.UserType
	}
	return ""
}

// GetUserEmail retrieves the user email from the context
func GetUserEmail(ctx context.Context) string {
	if user := GetUser(ctx); user != nil {
		return user.Email
	}
	return ""
}

// HasPermission checks if the user has a specific permission
func HasPermission(ctx context.Context, permission string) bool {
	if user := GetUser(ctx); user != nil {
		for _, perm := range user.Permissions {
			if perm == permission {
				return true
			}
		}
	}
	return false
}

// HasRole checks if the user has a specific role
func HasRole(ctx context.Context, role string) bool {
	if user := GetUser(ctx); user != nil {
		for _, userRole := range user.Roles {
			if userRole.Name == role {
				return true
			}
		}
	}
	return false
}

// IsUserType checks if the user is of a specific type
func IsUserType(ctx context.Context, userType UserType) bool {
	if user := GetUser(ctx); user != nil {
		return user.UserType == userType
	}
	return false
}

// IsInternalUser checks if the user is an internal user
func IsInternalUser(ctx context.Context) bool {
	return IsUserType(ctx, UserTypeInternal)
}

// IsExternalUser checks if the user is an external user
func IsExternalUser(ctx context.Context) bool {
	return IsUserType(ctx, UserTypeExternal)
}

// IsEndUser checks if the user is an end user
func IsEndUser(ctx context.Context) bool {
	return IsUserType(ctx, UserTypeEndUser)
}

// BelongsToOrganization checks if the user belongs to a specific organization
func BelongsToOrganization(ctx context.Context, orgID xid.ID) bool {
	if user := GetUser(ctx); user != nil && user.OrganizationID != nil {
		return *user.OrganizationID == orgID
	}
	return false
}

// GetSessionID retrieves the session ID from the context
func GetSessionID(ctx context.Context) *xid.ID {
	if session := GetSession(ctx); session != nil {
		return &session.ID
	}
	return nil
}

// GetAPIKeyID retrieves the API key ID from the context
func GetAPIKeyID(ctx context.Context) *xid.ID {
	if apiKey := GetAPIKey(ctx); apiKey != nil {
		return &apiKey.ID
	}
	return nil
}

// IsAPIKeyAuth checks if the request was authenticated via API key
func IsAPIKeyAuth(ctx context.Context) bool {
	return GetAuthMethod(ctx) == AuthMethodAPIKey
}

// IsJWTAuth checks if the request was authenticated via JWT
func IsJWTAuth(ctx context.Context) bool {
	return GetAuthMethod(ctx) == AuthMethodJWT
}

// IsSessionAuth checks if the request was authenticated via session
func IsSessionAuth(ctx context.Context) bool {
	return GetAuthMethod(ctx) == AuthMethodSession
}
