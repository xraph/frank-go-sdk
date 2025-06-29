package huma

import (
	"github.com/danielgtaylor/huma/v2"
	"github.com/rs/xid"
	"github.com/xraph/frank-go-sdk"
)

// Huma context helpers

// GetUserFromHumaContext retrieves the authenticated user from Huma context
func GetUserFromHumaContext(ctx huma.Context) *frank.User {
	return frank.GetUser(ctx.Context())
}

// GetAuthMethodFromHumaContext retrieves the authentication method from Huma context
func GetAuthMethodFromHumaContext(ctx huma.Context) frank.AuthMethod {
	return frank.GetAuthMethod(ctx.Context())
}

// GetAPIKeyFromHumaContext retrieves the API key information from Huma context
func GetAPIKeyFromHumaContext(ctx huma.Context) *frank.APIKey {
	return frank.GetAPIKey(ctx.Context())
}

// GetSessionFromHumaContext retrieves the session information from Huma context
func GetSessionFromHumaContext(ctx huma.Context) *frank.Session {
	return frank.GetSession(ctx.Context())
}

// GetOrganizationFromHumaContext retrieves the organization information from Huma context
func GetOrganizationFromHumaContext(ctx huma.Context) *frank.Organization {
	return frank.GetOrganization(ctx.Context())
}

// GetOrganizationIDFromHumaContext retrieves the organization ID from Huma context
func GetOrganizationIDFromHumaContext(ctx huma.Context) *xid.ID {
	return frank.GetOrganizationID(ctx.Context())
}

// GetIPAddressFromHumaContext retrieves the client IP address from Huma context
func GetIPAddressFromHumaContext(ctx huma.Context) string {
	return frank.GetIPAddress(ctx.Context())
}

// GetUserAgentFromHumaContext retrieves the user agent from Huma context
func GetUserAgentFromHumaContext(ctx huma.Context) string {
	return frank.GetUserAgent(ctx.Context())
}

// GetRequestIDFromHumaContext retrieves the request ID from Huma context
func GetRequestIDFromHumaContext(ctx huma.Context) string {
	return frank.GetRequestID(ctx.Context())
}

// GetPermissionsFromHumaContext retrieves the user permissions from Huma context
func GetPermissionsFromHumaContext(ctx huma.Context) []string {
	return frank.GetPermissions(ctx.Context())
}

// IsAuthenticatedHuma checks if the Huma context has an authenticated user
func IsAuthenticatedHuma(ctx huma.Context) bool {
	return frank.IsAuthenticated(ctx.Context())
}

// GetUserIDFromHumaContext retrieves the user ID from Huma context
func GetUserIDFromHumaContext(ctx huma.Context) *xid.ID {
	return frank.GetUserID(ctx.Context())
}

// GetUserTypeFromHumaContext retrieves the user type from Huma context
func GetUserTypeFromHumaContext(ctx huma.Context) frank.UserType {
	return frank.GetUserType(ctx.Context())
}

// GetUserEmailFromHumaContext retrieves the user email from Huma context
func GetUserEmailFromHumaContext(ctx huma.Context) string {
	return frank.GetUserEmail(ctx.Context())
}

// HasPermissionHuma checks if the user has a specific permission in Huma context
func HasPermissionHuma(ctx huma.Context, permission string) bool {
	return frank.HasPermission(ctx.Context(), permission)
}

// HasRoleHuma checks if the user has a specific role in Huma context
func HasRoleHuma(ctx huma.Context, role string) bool {
	return frank.HasRole(ctx.Context(), role)
}

// IsUserTypeHuma checks if the user is of a specific type in Huma context
func IsUserTypeHuma(ctx huma.Context, userType frank.UserType) bool {
	return frank.IsUserType(ctx.Context(), userType)
}

// IsInternalUserHuma checks if the user is an internal user in Huma context
func IsInternalUserHuma(ctx huma.Context) bool {
	return frank.IsInternalUser(ctx.Context())
}

// IsExternalUserHuma checks if the user is an external user in Huma context
func IsExternalUserHuma(ctx huma.Context) bool {
	return frank.IsExternalUser(ctx.Context())
}

// IsEndUserHuma checks if the user is an end user in Huma context
func IsEndUserHuma(ctx huma.Context) bool {
	return frank.IsEndUser(ctx.Context())
}

// BelongsToOrganizationHuma checks if the user belongs to a specific organization in Huma context
func BelongsToOrganizationHuma(ctx huma.Context, orgID xid.ID) bool {
	return frank.BelongsToOrganization(ctx.Context(), orgID)
}

// IsJWTAuthHuma checks if the request was authenticated via JWT in Huma context
func IsJWTAuthHuma(ctx huma.Context) bool {
	return frank.IsJWTAuth(ctx.Context())
}

// IsSessionAuthHuma checks if the request was authenticated via session in Huma context
func IsSessionAuthHuma(ctx huma.Context) bool {
	return frank.IsSessionAuth(ctx.Context())
}

// GetSessionIDFromHumaContext retrieves the session ID from Huma context
func GetSessionIDFromHumaContext(ctx huma.Context) *xid.ID {
	return frank.GetSessionID(ctx.Context())
}

// IsAPIKeyAuthHuma checks if the request was authenticated via API key in Huma context
func IsAPIKeyAuthHuma(ctx huma.Context) bool {
	return frank.IsAPIKeyAuth(ctx.Context())
}

// GetAPIKeyIDFromHumaContext retrieves the API key ID from Huma context
func GetAPIKeyIDFromHumaContext(ctx huma.Context) *xid.ID {
	return frank.GetAPIKeyID(ctx.Context())
}
