package frank

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/xid"
)

// Version of the Frank Go SDK
const Version = "0.0.3"

// UserType represents the type of user in Frank Auth's three-tier system
type UserType string

const (
	// UserTypeInternal represents internal platform users (Frank Auth staff)
	UserTypeInternal UserType = "internal"

	// UserTypeExternal represents external users (customer organization members)
	UserTypeExternal UserType = "external"

	// UserTypeEndUser represents end users (users of customer applications)
	UserTypeEndUser UserType = "end_user"
)

// RoleInfo represents role information for a user
type RoleInfo struct {
	ID          xid.ID    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Type        string    `json:"type"`
	Context     string    `json:"context,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
}

// APIKeyRateLimits represents rate limiting configuration for API keys
type APIKeyRateLimits struct {
	RequestsPerSecond int `json:"requestsPerSecond"`
	RequestsPerMinute int `json:"requestsPerMinute"`
	RequestsPerHour   int `json:"requestsPerHour"`
	RequestsPerDay    int `json:"requestsPerDay"`
	BurstLimit        int `json:"burstLimit"`
}

// JWTClaims represents JWT token claims for Frank Auth
type JWTClaims struct {
	UserID         xid.ID   `json:"user_id"`
	OrganizationID *xid.ID  `json:"organization_id"`
	SessionID      *xid.ID  `json:"session_id"`
	UserType       string   `json:"user_type"`
	Permissions    []string `json:"permissions,omitempty"`
	jwt.RegisteredClaims
}

// UserRolesResponse represents a user roles response
type UserRolesResponse struct {
	UserID            xid.ID     `json:"userId"`
	SystemRoles       []RoleInfo `json:"systemRoles,omitempty"`
	OrganizationRoles []RoleInfo `json:"organizationRoles,omitempty"`
	ApplicationRoles  []RoleInfo `json:"applicationRoles,omitempty"`
}

// FilterParams represents common filtering parameters
type FilterParams struct {
	Search    string     `json:"search,omitempty" query:"search"`
	SortBy    string     `json:"sortBy,omitempty" query:"sortBy"`
	SortOrder string     `json:"sortOrder,omitempty" query:"sortOrder" enum:"asc,desc" default:"asc"`
	Active    *bool      `json:"active,omitempty" query:"active"`
	CreatedAt *time.Time `json:"createdAt,omitempty" query:"createdAt"`
	UpdatedAt *time.Time `json:"updatedAt,omitempty" query:"updatedAt"`
}

// PaginatedResponse represents a paginated response
type PaginatedResponse[T any] struct {
	Data       []T        `json:"data"`
	Pagination Pagination `json:"pagination"`
}

// Pagination represents pagination metadata
type Pagination struct {
	Page       int  `json:"page"`
	PageSize   int  `json:"pageSize"`
	TotalCount int  `json:"totalCount"`
	TotalPages int  `json:"totalPages"`
	HasNext    bool `json:"hasNext"`
	HasPrev    bool `json:"hasPrev"`
}

// List request/response types

// ListUsersRequest represents a request to list users
type ListUsersRequest struct {
	PaginationParams
	FilterParams
	UserType       UserType `json:"userType,omitempty" query:"userType"`
	OrganizationID *xid.ID  `json:"organizationId,omitempty" query:"organizationId"`
	EmailVerified  *bool    `json:"emailVerified,omitempty" query:"emailVerified"`
	MFAEnabled     *bool    `json:"mfaEnabled,omitempty" query:"mfaEnabled"`
}

// ListUsersResponse represents a response containing users
type ListUsersResponse = PaginatedResponse[*User]

// ListOrganizationsRequest represents a request to list organizations
type ListOrganizationsRequest struct {
	PaginationParams
	FilterParams
	Plan   string `json:"plan,omitempty" query:"plan"`
	Domain string `json:"domain,omitempty" query:"domain"`
}

// ListOrganizationsResponse represents a response containing organizations
type ListOrganizationsResponse = PaginatedResponse[*Organization]

// ListAPIKeysRequest represents a request to list API keys
type ListAPIKeysRequest struct {
	PaginationParams
	FilterParams
	Type           string  `json:"type,omitempty" query:"type"`
	UserID         *xid.ID `json:"userId,omitempty" query:"userId"`
	OrganizationID *xid.ID `json:"organizationId,omitempty" query:"organizationId"`
	Expired        *bool   `json:"expired,omitempty" query:"expired"`
}

// ListAPIKeysResponse represents a response containing API keys
type ListAPIKeysResponse = PaginatedResponse[*APIKey]

// ListSessionsRequest represents a request to list sessions
type ListSessionsRequest struct {
	PaginationParams
	FilterParams
	UserID         *xid.ID `json:"userId,omitempty" query:"userId"`
	OrganizationID *xid.ID `json:"organizationId,omitempty" query:"organizationId"`
	Expired        *bool   `json:"expired,omitempty" query:"expired"`
	IPAddress      string  `json:"ipAddress,omitempty" query:"ipAddress"`
}

// ListSessionsResponse represents a response containing sessions
type ListSessionsResponse = PaginatedResponse[*Session]

// WebhookEvent represents a webhook event
type WebhookEvent struct {
	ID           xid.ID                 `json:"id"`
	Type         string                 `json:"type"`
	Data         map[string]interface{} `json:"data"`
	UserID       *xid.ID                `json:"userId,omitempty"`
	SessionID    *xid.ID                `json:"sessionId,omitempty"`
	APIKeyID     *xid.ID                `json:"apiKeyId,omitempty"`
	IPAddress    string                 `json:"ipAddress,omitempty"`
	UserAgent    string                 `json:"userAgent,omitempty"`
	Timestamp    time.Time              `json:"timestamp"`
	DeliveryID   xid.ID                 `json:"deliveryId"`
	AttemptCount int                    `json:"attemptCount"`
}

// Audit and compliance types

// AuditLog represents an audit log entry
type AuditLog struct {
	ID             xid.ID                 `json:"id"`
	Action         string                 `json:"action"`
	Resource       string                 `json:"resource"`
	ResourceID     string                 `json:"resourceId,omitempty"`
	UserID         *xid.ID                `json:"userId,omitempty"`
	SessionID      *xid.ID                `json:"sessionId,omitempty"`
	APIKeyID       *xid.ID                `json:"apiKeyId,omitempty"`
	OrganizationID *xid.ID                `json:"organizationId,omitempty"`
	IPAddress      string                 `json:"ipAddress,omitempty"`
	UserAgent      string                 `json:"userAgent,omitempty"`
	Status         string                 `json:"status"`
	Details        map[string]interface{} `json:"details,omitempty"`
	Timestamp      time.Time              `json:"timestamp"`
	CreatedAt      time.Time              `json:"createdAt"`
}

// SessionStats represents session statistics
type SessionStats struct {
	TotalSessions  int            `json:"totalSessions"`
	ActiveSessions int            `json:"activeSessions"`
	NewSessions    int            `json:"newSessions"`
	SessionsByType map[string]int `json:"sessionsByType"`
	AvgSessionTime time.Duration  `json:"avgSessionTime"`
	TopCountries   map[string]int `json:"topCountries"`
	TopDevices     map[string]int `json:"topDevices"`
	Timestamp      time.Time      `json:"timestamp"`
}

// OrganizationStats represents organization statistics
type OrganizationStats struct {
	TotalOrganizations  int            `json:"totalOrganizations"`
	ActiveOrganizations int            `json:"activeOrganizations"`
	NewOrganizations    int            `json:"newOrganizations"`
	OrganizationsByPlan map[string]int `json:"organizationsByPlan"`
	AvgMembersPerOrg    float64        `json:"avgMembersPerOrg"`
	GrowthRate          float64        `json:"growthRate"`
	Timestamp           time.Time      `json:"timestamp"`
}

// Configuration types for advanced features

// RateLimitConfig represents rate limiting configuration
type RateLimitConfig struct {
	Enabled           bool          `json:"enabled"`
	RequestsPerSecond int           `json:"requestsPerSecond"`
	BurstLimit        int           `json:"burstLimit"`
	WindowSize        time.Duration `json:"windowSize"`
	BlockDuration     time.Duration `json:"blockDuration"`
}

// SecurityConfig represents security configuration
type SecurityConfig struct {
	RequireHTTPS       bool           `json:"requireHttps"`
	AllowedOrigins     []string       `json:"allowedOrigins"`
	TrustedProxies     []string       `json:"trustedProxies"`
	SessionTimeout     time.Duration  `json:"sessionTimeout"`
	MaxSessionsPerUser int            `json:"maxSessionsPerUser"`
	RequireMFA         bool           `json:"requireMfa"`
	PasswordPolicy     PasswordPolicy `json:"passwordPolicy"`
}

// PasswordPolicy represents password policy configuration
type PasswordPolicy struct {
	MinLength        int           `json:"minLength"`
	RequireUppercase bool          `json:"requireUppercase"`
	RequireLowercase bool          `json:"requireLowercase"`
	RequireNumbers   bool          `json:"requireNumbers"`
	RequireSymbols   bool          `json:"requireSymbols"`
	MaxAge           time.Duration `json:"maxAge"`
	PreventReuse     int           `json:"preventReuse"`
}

type PaginationParams struct {
	Page   int    `json:"page,omitempty" url:"page,omitempty"`
	Limit  int    `json:"limit,omitempty" url:"limit,omitempty"`
	Sort   string `json:"sort,omitempty" url:"sort,omitempty"`
	Order  string `json:"order,omitempty" url:"order,omitempty"`
	Search string `json:"search,omitempty" url:"search,omitempty"`
}

type PaginationMeta struct {
	Page       int   `json:"page"`
	Limit      int   `json:"limit"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"totalPages"`
	HasNext    bool  `json:"hasNext"`
	HasPrev    bool  `json:"hasPrev"`
}

type PaginatedOutput[T any] struct {
	Data       []T            `json:"data"`
	Pagination PaginationMeta `json:"pagination"`
}

// Authentication types

type LoginRequest struct {
	Email       string `json:"email,omitempty"`
	Username    string `json:"username,omitempty"`
	PhoneNumber string `json:"phoneNumber,omitempty"`
	Password    string `json:"password,omitempty"`
	Provider    string `json:"provider,omitempty"`
	RememberMe  bool   `json:"rememberMe,omitempty"`
}

type LoginResponse struct {
	Success              bool     `json:"success"`
	User                 *User    `json:"user,omitempty"`
	AccessToken          string   `json:"accessToken,omitempty"`
	RefreshToken         string   `json:"refreshToken,omitempty"`
	ExpiresIn            int      `json:"expiresIn,omitempty"`
	Session              *Session `json:"session,omitempty"`
	VerificationRequired bool     `json:"verificationRequired,omitempty"`
	MFARequired          bool     `json:"mfaRequired,omitempty"`
	MFAToken             string   `json:"mfaToken,omitempty"`
	Message              string   `json:"message,omitempty"`
}

type RegisterRequest struct {
	Email            string                 `json:"email"`
	Password         string                 `json:"password,omitempty"`
	FirstName        *string                `json:"firstName,omitempty"`
	LastName         *string                `json:"lastName,omitempty"`
	PhoneNumber      *string                `json:"phoneNumber,omitempty"`
	Username         string                 `json:"username,omitempty"`
	UserType         string                 `json:"userType,omitempty"`
	OrganizationID   *xid.ID                `json:"organizationId,omitempty"`
	AcceptTerms      bool                   `json:"acceptTerms,omitempty"`
	AcceptPrivacy    bool                   `json:"acceptPrivacy,omitempty"`
	CustomAttributes map[string]interface{} `json:"customAttributes,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

type RegisterResponse struct {
	Success      bool   `json:"success"`
	User         *User  `json:"user,omitempty"`
	AccessToken  string `json:"accessToken,omitempty"`
	RefreshToken string `json:"refreshToken,omitempty"`
	ExpiresIn    int    `json:"expiresIn,omitempty"`
	Message      string `json:"message,omitempty"`
}

type LogoutRequest struct {
	LogoutAll bool `json:"logoutAll,omitempty"`
}

type LogoutResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken"`
}

type RefreshTokenResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken,omitempty"`
	ExpiresIn    int    `json:"expiresIn"`
}

type AuthStatus struct {
	IsAuthenticated bool                   `json:"isAuthenticated"`
	User            *User                  `json:"user,omitempty"`
	Session         *Session               `json:"session,omitempty"`
	Organization    *Organization          `json:"organization,omitempty"`
	Roles           []string               `json:"roles,omitempty"`
	Permissions     []string               `json:"permissions,omitempty"`
	Scopes          []string               `json:"scopes,omitempty"`
	HasAPIAccess    bool                   `json:"hasAPIAccess,omitempty"`
	APIKeyType      string                 `json:"apiKeyType,omitempty"`
	APIKeyID        *xid.ID                `json:"apiKeyId,omitempty"`
	OrganizationID  *xid.ID                `json:"organizationId,omitempty"`
	Context         map[string]interface{} `json:"context,omitempty"`
}

// Password reset types

type PasswordResetRequest struct {
	Email string `json:"email"`
}

type PasswordResetResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Token   string `json:"token,omitempty"` // Only in development
}

type PasswordResetConfirmRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"newPassword"`
}

type PasswordResetConfirmResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

type SetPasswordRequest struct {
	NewPassword string `json:"newPassword"`
	Notify      bool   `json:"notify,omitempty"`
}

// MFA types

type SetupMFARequest struct {
	Method      string `json:"method"`
	PhoneNumber string `json:"phoneNumber,omitempty"`
	Email       string `json:"email,omitempty"`
	Name        string `json:"name,omitempty"`
}

type MFASetupResponse struct {
	Method                   string `json:"method"`
	MethodID                 xid.ID `json:"methodId"`
	Secret                   string `json:"secret,omitempty"`
	QRCode                   string `json:"qrCode,omitempty"`
	BackupURL                string `json:"backupUrl,omitempty"`
	PhoneNumber              string `json:"phoneNumber,omitempty"`
	Email                    string `json:"email,omitempty"`
	RequiresVerification     bool   `json:"requiresVerification"`
	VerificationInstructions string `json:"verificationInstructions,omitempty"`
	Message                  string `json:"message,omitempty"`
}

type VerifyMFASetupRequest struct {
	MethodID            *xid.ID `json:"methodId,omitempty"`
	Method              string  `json:"method,omitempty"`
	Code                string  `json:"code"`
	GenerateBackupCodes bool    `json:"generateBackupCodes,omitempty"`
}

type MFASetupVerifyResponse struct {
	Success     bool     `json:"success"`
	Method      string   `json:"method"`
	MethodID    xid.ID   `json:"methodId"`
	Message     string   `json:"message"`
	IsVerified  bool     `json:"isVerified"`
	BackupCodes []string `json:"backupCodes,omitempty"`
}

type MFAVerifyRequest struct {
	Code     string `json:"code"`
	Method   string `json:"method,omitempty"`
	MFAToken string `json:"mfaToken,omitempty"`
}

type MFAVerifyResponse struct {
	Success   bool           `json:"success"`
	Method    string         `json:"method"`
	Message   string         `json:"message"`
	LoginData *LoginResponse `json:"loginData,omitempty"`
}

type GenerateBackupCodesRequest struct {
	Count int `json:"count,omitempty"`
}

type MFABackCodes struct {
	Codes     []string  `json:"codes"`
	Generated time.Time `json:"generated"`
	Count     int       `json:"count"`
}

// Passkey types

type PasskeyRegistrationBeginRequest struct {
	Username          string `json:"username,omitempty"`
	DisplayName       string `json:"displayName,omitempty"`
	AuthenticatorType string `json:"authenticatorType,omitempty"`
}

type PasskeyRegistrationBeginResponse struct {
	SessionID string      `json:"sessionId"`
	Options   interface{} `json:"options"` // WebAuthn CredentialCreationOptions
}

type PasskeyRegistrationFinishRequest struct {
	SessionID string      `json:"sessionId"`
	Name      string      `json:"name,omitempty"`
	Response  interface{} `json:"response"` // WebAuthn CredentialCreationResponse
}

type PasskeyRegistrationFinishResponse struct {
	Success bool     `json:"success"`
	Passkey *Passkey `json:"passkey"`
	Message string   `json:"message"`
}

type PasskeyAuthenticationBeginRequest struct {
	Username string `json:"username,omitempty"`
}

type PasskeyAuthenticationBeginResponse struct {
	SessionID string      `json:"sessionId"`
	Options   interface{} `json:"options"` // WebAuthn CredentialRequestOptions
}

type PasskeyAuthenticationFinishRequest struct {
	SessionID string      `json:"sessionId"`
	Response  interface{} `json:"response"` // WebAuthn CredentialAssertionResponse
}

type PasskeyAuthenticationFinishResponse struct {
	Success      bool   `json:"success"`
	User         *User  `json:"user"`
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    int    `json:"expiresIn"`
	Message      string `json:"message"`
}

type PasskeyListRequest struct {
	PaginationParams
	UserID     OptionalParam[xid.ID] `json:"userId,omitempty"`
	Active     OptionalParam[bool]   `json:"active,omitempty"`
	DeviceType string                `json:"deviceType,omitempty"`
}

type PasskeyListResponse struct {
	Data       []*Passkey     `json:"data"`
	Pagination PaginationMeta `json:"pagination"`
}

type Passkey struct {
	ID              xid.ID                 `json:"id"`
	UserID          xid.ID                 `json:"userId"`
	Name            string                 `json:"name"`
	CredentialID    string                 `json:"credentialId"`
	PublicKey       string                 `json:"publicKey"`
	AttestationType string                 `json:"attestationType"`
	Transport       []string               `json:"transport"`
	DeviceType      string                 `json:"deviceType"`
	BackedUp        bool                   `json:"backedUp"`
	LastUsedAt      *time.Time             `json:"lastUsedAt,omitempty"`
	CreatedAt       time.Time              `json:"createdAt"`
	UpdatedAt       time.Time              `json:"updatedAt"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// Magic Link types

type MagicLinkRequest struct {
	Email       string `json:"email"`
	RedirectURL string `json:"redirectUrl,omitempty"`
}

type MagicLinkResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Token   string `json:"token,omitempty"` // Only in development
}

// Verification types

type VerificationRequest struct {
	Token       string `json:"token"`
	Email       string `json:"email,omitempty"`
	PhoneNumber string `json:"phoneNumber,omitempty"`
}

type VerificationResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type ResendVerificationRequest struct {
	Email       string `json:"email,omitempty"`
	PhoneNumber string `json:"phoneNumber,omitempty"`
	Type        string `json:"type"`
}

type ResendVerificationResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// OAuth types

type AuthProvider struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Icon        string `json:"icon,omitempty"`
	Enabled     bool   `json:"enabled"`
}

// Session types

type ListSessionsParams struct {
	PaginationParams
	Active bool `json:"active,omitempty"`
}

type Session struct {
	ID           xid.ID                 `json:"id"`
	UserID       xid.ID                 `json:"userId"`
	Token        string                 `json:"token,omitempty"`
	IPAddress    *string                `json:"ipAddress,omitempty"`
	UserAgent    *string                `json:"userAgent,omitempty"`
	DeviceID     *string                `json:"deviceId,omitempty"`
	Location     *string                `json:"location,omitempty"`
	Active       bool                   `json:"active"`
	ExpiresAt    time.Time              `json:"expiresAt"`
	LastActiveAt *time.Time             `json:"lastActiveAt,omitempty"`
	CreatedAt    time.Time              `json:"createdAt"`
	UpdatedAt    time.Time              `json:"updatedAt"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

type SessionInfo struct {
	ID           xid.ID     `json:"id"`
	UserID       xid.ID     `json:"userId"`
	IPAddress    *string    `json:"ipAddress,omitempty"`
	UserAgent    *string    `json:"userAgent,omitempty"`
	DeviceID     *string    `json:"deviceId,omitempty"`
	Location     *string    `json:"location,omitempty"`
	Active       bool       `json:"active"`
	ExpiresAt    time.Time  `json:"expiresAt"`
	LastActiveAt *time.Time `json:"lastActiveAt,omitempty"`
	CreatedAt    time.Time  `json:"createdAt"`
}

// User types

type User struct {
	ID               xid.ID                 `json:"id"`
	Email            string                 `json:"email"`
	EmailVerified    bool                   `json:"emailVerified"`
	Username         *string                `json:"username,omitempty"`
	FirstName        *string                `json:"firstName,omitempty"`
	LastName         *string                `json:"lastName,omitempty"`
	PhoneNumber      *string                `json:"phoneNumber,omitempty"`
	PhoneVerified    bool                   `json:"phoneVerified"`
	ProfileImageURL  *string                `json:"profileImageUrl,omitempty"`
	OrganizationID   *xid.ID                `json:"organizationId,omitempty"`
	UserType         UserType               `json:"userType"`
	Active           bool                   `json:"active"`
	MFAEnabled       bool                   `json:"mfaEnabled"`
	LastLoginAt      *time.Time             `json:"lastLoginAt,omitempty"`
	CreatedAt        time.Time              `json:"createdAt"`
	UpdatedAt        time.Time              `json:"updatedAt"`
	CustomAttributes map[string]interface{} `json:"customAttributes,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	Roles            []RoleInfo             `json:"roles,omitempty"`
	Permissions      []string               `json:"permissions,omitempty"`
	Scopes           []string               `json:"scopes,omitempty"`
}

type UserProfileUpdateRequest struct {
	FirstName       *string                `json:"firstName,omitempty"`
	LastName        *string                `json:"lastName,omitempty"`
	Username        *string                `json:"username,omitempty"`
	PhoneNumber     *string                `json:"phoneNumber,omitempty"`
	ProfileImageURL *string                `json:"profileImageUrl,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

type UserListRequest struct {
	PaginationParams
	OrganizationID *xid.ID `json:"organizationId,omitempty"`
	UserType       string  `json:"userType,omitempty"`
	Active         *bool   `json:"active,omitempty"`
	MFAEnabled     *bool   `json:"mfaEnabled,omitempty"`
	EmailVerified  *bool   `json:"emailVerified,omitempty"`
	Search         string  `json:"search,omitempty"`
}

type UserListResponse struct {
	Data       []*User        `json:"data"`
	Pagination PaginationMeta `json:"pagination"`
}

type CreateUserRequest struct {
	Email            string                 `json:"email"`
	Password         string                 `json:"password,omitempty"`
	FirstName        *string                `json:"firstName,omitempty"`
	LastName         *string                `json:"lastName,omitempty"`
	Username         *string                `json:"username,omitempty"`
	PhoneNumber      *string                `json:"phoneNumber,omitempty"`
	UserType         string                 `json:"userType,omitempty"`
	OrganizationID   *xid.ID                `json:"organizationId,omitempty"`
	SendInvitation   bool                   `json:"sendInvitation,omitempty"`
	CustomAttributes map[string]interface{} `json:"customAttributes,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

type UpdateUserRequest struct {
	FirstName        *string                `json:"firstName,omitempty"`
	LastName         *string                `json:"lastName,omitempty"`
	Username         *string                `json:"username,omitempty"`
	PhoneNumber      *string                `json:"phoneNumber,omitempty"`
	Active           *bool                  `json:"active,omitempty"`
	CustomAttributes map[string]interface{} `json:"customAttributes,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

type DeleteUserRequest struct {
	TransferOwnership bool    `json:"transferOwnership,omitempty"`
	NewOwnerID        *xid.ID `json:"newOwnerId,omitempty"`
}

// Organization types

type Organization struct {
	ID                     xid.ID                 `json:"id"`
	Name                   string                 `json:"name"`
	Slug                   string                 `json:"slug"`
	Domain                 *string                `json:"domain,omitempty"`
	Plan                   string                 `json:"plan"`
	Active                 bool                   `json:"active"`
	IsPlatformOrganization bool                   `json:"isPlatformOrganization"`
	OrgType                string                 `json:"orgType"`
	LogoURL                *string                `json:"logoUrl,omitempty"`
	Website                *string                `json:"website,omitempty"`
	Description            *string                `json:"description,omitempty"`
	Settings               map[string]interface{} `json:"settings,omitempty"`
	Metadata               map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt              time.Time              `json:"createdAt"`
	UpdatedAt              time.Time              `json:"updatedAt"`
}

// API Key types

type APIKey struct {
	ID             xid.ID    `json:"id"`
	Name           string    `json:"name"`
	Type           string    `json:"type"`
	Key            string    `json:"key,omitempty"`
	UserID         xid.ID    `json:"userId"`
	OrganizationID *xid.ID   `json:"organizationId,omitempty"`
	Permissions    []string  `json:"permissions"`
	Scopes         []string  `json:"scopes"`
	Active         bool      `json:"active"`
	ExpiresAt      time.Time `json:"expiresAt"`
	LastUsedAt     time.Time `json:"lastUsedAt"`
	CreatedAt      time.Time `json:"createdAt"`
}

// Health types

type HealthResponse struct {
	Status      string                 `json:"status"`
	Timestamp   time.Time              `json:"timestamp"`
	Version     string                 `json:"version"`
	Environment string                 `json:"environment"`
	Uptime      int64                  `json:"uptime"`
	Components  map[string]interface{} `json:"components,omitempty"`
}

// Existing verification types (for backward compatibility)

type VerifyTokenRequest struct {
	Token string `json:"token"`
	Type  string `json:"type"`
}

type VerifyTokenResponse struct {
	Valid bool  `json:"valid"`
	User  *User `json:"user,omitempty"`
}

type VerifyAPIKeyResponse struct {
	Valid  bool    `json:"valid"`
	APIKey *APIKey `json:"apiKey,omitempty"`
	User   *User   `json:"user,omitempty"`
}

type VerifySessionResponse struct {
	IsAuthenticated bool     `json:"isAuthenticated"`
	Session         *Session `json:"session,omitempty"`
	User            *User    `json:"user,omitempty"`
}

type UserPermissionsResponse struct {
	Permissions []string `json:"permissions"`
}

type CheckPermissionRequest struct {
	UserID         xid.ID  `json:"userId"`
	Permission     string  `json:"permission"`
	OrganizationID *xid.ID `json:"organizationId,omitempty"`
}

type CheckPermissionResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

// Helper types

type OptionalParam[T any] struct {
	Value T    `json:"value"`
	IsSet bool `json:"isSet"`
}

// Additional user management types

type UserActivityRequest struct {
	PaginationParams
	ActionTypes []string   `json:"actionTypes,omitempty"`
	StartDate   *time.Time `json:"startDate,omitempty"`
	EndDate     *time.Time `json:"endDate,omitempty"`
}

type UserActivityResponse struct {
	Data       []*ActivityLog `json:"data"`
	Pagination PaginationMeta `json:"pagination"`
}

type ActivityLog struct {
	ID         xid.ID                 `json:"id"`
	UserID     xid.ID                 `json:"userId"`
	Action     string                 `json:"action"`
	Resource   string                 `json:"resource"`
	ResourceID *xid.ID                `json:"resourceId,omitempty"`
	IPAddress  string                 `json:"ipAddress"`
	UserAgent  string                 `json:"userAgent"`
	Status     string                 `json:"status"`
	Details    map[string]interface{} `json:"details,omitempty"`
	CreatedAt  time.Time              `json:"createdAt"`
}

type UserStats struct {
	TotalUsers      int                    `json:"totalUsers"`
	ActiveUsers     int                    `json:"activeUsers"`
	NewUsers        int                    `json:"newUsers"`
	VerifiedUsers   int                    `json:"verifiedUsers"`
	MFAEnabledUsers int                    `json:"mfaEnabledUsers"`
	UsersByType     map[string]int         `json:"usersByType"`
	UserGrowth      map[string]int         `json:"userGrowth"`
	LoginActivity   map[string]int         `json:"loginActivity"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

type BulkUserOperation struct {
	Operation      string                 `json:"operation"`
	UserIDs        []xid.ID               `json:"userIds"`
	Data           map[string]interface{} `json:"data,omitempty"`
	OrganizationID *xid.ID                `json:"organizationId,omitempty"`
}

type BulkUserOperationResponse struct {
	Success   bool     `json:"success"`
	Processed int      `json:"processed"`
	Failed    int      `json:"failed"`
	Errors    []string `json:"errors,omitempty"`
	Message   string   `json:"message"`
}

// Role and Permission types

type Role struct {
	ID             xid.ID                 `json:"id"`
	Name           string                 `json:"name"`
	DisplayName    string                 `json:"displayName"`
	Description    string                 `json:"description"`
	Type           string                 `json:"type"`
	OrganizationID *xid.ID                `json:"organizationId,omitempty"`
	Permissions    []string               `json:"permissions"`
	Active         bool                   `json:"active"`
	CreatedAt      time.Time              `json:"createdAt"`
	UpdatedAt      time.Time              `json:"updatedAt"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

type Permission struct {
	ID          xid.ID    `json:"id"`
	Name        string    `json:"name"`
	DisplayName string    `json:"displayName"`
	Description string    `json:"description"`
	Resource    string    `json:"resource"`
	Action      string    `json:"action"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type AssignRoleRequest struct {
	RoleID string `json:"roleId"`
}

type AssignPermissionRequest struct {
	PermissionID string `json:"permissionId"`
}
