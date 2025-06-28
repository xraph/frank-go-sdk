package frank

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config represents the Frank Auth SDK configuration
type Config struct {
	// BaseURL is the Frank Auth service base URL
	BaseURL string

	// SessionCookieName defines the name of the session cookie used for authentication and user session management.
	SessionCookieName string

	// IncludeCredentials determines whether HTTP requests should include credentials such as cookies or authentication headers.
	IncludeCredentials bool

	// SecretKey is your Frank Auth API key for server-to-server communication
	SecretKey string

	// PublishableKey is your Frank Auth publishable key for client-side operations
	PublishableKey string

	// ProjectID is your Frank Auth project identifier
	ProjectID string

	// OrganizationID is the default organization context for requests
	UserType UserType

	// JWTSecret is the JWT signing secret (for local JWT verification)
	JWTSecret string

	// JWTIssuer is the expected JWT issuer
	JWTIssuer string

	// JWTAudience is the expected JWT audience
	JWTAudience []string

	// EnableCaching enables response caching
	EnableCaching bool

	// CacheTTL is the cache time-to-live duration
	CacheTTL time.Duration

	// HTTPTimeout is the HTTP client timeout
	HTTPTimeout time.Duration

	// HTTPClient allows using a custom HTTP client
	HTTPClient *http.Client

	// EnablePermissionCaching enables permission caching
	EnablePermissionCaching bool

	// PermissionCacheTTL is the permission cache TTL
	PermissionCacheTTL time.Duration

	// EnableUserCaching enables user context caching
	EnableUserCaching bool

	// UserCacheTTL is the user context cache TTL
	UserCacheTTL time.Duration

	// EnableOrganizationCaching enables organization caching
	EnableOrganizationCaching bool

	// OrganizationCacheTTL is the organization cache TTL
	OrganizationCacheTTL time.Duration

	// Debug enables debug logging
	Debug bool

	// RequireHTTPS requires HTTPS for all requests
	RequireHTTPS bool

	// AllowInsecure allows insecure connections (for development)
	AllowInsecure bool

	// MaxRetries is the maximum number of retries for failed requests
	MaxRetries int

	// RetryDelay is the delay between retries
	RetryDelay time.Duration

	// BackoffMultiplier is the backoff multiplier for retries
	BackoffMultiplier float64

	// RateLimitEnabled enables client-side rate limiting
	RateLimitEnabled bool

	// RateLimitPerSecond is the rate limit per second
	RateLimitPerSecond int

	// RateLimitBurst is the rate limit burst size
	RateLimitBurst int

	// AuthConfig contains authentication-specific configuration
	Auth AuthConfig

	// WebhookConfig contains webhook-specific configuration
	Webhook WebhookConfig

	// OAuthConfig contains OAuth-specific configuration
	OAuth OAuthConfig

	// UserAgent is the user agent string to use for requests
	UserAgent string

	// DefaultUserType is the default user type for registration
	DefaultUserType string

	// AutoVerifyEmails automatically verifies emails in development
	AutoVerifyEmails bool

	// AutoVerifyPhones automatically verifies phone numbers in development
	AutoVerifyPhones bool
}

// AuthConfig contains authentication-specific configuration
type AuthConfig struct {
	// EnableMFA enables multi-factor authentication
	EnableMFA bool

	// MFARequired makes MFA mandatory for all users
	MFARequired bool

	// EnablePasskeys enables WebAuthn passkey support
	EnablePasskeys bool

	// EnableMagicLinks enables magic link authentication
	EnableMagicLinks bool

	// EnableOAuth enables OAuth authentication
	EnableOAuth bool

	// PasswordMinLength is the minimum password length
	PasswordMinLength int

	// PasswordRequireUppercase requires uppercase letters in passwords
	PasswordRequireUppercase bool

	// PasswordRequireLowercase requires lowercase letters in passwords
	PasswordRequireLowercase bool

	// PasswordRequireNumbers requires numbers in passwords
	PasswordRequireNumbers bool

	// PasswordRequireSymbols requires symbols in passwords
	PasswordRequireSymbols bool

	// SessionDuration is the default session duration
	SessionDuration time.Duration

	// RefreshTokenDuration is the refresh token duration
	RefreshTokenDuration time.Duration

	// AccessTokenDuration is the access token duration
	AccessTokenDuration time.Duration

	// MFACodeExpiry is the MFA code expiry time
	MFACodeExpiry time.Duration

	// MagicLinkExpiry is the magic link expiry time
	MagicLinkExpiry time.Duration

	// PasswordResetExpiry is the password reset token expiry time
	PasswordResetExpiry time.Duration

	// EmailVerificationExpiry is the email verification token expiry time
	EmailVerificationExpiry time.Duration

	// PhoneVerificationExpiry is the phone verification code expiry time
	PhoneVerificationExpiry time.Duration
}

// WebhookConfig contains webhook-specific configuration
type WebhookConfig struct {
	// SigningSecret is the webhook signing secret
	SigningSecret string

	// VerifySignatures enables webhook signature verification
	VerifySignatures bool

	// Timeout is the webhook delivery timeout
	Timeout time.Duration

	// MaxRetries is the maximum number of webhook delivery retries
	MaxRetries int

	// RetryDelay is the delay between webhook delivery retries
	RetryDelay time.Duration
}

// OAuthConfig contains OAuth-specific configuration
type OAuthConfig struct {
	// DefaultRedirectURL is the default OAuth redirect URL
	DefaultRedirectURL string

	// AllowedRedirectURLs is a list of allowed OAuth redirect URLs
	AllowedRedirectURLs []string

	// Providers contains provider-specific configuration
	Providers map[string]OAuthProviderConfig
}

// OAuthProviderConfig contains OAuth provider-specific configuration
type OAuthProviderConfig struct {
	// ClientID is the OAuth client ID
	ClientID string

	// ClientSecret is the OAuth client secret
	ClientSecret string

	// Scopes are the default OAuth scopes
	Scopes []string

	// Enabled indicates if the provider is enabled
	Enabled bool
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		BaseURL:                   "https://api.frankauth.com",
		EnableCaching:             true,
		CacheTTL:                  5 * time.Minute,
		HTTPTimeout:               30 * time.Second,
		EnablePermissionCaching:   true,
		PermissionCacheTTL:        10 * time.Minute,
		EnableUserCaching:         true,
		UserCacheTTL:              5 * time.Minute,
		EnableOrganizationCaching: true,
		OrganizationCacheTTL:      15 * time.Minute,
		Debug:                     false,
		RequireHTTPS:              true,
		AllowInsecure:             false,
		MaxRetries:                3,
		RetryDelay:                1 * time.Second,
		BackoffMultiplier:         2.0,
		RateLimitEnabled:          true,
		RateLimitPerSecond:        100,
		RateLimitBurst:            200,
		JWTIssuer:                 "frank",
		SessionCookieName:         "frank_sid",
		IncludeCredentials:        true,
		UserAgent:                 "frank-go-sdk/" + Version,
		DefaultUserType:           "external",
		AutoVerifyEmails:          false,
		AutoVerifyPhones:          false,
		Auth: AuthConfig{
			EnableMFA:                true,
			MFARequired:              false,
			EnablePasskeys:           true,
			EnableMagicLinks:         true,
			EnableOAuth:              true,
			PasswordMinLength:        8,
			PasswordRequireUppercase: true,
			PasswordRequireLowercase: true,
			PasswordRequireNumbers:   true,
			PasswordRequireSymbols:   false,
			SessionDuration:          24 * time.Hour,
			RefreshTokenDuration:     30 * 24 * time.Hour,
			AccessTokenDuration:      1 * time.Hour,
			MFACodeExpiry:            5 * time.Minute,
			MagicLinkExpiry:          15 * time.Minute,
			PasswordResetExpiry:      1 * time.Hour,
			EmailVerificationExpiry:  24 * time.Hour,
			PhoneVerificationExpiry:  10 * time.Minute,
		},
		Webhook: WebhookConfig{
			VerifySignatures: true,
			Timeout:          30 * time.Second,
			MaxRetries:       3,
			RetryDelay:       5 * time.Second,
		},
		OAuth: OAuthConfig{
			DefaultRedirectURL:  "http://localhost:3000/auth/callback",
			AllowedRedirectURLs: []string{},
			Providers:           make(map[string]OAuthProviderConfig),
		},
	}
}

// NewConfigFromEnv creates a configuration from environment variables
func NewConfigFromEnv() *Config {
	config := DefaultConfig()

	if baseURL := os.Getenv("FRANK_BASE_URL"); baseURL != "" {
		config.BaseURL = baseURL
	}

	if apiKey := os.Getenv("FRANK_API_KEY"); apiKey != "" {
		config.SecretKey = apiKey
	}

	if publishableKey := os.Getenv("FRANK_PUBLISHABLE_KEY"); publishableKey != "" {
		config.PublishableKey = publishableKey
	}

	if projectID := os.Getenv("FRANK_PROJECT_ID"); projectID != "" {
		config.ProjectID = projectID
	}

	if userType := os.Getenv("FRANK_USER_TYPE"); userType != "" {
		config.UserType = UserType(userType)
	}

	if jwtSecret := os.Getenv("FRANK_JWT_SECRET"); jwtSecret != "" {
		config.JWTSecret = jwtSecret
	}

	if jwtIssuer := os.Getenv("FRANK_JWT_ISSUER"); jwtIssuer != "" {
		config.JWTIssuer = jwtIssuer
	}

	if jwtAudience := os.Getenv("FRANK_JWT_AUDIENCE"); jwtAudience != "" {
		config.JWTAudience = strings.Split(jwtAudience, ",")
	}

	if enableCaching := os.Getenv("FRANK_ENABLE_CACHING"); enableCaching != "" {
		config.EnableCaching = parseBool(enableCaching, true)
	}

	if cacheTTL := os.Getenv("FRANK_CACHE_TTL"); cacheTTL != "" {
		if duration, err := time.ParseDuration(cacheTTL); err == nil {
			config.CacheTTL = duration
		}
	}

	if httpTimeout := os.Getenv("FRANK_HTTP_TIMEOUT"); httpTimeout != "" {
		if duration, err := time.ParseDuration(httpTimeout); err == nil {
			config.HTTPTimeout = duration
		}
	}

	if enablePermissionCaching := os.Getenv("FRANK_ENABLE_PERMISSION_CACHING"); enablePermissionCaching != "" {
		config.EnablePermissionCaching = parseBool(enablePermissionCaching, true)
	}

	if permissionCacheTTL := os.Getenv("FRANK_PERMISSION_CACHE_TTL"); permissionCacheTTL != "" {
		if duration, err := time.ParseDuration(permissionCacheTTL); err == nil {
			config.PermissionCacheTTL = duration
		}
	}

	if enableUserCaching := os.Getenv("FRANK_ENABLE_USER_CACHING"); enableUserCaching != "" {
		config.EnableUserCaching = parseBool(enableUserCaching, true)
	}

	if userCacheTTL := os.Getenv("FRANK_USER_CACHE_TTL"); userCacheTTL != "" {
		if duration, err := time.ParseDuration(userCacheTTL); err == nil {
			config.UserCacheTTL = duration
		}
	}

	if enableOrganizationCaching := os.Getenv("FRANK_ENABLE_ORGANIZATION_CACHING"); enableOrganizationCaching != "" {
		config.EnableOrganizationCaching = parseBool(enableOrganizationCaching, true)
	}

	if organizationCacheTTL := os.Getenv("FRANK_ORGANIZATION_CACHE_TTL"); organizationCacheTTL != "" {
		if duration, err := time.ParseDuration(organizationCacheTTL); err == nil {
			config.OrganizationCacheTTL = duration
		}
	}

	if debug := os.Getenv("FRANK_DEBUG"); debug != "" {
		config.Debug = parseBool(debug, false)
	}

	if requireHTTPS := os.Getenv("FRANK_REQUIRE_HTTPS"); requireHTTPS != "" {
		config.RequireHTTPS = parseBool(requireHTTPS, true)
	}

	if allowInsecure := os.Getenv("FRANK_ALLOW_INSECURE"); allowInsecure != "" {
		config.AllowInsecure = parseBool(allowInsecure, false)
	}

	if maxRetries := os.Getenv("FRANK_MAX_RETRIES"); maxRetries != "" {
		if retries, err := strconv.Atoi(maxRetries); err == nil {
			config.MaxRetries = retries
		}
	}

	if retryDelay := os.Getenv("FRANK_RETRY_DELAY"); retryDelay != "" {
		if duration, err := time.ParseDuration(retryDelay); err == nil {
			config.RetryDelay = duration
		}
	}

	if backoffMultiplier := os.Getenv("FRANK_BACKOFF_MULTIPLIER"); backoffMultiplier != "" {
		if multiplier, err := strconv.ParseFloat(backoffMultiplier, 64); err == nil {
			config.BackoffMultiplier = multiplier
		}
	}

	if rateLimitEnabled := os.Getenv("FRANK_RATE_LIMIT_ENABLED"); rateLimitEnabled != "" {
		config.RateLimitEnabled = parseBool(rateLimitEnabled, true)
	}

	if rateLimitPerSecond := os.Getenv("FRANK_RATE_LIMIT_PER_SECOND"); rateLimitPerSecond != "" {
		if limit, err := strconv.Atoi(rateLimitPerSecond); err == nil {
			config.RateLimitPerSecond = limit
		}
	}

	if rateLimitBurst := os.Getenv("FRANK_RATE_LIMIT_BURST"); rateLimitBurst != "" {
		if burst, err := strconv.Atoi(rateLimitBurst); err == nil {
			config.RateLimitBurst = burst
		}
	}

	if userAgent := os.Getenv("FRANK_USER_AGENT"); userAgent != "" {
		config.UserAgent = userAgent
	}

	if defaultUserType := os.Getenv("FRANK_DEFAULT_USER_TYPE"); defaultUserType != "" {
		config.DefaultUserType = defaultUserType
	}

	// Auth configuration
	if enableMFA := os.Getenv("FRANK_ENABLE_MFA"); enableMFA != "" {
		config.Auth.EnableMFA = parseBool(enableMFA, true)
	}

	if mfaRequired := os.Getenv("FRANK_MFA_REQUIRED"); mfaRequired != "" {
		config.Auth.MFARequired = parseBool(mfaRequired, false)
	}

	if enablePasskeys := os.Getenv("FRANK_ENABLE_PASSKEYS"); enablePasskeys != "" {
		config.Auth.EnablePasskeys = parseBool(enablePasskeys, true)
	}

	if enableMagicLinks := os.Getenv("FRANK_ENABLE_MAGIC_LINKS"); enableMagicLinks != "" {
		config.Auth.EnableMagicLinks = parseBool(enableMagicLinks, true)
	}

	if enableOAuth := os.Getenv("FRANK_ENABLE_OAUTH"); enableOAuth != "" {
		config.Auth.EnableOAuth = parseBool(enableOAuth, true)
	}

	if passwordMinLength := os.Getenv("FRANK_PASSWORD_MIN_LENGTH"); passwordMinLength != "" {
		if length, err := strconv.Atoi(passwordMinLength); err == nil {
			config.Auth.PasswordMinLength = length
		}
	}

	if sessionDuration := os.Getenv("FRANK_SESSION_DURATION"); sessionDuration != "" {
		if duration, err := time.ParseDuration(sessionDuration); err == nil {
			config.Auth.SessionDuration = duration
		}
	}

	if accessTokenDuration := os.Getenv("FRANK_ACCESS_TOKEN_DURATION"); accessTokenDuration != "" {
		if duration, err := time.ParseDuration(accessTokenDuration); err == nil {
			config.Auth.AccessTokenDuration = duration
		}
	}

	if refreshTokenDuration := os.Getenv("FRANK_REFRESH_TOKEN_DURATION"); refreshTokenDuration != "" {
		if duration, err := time.ParseDuration(refreshTokenDuration); err == nil {
			config.Auth.RefreshTokenDuration = duration
		}
	}

	// Webhook configuration
	if webhookSigningSecret := os.Getenv("FRANK_WEBHOOK_SIGNING_SECRET"); webhookSigningSecret != "" {
		config.Webhook.SigningSecret = webhookSigningSecret
	}

	if verifySignatures := os.Getenv("FRANK_WEBHOOK_VERIFY_SIGNATURES"); verifySignatures != "" {
		config.Webhook.VerifySignatures = parseBool(verifySignatures, true)
	}

	if webhookTimeout := os.Getenv("FRANK_WEBHOOK_TIMEOUT"); webhookTimeout != "" {
		if duration, err := time.ParseDuration(webhookTimeout); err == nil {
			config.Webhook.Timeout = duration
		}
	}

	// OAuth configuration
	if defaultRedirectURL := os.Getenv("FRANK_OAUTH_DEFAULT_REDIRECT_URL"); defaultRedirectURL != "" {
		config.OAuth.DefaultRedirectURL = defaultRedirectURL
	}

	if allowedRedirectURLs := os.Getenv("FRANK_OAUTH_ALLOWED_REDIRECT_URLS"); allowedRedirectURLs != "" {
		config.OAuth.AllowedRedirectURLs = strings.Split(allowedRedirectURLs, ",")
	}

	// OAuth provider configuration
	setupOAuthProvider(config, "google", "FRANK_OAUTH_GOOGLE_CLIENT_ID", "FRANK_OAUTH_GOOGLE_CLIENT_SECRET")
	setupOAuthProvider(config, "github", "FRANK_OAUTH_GITHUB_CLIENT_ID", "FRANK_OAUTH_GITHUB_CLIENT_SECRET")
	setupOAuthProvider(config, "microsoft", "FRANK_OAUTH_MICROSOFT_CLIENT_ID", "FRANK_OAUTH_MICROSOFT_CLIENT_SECRET")
	setupOAuthProvider(config, "discord", "FRANK_OAUTH_DISCORD_CLIENT_ID", "FRANK_OAUTH_DISCORD_CLIENT_SECRET")
	setupOAuthProvider(config, "slack", "FRANK_OAUTH_SLACK_CLIENT_ID", "FRANK_OAUTH_SLACK_CLIENT_SECRET")

	return config
}

// setupOAuthProvider configures an OAuth provider from environment variables
func setupOAuthProvider(config *Config, provider, clientIDEnv, clientSecretEnv string) {
	clientID := os.Getenv(clientIDEnv)
	clientSecret := os.Getenv(clientSecretEnv)

	if clientID != "" && clientSecret != "" {
		config.OAuth.Providers[provider] = OAuthProviderConfig{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Enabled:      true,
			Scopes:       getDefaultOAuthScopes(provider),
		}
	}
}

// getDefaultOAuthScopes returns default scopes for OAuth providers
func getDefaultOAuthScopes(provider string) []string {
	switch provider {
	case "google":
		return []string{"openid", "profile", "email"}
	case "github":
		return []string{"user:email", "read:user"}
	case "microsoft":
		return []string{"openid", "profile", "email"}
	case "discord":
		return []string{"identify", "email"}
	case "slack":
		return []string{"identity.basic", "identity.email"}
	default:
		return []string{"openid", "profile", "email"}
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.BaseURL == "" {
		return &Error{
			Code:    "INVALID_CONFIG",
			Message: "BaseURL is required",
		}
	}

	if c.SecretKey == "" && c.PublishableKey == "" && c.JWTSecret == "" {
		return &Error{
			Code:    "INVALID_CONFIG",
			Message: "Either APIKey, PublishableKey, or JWTSecret is required",
		}
	}

	if c.RequireHTTPS && !strings.HasPrefix(c.BaseURL, "https://") && !c.AllowInsecure {
		return &Error{
			Code:    "INVALID_CONFIG",
			Message: "HTTPS is required but BaseURL does not use HTTPS",
		}
	}

	if c.HTTPTimeout <= 0 {
		return &Error{
			Code:    "INVALID_CONFIG",
			Message: "HTTPTimeout must be greater than 0",
		}
	}

	if c.MaxRetries < 0 {
		return &Error{
			Code:    "INVALID_CONFIG",
			Message: "MaxRetries cannot be negative",
		}
	}

	if c.RetryDelay <= 0 {
		return &Error{
			Code:    "INVALID_CONFIG",
			Message: "RetryDelay must be greater than 0",
		}
	}

	if c.BackoffMultiplier <= 0 {
		return &Error{
			Code:    "INVALID_CONFIG",
			Message: "BackoffMultiplier must be greater than 0",
		}
	}

	if c.RateLimitEnabled {
		if c.RateLimitPerSecond <= 0 {
			return &Error{
				Code:    "INVALID_CONFIG",
				Message: "RateLimitPerSecond must be greater than 0 when rate limiting is enabled",
			}
		}

		if c.RateLimitBurst <= 0 {
			return &Error{
				Code:    "INVALID_CONFIG",
				Message: "RateLimitBurst must be greater than 0 when rate limiting is enabled",
			}
		}
	}

	// Validate auth configuration
	if c.Auth.PasswordMinLength < 4 {
		return &Error{
			Code:    "INVALID_CONFIG",
			Message: "PasswordMinLength must be at least 4",
		}
	}

	if c.Auth.SessionDuration <= 0 {
		return &Error{
			Code:    "INVALID_CONFIG",
			Message: "SessionDuration must be greater than 0",
		}
	}

	if c.Auth.AccessTokenDuration <= 0 {
		return &Error{
			Code:    "INVALID_CONFIG",
			Message: "AccessTokenDuration must be greater than 0",
		}
	}

	if c.Auth.RefreshTokenDuration <= 0 {
		return &Error{
			Code:    "INVALID_CONFIG",
			Message: "RefreshTokenDuration must be greater than 0",
		}
	}

	// Validate webhook configuration
	if c.Webhook.VerifySignatures && c.Webhook.SigningSecret == "" {
		return &Error{
			Code:    "INVALID_CONFIG",
			Message: "WebhookSigningSecret is required when signature verification is enabled",
		}
	}

	if c.Webhook.Timeout <= 0 {
		return &Error{
			Code:    "INVALID_CONFIG",
			Message: "WebhookTimeout must be greater than 0",
		}
	}

	// Validate OAuth configuration
	if c.Auth.EnableOAuth {
		if c.OAuth.DefaultRedirectURL == "" {
			return &Error{
				Code:    "INVALID_CONFIG",
				Message: "DefaultRedirectURL is required when OAuth is enabled",
			}
		}

		for provider, config := range c.OAuth.Providers {
			if config.Enabled {
				if config.ClientID == "" {
					return &Error{
						Code:    "INVALID_CONFIG",
						Message: fmt.Sprintf("ClientID is required for OAuth provider %s", provider),
					}
				}
				if config.ClientSecret == "" {
					return &Error{
						Code:    "INVALID_CONFIG",
						Message: fmt.Sprintf("ClientSecret is required for OAuth provider %s", provider),
					}
				}
			}
		}
	}

	return nil
}

// Clone creates a copy of the configuration
func (c *Config) Clone() *Config {
	clone := *c

	// Deep copy slices
	if c.JWTAudience != nil {
		clone.JWTAudience = make([]string, len(c.JWTAudience))
		copy(clone.JWTAudience, c.JWTAudience)
	}

	if c.OAuth.AllowedRedirectURLs != nil {
		clone.OAuth.AllowedRedirectURLs = make([]string, len(c.OAuth.AllowedRedirectURLs))
		copy(clone.OAuth.AllowedRedirectURLs, c.OAuth.AllowedRedirectURLs)
	}

	// Deep copy OAuth providers
	if c.OAuth.Providers != nil {
		clone.OAuth.Providers = make(map[string]OAuthProviderConfig)
		for k, v := range c.OAuth.Providers {
			providerClone := v
			if v.Scopes != nil {
				providerClone.Scopes = make([]string, len(v.Scopes))
				copy(providerClone.Scopes, v.Scopes)
			}
			clone.OAuth.Providers[k] = providerClone
		}
	}

	return &clone
}

// IsDevelopment returns true if running in development mode
func (c *Config) IsDevelopment() bool {
	return c.Debug || c.AllowInsecure || strings.Contains(c.BaseURL, "localhost") || strings.Contains(c.BaseURL, "127.0.0.1")
}

// IsProduction returns true if running in production mode
func (c *Config) IsProduction() bool {
	return !c.IsDevelopment()
}

// GetAPIKey returns the appropriate API key based on the context
func (c *Config) GetAPIKey() string {
	if c.SecretKey != "" {
		return c.SecretKey
	}
	return c.PublishableKey
}

// SetOAuthProvider sets configuration for an OAuth provider
func (c *Config) SetOAuthProvider(provider, clientID, clientSecret string, scopes []string) {
	if c.OAuth.Providers == nil {
		c.OAuth.Providers = make(map[string]OAuthProviderConfig)
	}

	if scopes == nil {
		scopes = getDefaultOAuthScopes(provider)
	}

	c.OAuth.Providers[provider] = OAuthProviderConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		Enabled:      true,
	}
}

// GetOAuthProvider gets configuration for an OAuth provider
func (c *Config) GetOAuthProvider(provider string) (OAuthProviderConfig, bool) {
	if c.OAuth.Providers == nil {
		return OAuthProviderConfig{}, false
	}

	config, exists := c.OAuth.Providers[provider]
	return config, exists
}

// IsOAuthProviderEnabled checks if an OAuth provider is enabled
func (c *Config) IsOAuthProviderEnabled(provider string) bool {
	if !c.Auth.EnableOAuth {
		return false
	}

	config, exists := c.GetOAuthProvider(provider)
	return exists && config.Enabled && config.ClientID != "" && config.ClientSecret != ""
}

// GetEnabledOAuthProviders returns a list of enabled OAuth providers
func (c *Config) GetEnabledOAuthProviders() []string {
	if !c.Auth.EnableOAuth {
		return []string{}
	}

	var providers []string
	for name, config := range c.OAuth.Providers {
		if config.Enabled && config.ClientID != "" && config.ClientSecret != "" {
			providers = append(providers, name)
		}
	}

	return providers
}

// parseBool parses a boolean string with a default value
func parseBool(value string, defaultValue bool) bool {
	switch strings.ToLower(value) {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	default:
		return defaultValue
	}
}
