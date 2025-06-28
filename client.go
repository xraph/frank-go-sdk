package frank

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/rs/xid"
)

// Client is the main Frank Auth API client
type Client struct {
	config         *Config
	httpClient     *http.Client
	baseURL        string
	secretKey      string
	publishableKey string
	projectID      string
	userType       UserType
	logger         *log.Logger
}

// NewClient creates a new Frank Auth client
func NewClient(config *Config) *Client {
	httpClient := &http.Client{
		Timeout: config.HTTPTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Preserve cookies and authorization headers through redirects
			if len(via) > 0 {
				// Copy cookies from the original request
				for _, cookie := range via[0].Cookies() {
					req.AddCookie(cookie)
				}
				// Copy authorization headers
				if auth := via[0].Header.Get("Authorization"); auth != "" {
					req.Header.Set("Authorization", auth)
				}
				if apiKey := via[0].Header.Get("X-API-Key"); apiKey != "" {
					req.Header.Set("X-API-Key", apiKey)
				}
			}
			return nil
		},
	}

	if config.HTTPClient != nil {
		httpClient = config.HTTPClient
	}

	client := &Client{
		config:         config,
		httpClient:     httpClient,
		baseURL:        strings.TrimSuffix(config.BaseURL, "/"),
		secretKey:      config.SecretKey,
		projectID:      config.ProjectID,
		userType:       config.UserType,
		publishableKey: config.PublishableKey,
	}

	// Initialize logger for debug output
	if config.Debug {
		client.logger = log.New(os.Stdout, "[FRANK-DEBUG] ", log.LstdFlags|log.Lmicroseconds)
		client.debugLog("Client initialized with config: BaseURL=%s, ProjectID=%s, Debug=%t",
			config.BaseURL, config.ProjectID, config.Debug)
	}

	return client
}

// Auth Operations

// Login authenticates a user with email/password or other methods
func (c *Client) Login(ctx context.Context, req LoginRequest) (*LoginResponse, error) {
	c.debugLog("Login called")

	var resp LoginResponse
	if err := c.doRequest(ctx, "POST", "/api/v1/public/auth/login", req, &resp); err != nil {
		c.debugLog("Login failed: %v", err)
		return nil, err
	}

	c.debugLog("Login successful")
	return &resp, nil
}

// Register creates a new user account
func (c *Client) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	c.debugLog("Register called")

	var resp RegisterResponse
	if err := c.doRequest(ctx, "POST", "/api/v1/public/auth/register", req, &resp); err != nil {
		c.debugLog("Register failed: %v", err)
		return nil, err
	}

	c.debugLog("Register successful")
	return &resp, nil
}

// Logout logs out the current user
func (c *Client) Logout(ctx context.Context, req LogoutRequest) (*LogoutResponse, error) {
	c.debugLog("Logout called")

	var resp LogoutResponse
	if err := c.doRequest(ctx, "POST", "/api/v1/me/auth/logout", req, &resp); err != nil {
		c.debugLog("Logout failed: %v", err)
		return nil, err
	}

	c.debugLog("Logout successful")
	return &resp, nil
}

// RefreshToken refreshes an access token using a refresh token
func (c *Client) RefreshToken(ctx context.Context, req RefreshTokenRequest) (*RefreshTokenResponse, error) {
	c.debugLog("RefreshToken called")

	var resp RefreshTokenResponse
	if err := c.doRequest(ctx, "POST", "/api/v1/me/auth/refresh", req, &resp); err != nil {
		c.debugLog("RefreshToken failed: %v", err)
		return nil, err
	}

	c.debugLog("RefreshToken successful")
	return &resp, nil
}

// ForgotPassword initiates password reset process
func (c *Client) ForgotPassword(ctx context.Context, req PasswordResetRequest) (*PasswordResetResponse, error) {
	c.debugLog("ForgotPassword called")

	var resp PasswordResetResponse
	if err := c.doRequest(ctx, "POST", "/api/v1/public/auth/forgot-password", req, &resp); err != nil {
		c.debugLog("ForgotPassword failed: %v", err)
		return nil, err
	}

	c.debugLog("ForgotPassword successful")
	return &resp, nil
}

// ResetPassword completes password reset with token
func (c *Client) ResetPassword(ctx context.Context, req PasswordResetConfirmRequest) (*PasswordResetConfirmResponse, error) {
	c.debugLog("ResetPassword called")

	var resp PasswordResetConfirmResponse
	if err := c.doRequest(ctx, "POST", "/api/v1/public/auth/reset-password", req, &resp); err != nil {
		c.debugLog("ResetPassword failed: %v", err)
		return nil, err
	}

	c.debugLog("ResetPassword successful")
	return &resp, nil
}

// GetAuthStatus gets current authentication status
func (c *Client) GetAuthStatus(ctx context.Context) (*AuthStatus, error) {
	c.debugLog("GetAuthStatus called")

	var resp AuthStatus
	if err := c.doRequest(ctx, "GET", "/api/v1/me/auth/status", nil, &resp); err != nil {
		c.debugLog("GetAuthStatus failed: %v", err)
		return nil, err
	}

	c.debugLog("GetAuthStatus successful")
	return &resp, nil
}

// MFA Operations

// SetupMFA initiates MFA setup for a user
func (c *Client) SetupMFA(ctx context.Context, req SetupMFARequest) (*MFASetupResponse, error) {
	c.debugLog("SetupMFA called")

	var resp MFASetupResponse
	if err := c.doRequest(ctx, "POST", "/api/v1/me/auth/mfa/setup", req, &resp); err != nil {
		c.debugLog("SetupMFA failed: %v", err)
		return nil, err
	}

	c.debugLog("SetupMFA successful")
	return &resp, nil
}

// VerifyMFASetup completes MFA setup verification
func (c *Client) VerifyMFASetup(ctx context.Context, req VerifyMFASetupRequest) (*MFASetupVerifyResponse, error) {
	c.debugLog("VerifyMFASetup called")

	var resp MFASetupVerifyResponse
	if err := c.doRequest(ctx, "POST", "/api/v1/me/auth/mfa/setup/verify", req, &resp); err != nil {
		c.debugLog("VerifyMFASetup failed: %v", err)
		return nil, err
	}

	c.debugLog("VerifyMFASetup successful")
	return &resp, nil
}

// VerifyMFA verifies MFA code during login or management
func (c *Client) VerifyMFA(ctx context.Context, req MFAVerifyRequest) (*MFAVerifyResponse, error) {
	c.debugLog("VerifyMFA called")

	var resp MFAVerifyResponse
	if err := c.doRequest(ctx, "POST", "/api/v1/public/auth/mfa/verify", req, &resp); err != nil {
		c.debugLog("VerifyMFA failed: %v", err)
		return nil, err
	}

	c.debugLog("VerifyMFA successful")
	return &resp, nil
}

// DisableMFA disables MFA for current user
func (c *Client) DisableMFA(ctx context.Context) error {
	c.debugLog("DisableMFA called")

	if err := c.doRequest(ctx, "DELETE", "/api/v1/me/auth/mfa", nil, nil); err != nil {
		c.debugLog("DisableMFA failed: %v", err)
		return err
	}

	c.debugLog("DisableMFA successful")
	return nil
}

// GetMFABackupCodes gets or regenerates MFA backup codes
func (c *Client) GetMFABackupCodes(ctx context.Context, req GenerateBackupCodesRequest) (*MFABackCodes, error) {
	c.debugLog("GetMFABackupCodes called")

	var resp MFABackCodes
	if err := c.doRequest(ctx, "GET", "/api/v1/me/auth/mfa/backup-codes", req, &resp); err != nil {
		c.debugLog("GetMFABackupCodes failed: %v", err)
		return nil, err
	}

	c.debugLog("GetMFABackupCodes successful")
	return &resp, nil
}

// Passkey Operations

// BeginPasskeyRegistration starts passkey registration process
func (c *Client) BeginPasskeyRegistration(ctx context.Context, req PasskeyRegistrationBeginRequest) (*PasskeyRegistrationBeginResponse, error) {
	c.debugLog("BeginPasskeyRegistration called")

	var resp PasskeyRegistrationBeginResponse
	if err := c.doRequest(ctx, "POST", "/api/v1/me/auth/passkeys/register/begin", req, &resp); err != nil {
		c.debugLog("BeginPasskeyRegistration failed: %v", err)
		return nil, err
	}

	c.debugLog("BeginPasskeyRegistration successful")
	return &resp, nil
}

// FinishPasskeyRegistration completes passkey registration
func (c *Client) FinishPasskeyRegistration(ctx context.Context, req PasskeyRegistrationFinishRequest) (*PasskeyRegistrationFinishResponse, error) {
	c.debugLog("FinishPasskeyRegistration called")

	var resp PasskeyRegistrationFinishResponse
	if err := c.doRequest(ctx, "POST", "/api/v1/me/auth/passkeys/register/finish", req, &resp); err != nil {
		c.debugLog("FinishPasskeyRegistration failed: %v", err)
		return nil, err
	}

	c.debugLog("FinishPasskeyRegistration successful")
	return &resp, nil
}

// BeginPasskeyAuthentication starts passkey authentication process
func (c *Client) BeginPasskeyAuthentication(ctx context.Context, req PasskeyAuthenticationBeginRequest) (*PasskeyAuthenticationBeginResponse, error) {
	c.debugLog("BeginPasskeyAuthentication called")

	var resp PasskeyAuthenticationBeginResponse
	if err := c.doRequest(ctx, "POST", "/api/v1/public/auth/passkeys/authenticate/begin", req, &resp); err != nil {
		c.debugLog("BeginPasskeyAuthentication failed: %v", err)
		return nil, err
	}

	c.debugLog("BeginPasskeyAuthentication successful")
	return &resp, nil
}

// FinishPasskeyAuthentication completes passkey authentication
func (c *Client) FinishPasskeyAuthentication(ctx context.Context, req PasskeyAuthenticationFinishRequest) (*PasskeyAuthenticationFinishResponse, error) {
	c.debugLog("FinishPasskeyAuthentication called")

	var resp PasskeyAuthenticationFinishResponse
	if err := c.doRequest(ctx, "POST", "/api/v1/public/auth/passkeys/authenticate/finish", req, &resp); err != nil {
		c.debugLog("FinishPasskeyAuthentication failed: %v", err)
		return nil, err
	}

	c.debugLog("FinishPasskeyAuthentication successful")
	return &resp, nil
}

// ListPasskeys lists user's registered passkeys
func (c *Client) ListPasskeys(ctx context.Context, params PaginationParams) (*PasskeyListResponse, error) {
	c.debugLog("ListPasskeys called")

	var resp PasskeyListResponse
	path := c.buildURLWithParams("/api/v1/me/auth/passkeys", params)
	if err := c.doRequest(ctx, "GET", path, nil, &resp); err != nil {
		c.debugLog("ListPasskeys failed: %v", err)
		return nil, err
	}

	c.debugLog("ListPasskeys successful")
	return &resp, nil
}

// DeletePasskey deletes a specific passkey
func (c *Client) DeletePasskey(ctx context.Context, passkeyID xid.ID) error {
	c.debugLog("DeletePasskey called")

	path := fmt.Sprintf("/api/v1/me/auth/passkeys/%s", passkeyID.String())
	if err := c.doRequest(ctx, "DELETE", path, nil, nil); err != nil {
		c.debugLog("DeletePasskey failed: %v", err)
		return err
	}

	c.debugLog("DeletePasskey successful")
	return nil
}

// Session Management

// ListSessions lists user's active sessions
func (c *Client) ListSessions(ctx context.Context, params ListSessionsParams) (*PaginatedOutput[SessionInfo], error) {
	c.debugLog("ListSessions called")

	var resp PaginatedOutput[SessionInfo]
	path := c.buildURLWithParams("/api/v1/me/auth/sessions", params)
	if err := c.doRequest(ctx, "GET", path, nil, &resp); err != nil {
		c.debugLog("ListSessions failed: %v", err)
		return nil, err
	}

	c.debugLog("ListSessions successful")
	return &resp, nil
}

// RefreshSession extends a session's expiration time
func (c *Client) RefreshSession(ctx context.Context, sessionID xid.ID) (*Session, error) {
	c.debugLog("RefreshSession called")

	path := fmt.Sprintf("/api/v1/me/auth/sessions/%s/refresh", sessionID.String())
	var resp Session
	if err := c.doRequest(ctx, "POST", path, nil, &resp); err != nil {
		c.debugLog("RefreshSession failed: %v", err)
		return nil, err
	}

	c.debugLog("RefreshSession successful")
	return &resp, nil
}

// RevokeSession revokes a specific session
func (c *Client) RevokeSession(ctx context.Context, sessionID xid.ID) error {
	c.debugLog("RevokeSession called")

	path := fmt.Sprintf("/api/v1/me/auth/sessions/%s", sessionID.String())
	if err := c.doRequest(ctx, "DELETE", path, nil, nil); err != nil {
		c.debugLog("RevokeSession failed: %v", err)
		return err
	}

	c.debugLog("RevokeSession successful")
	return nil
}

// RevokeAllSessions revokes all user sessions
func (c *Client) RevokeAllSessions(ctx context.Context, exceptCurrent bool) error {
	c.debugLog("RevokeAllSessions called")

	req := map[string]bool{"exceptCurrent": exceptCurrent}
	if err := c.doRequest(ctx, "DELETE", "/api/v1/me/auth/sessions", req, nil); err != nil {
		c.debugLog("RevokeAllSessions failed: %v", err)
		return err
	}

	c.debugLog("RevokeAllSessions successful")
	return nil
}

// User Profile Management

// GetUserProfile gets current user's profile
func (c *Client) GetUserProfile(ctx context.Context) (*User, error) {
	c.debugLog("GetUserProfile called")

	var resp User
	if err := c.doRequest(ctx, "GET", "/api/v1/me/profile", nil, &resp); err != nil {
		c.debugLog("GetUserProfile failed: %v", err)
		return nil, err
	}

	c.debugLog("GetUserProfile successful")
	return &resp, nil
}

// UpdateUserProfile updates current user's profile
func (c *Client) UpdateUserProfile(ctx context.Context, req UserProfileUpdateRequest) (*User, error) {
	c.debugLog("UpdateUserProfile called")

	var resp User
	if err := c.doRequest(ctx, "PUT", "/api/v1/me/profile", req, &resp); err != nil {
		c.debugLog("UpdateUserProfile failed: %v", err)
		return nil, err
	}

	c.debugLog("UpdateUserProfile successful")
	return &resp, nil
}

// ChangePassword changes current user's password
func (c *Client) ChangePassword(ctx context.Context, req ChangePasswordRequest) error {
	c.debugLog("ChangePassword called")

	if err := c.doRequest(ctx, "POST", "/api/v1/me/change-password", req, nil); err != nil {
		c.debugLog("ChangePassword failed: %v", err)
		return err
	}

	c.debugLog("ChangePassword successful")
	return nil
}

// Organization Operations

// ListPersonalOrganizations lists organizations for current user
func (c *Client) ListPersonalOrganizations(ctx context.Context, params PaginationParams) (*PaginatedOutput[Organization], error) {
	c.debugLog("ListPersonalOrganizations called")

	var resp PaginatedOutput[Organization]
	path := c.buildURLWithParams("/api/v1/me/organizations", params)
	if err := c.doRequest(ctx, "GET", path, nil, &resp); err != nil {
		c.debugLog("ListPersonalOrganizations failed: %v", err)
		return nil, err
	}

	c.debugLog("ListPersonalOrganizations successful")
	return &resp, nil
}

// User Management (Admin Operations)

// ListUsers lists users in an organization
func (c *Client) ListUsers(ctx context.Context, orgID xid.ID, params UserListRequest) (*UserListResponse, error) {
	c.debugLog("ListUsers called for org: %s", orgID)

	var resp UserListResponse
	path := c.buildURLWithParams(fmt.Sprintf("/api/v1/organizations/%s/users", orgID.String()), params)
	if err := c.doRequest(ctx, "GET", path, nil, &resp); err != nil {
		c.debugLog("ListUsers failed: %v", err)
		return nil, err
	}

	c.debugLog("ListUsers successful")
	return &resp, nil
}

// CreateUser creates a new user in organization
func (c *Client) CreateUser(ctx context.Context, orgID xid.ID, req CreateUserRequest) (*User, error) {
	c.debugLog("CreateUser called for org: %s", orgID)

	var resp User
	path := fmt.Sprintf("/api/v1/organizations/%s/users", orgID.String())
	if err := c.doRequest(ctx, "POST", path, req, &resp); err != nil {
		c.debugLog("CreateUser failed: %v", err)
		return nil, err
	}

	c.debugLog("CreateUser successful")
	return &resp, nil
}

// UpdateUser updates a user in organization
func (c *Client) UpdateUser(ctx context.Context, orgID, userID xid.ID, req UpdateUserRequest) (*User, error) {
	c.debugLog("UpdateUser called for org: %s, user: %s", orgID, userID)

	var resp User
	path := fmt.Sprintf("/api/v1/organizations/%s/users/%s", orgID.String(), userID.String())
	if err := c.doRequest(ctx, "PUT", path, req, &resp); err != nil {
		c.debugLog("UpdateUser failed: %v", err)
		return nil, err
	}

	c.debugLog("UpdateUser successful")
	return &resp, nil
}

// DeleteUser deletes a user from organization
func (c *Client) DeleteUser(ctx context.Context, orgID, userID xid.ID, req DeleteUserRequest) error {
	c.debugLog("DeleteUser called for org: %s, user: %s", orgID, userID)

	path := fmt.Sprintf("/api/v1/organizations/%s/users/%s", orgID.String(), userID.String())
	if err := c.doRequest(ctx, "DELETE", path, req, nil); err != nil {
		c.debugLog("DeleteUser failed: %v", err)
		return err
	}

	c.debugLog("DeleteUser successful")
	return nil
}

// SetUserPassword sets password for a user (admin operation)
func (c *Client) SetUserPassword(ctx context.Context, orgID, userID xid.ID, req SetPasswordRequest) error {
	c.debugLog("SetUserPassword called for org: %s, user: %s", orgID, userID)

	path := fmt.Sprintf("/api/v1/organizations/%s/users/%s/set-password", orgID.String(), userID.String())
	if err := c.doRequest(ctx, "POST", path, req, nil); err != nil {
		c.debugLog("SetUserPassword failed: %v", err)
		return err
	}

	c.debugLog("SetUserPassword successful")
	return nil
}

// GetUserSessions gets active sessions for a user
func (c *Client) GetUserSessions(ctx context.Context, orgID, userID xid.ID) ([]*Session, error) {
	c.debugLog("GetUserSessions called for org: %s, user: %s", orgID, userID)

	var resp []*Session
	path := fmt.Sprintf("/api/v1/organizations/%s/users/%s/sessions", orgID.String(), userID.String())
	if err := c.doRequest(ctx, "GET", path, nil, &resp); err != nil {
		c.debugLog("GetUserSessions failed: %v", err)
		return nil, err
	}

	c.debugLog("GetUserSessions successful")
	return resp, nil
}

// RevokeUserSession revokes a specific user session
func (c *Client) RevokeUserSession(ctx context.Context, orgID, userID, sessionID xid.ID) error {
	c.debugLog("RevokeUserSession called for org: %s, user: %s, session: %s", orgID, userID, sessionID)

	path := fmt.Sprintf("/api/v1/organizations/%s/users/%s/sessions/%s", orgID.String(), userID.String(), sessionID.String())
	if err := c.doRequest(ctx, "DELETE", path, nil, nil); err != nil {
		c.debugLog("RevokeUserSession failed: %v", err)
		return err
	}

	c.debugLog("RevokeUserSession successful")
	return nil
}

// RevokeAllUserSessions revokes all sessions for a user
func (c *Client) RevokeAllUserSessions(ctx context.Context, orgID, userID xid.ID) error {
	c.debugLog("RevokeAllUserSessions called for org: %s, user: %s", orgID, userID)

	path := fmt.Sprintf("/api/v1/organizations/%s/users/%s/sessions", orgID.String(), userID.String())
	if err := c.doRequest(ctx, "DELETE", path, nil, nil); err != nil {
		c.debugLog("RevokeAllUserSessions failed: %v", err)
		return err
	}

	c.debugLog("RevokeAllUserSessions successful")
	return nil
}

// Magic Link Operations

// SendMagicLink sends a magic link for passwordless authentication
func (c *Client) SendMagicLink(ctx context.Context, req MagicLinkRequest) (*MagicLinkResponse, error) {
	c.debugLog("SendMagicLink called")

	var resp MagicLinkResponse
	if err := c.doRequest(ctx, "POST", "/api/v1/public/auth/magic-link", req, &resp); err != nil {
		c.debugLog("SendMagicLink failed: %v", err)
		return nil, err
	}

	c.debugLog("SendMagicLink successful")
	return &resp, nil
}

// VerifyMagicLink verifies a magic link token
func (c *Client) VerifyMagicLink(ctx context.Context, token string) (*LoginResponse, error) {
	c.debugLog("VerifyMagicLink called")

	var resp LoginResponse
	path := fmt.Sprintf("/api/v1/public/auth/magic-link/verify/%s", token)
	if err := c.doRequest(ctx, "GET", path, nil, &resp); err != nil {
		c.debugLog("VerifyMagicLink failed: %v", err)
		return nil, err
	}

	c.debugLog("VerifyMagicLink successful")
	return &resp, nil
}

// Email/Phone Verification

// VerifyEmail verifies email address with token
func (c *Client) VerifyEmail(ctx context.Context, req VerificationRequest) (*VerificationResponse, error) {
	c.debugLog("VerifyEmail called")

	var resp VerificationResponse
	if err := c.doRequest(ctx, "POST", "/api/v1/public/auth/verify-email", req, &resp); err != nil {
		c.debugLog("VerifyEmail failed: %v", err)
		return nil, err
	}

	c.debugLog("VerifyEmail successful")
	return &resp, nil
}

// VerifyPhone verifies phone number with SMS code
func (c *Client) VerifyPhone(ctx context.Context, req VerificationRequest) (*VerificationResponse, error) {
	c.debugLog("VerifyPhone called")

	var resp VerificationResponse
	if err := c.doRequest(ctx, "POST", "/api/v1/public/auth/verify-phone", req, &resp); err != nil {
		c.debugLog("VerifyPhone failed: %v", err)
		return nil, err
	}

	c.debugLog("VerifyPhone successful")
	return &resp, nil
}

// ResendVerification resends email or SMS verification
func (c *Client) ResendVerification(ctx context.Context, req ResendVerificationRequest) (*ResendVerificationResponse, error) {
	c.debugLog("ResendVerification called")

	var resp ResendVerificationResponse
	if err := c.doRequest(ctx, "POST", "/api/v1/public/auth/resend-verification", req, &resp); err != nil {
		c.debugLog("ResendVerification failed: %v", err)
		return nil, err
	}

	c.debugLog("ResendVerification successful")
	return &resp, nil
}

// OAuth Operations

// GetOAuthProviders lists available OAuth providers
func (c *Client) GetOAuthProviders(ctx context.Context) ([]AuthProvider, error) {
	c.debugLog("GetOAuthProviders called")

	var resp []AuthProvider
	if err := c.doRequest(ctx, "GET", "/api/v1/public/auth/oauth/providers", nil, &resp); err != nil {
		c.debugLog("GetOAuthProviders failed: %v", err)
		return nil, err
	}

	c.debugLog("GetOAuthProviders successful")
	return resp, nil
}

// GetOAuthAuthorizeURL gets OAuth authorization URL
func (c *Client) GetOAuthAuthorizeURL(ctx context.Context, provider string, state string) (string, error) {
	c.debugLog("GetOAuthAuthorizeURL called for provider: %s", provider)

	path := fmt.Sprintf("/api/v1/public/auth/oauth/%s/authorize", provider)
	if state != "" {
		path += "?state=" + url.QueryEscape(state)
	}

	// This endpoint returns a redirect, so we need to handle it differently
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+path, nil)
	if err != nil {
		return "", err
	}

	// Set headers
	c.setRequestHeaders(req)

	// Don't follow redirects for this request
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		location := resp.Header.Get("Location")
		if location == "" {
			return "", fmt.Errorf("no redirect location found")
		}
		return location, nil
	}

	return "", fmt.Errorf("unexpected response status: %d", resp.StatusCode)
}

// Existing JWT/Token verification methods (keeping for backward compatibility)

// VerifyJWT verifies a JWT token with Frank Auth
func (c *Client) VerifyJWT(ctx context.Context, token string) (*User, error) {
	c.debugLog("VerifyJWT called")

	req := VerifyTokenRequest{
		Token: token,
		Type:  "jwt",
	}

	var resp VerifyTokenResponse
	if err := c.doRequest(ctx, "POST", "/api/v1/auth/verify", req, &resp); err != nil {
		c.debugLog("VerifyJWT failed: %v", err)
		return nil, err
	}

	if !resp.Valid {
		c.debugLog("VerifyJWT: token is invalid")
		return nil, &Error{
			Code:    "INVALID_TOKEN",
			Message: "Token is invalid or expired",
		}
	}

	c.debugLog("VerifyJWT successful for user: %s", resp.User.ID)
	return resp.User, nil
}

// VerifyAPIKey verifies an API key with Frank Auth
func (c *Client) VerifyAPIKey(ctx context.Context, apiKey string) (*APIKey, *User, error) {
	c.debugLog("VerifyAPIKey called")

	req := VerifyTokenRequest{
		Token: apiKey,
		Type:  "api_key",
	}

	var resp VerifyAPIKeyResponse
	if err := c.doRequest(ctx, "POST", "/api/v1/auth/verify", req, &resp); err != nil {
		c.debugLog("VerifyAPIKey failed: %v", err)
		return nil, nil, err
	}

	if !resp.Valid {
		c.debugLog("VerifyAPIKey: API key is invalid")
		return nil, nil, &Error{
			Code:    "INVALID_API_KEY",
			Message: "API key is invalid or expired",
		}
	}

	c.debugLog("VerifyAPIKey successful for user: %s", resp.User.ID)
	return resp.APIKey, resp.User, nil
}

// VerifySession verifies a session token with Frank Auth
func (c *Client) VerifySession(ctx context.Context, sessionToken string) (*Session, *User, error) {
	c.debugLog("VerifySession called")

	req := VerifyTokenRequest{
		Token: sessionToken,
		Type:  "session",
	}

	var resp VerifySessionResponse
	if err := c.doRequest(ctx, "GET", "/api/v1/me/auth/status", req, &resp); err != nil {
		c.debugLog("VerifySession failed: %v", err)
		return nil, nil, err
	}

	if !resp.IsAuthenticated {
		c.debugLog("VerifySession: session is invalid or expired")
		return nil, nil, &Error{
			Code:    "INVALID_SESSION",
			Message: "Session is invalid or expired",
		}
	}

	c.debugLog("VerifySession successful for user: %s", resp.User.ID)
	return resp.Session, resp.User, nil
}

// VerifySessionWithCookies verifies a session token with Frank Auth, forwarding specific cookies
func (c *Client) VerifySessionWithCookies(ctx context.Context, sessionToken string, cookies []*http.Cookie) (*Session, *User, error) {
	c.debugLog("VerifySessionWithCookies called with %d cookies", len(cookies))

	req := VerifyTokenRequest{
		Token: sessionToken,
		Type:  "session",
	}

	var resp VerifySessionResponse
	if err := c.doRequestWithHeadersAndCookies(ctx, "GET", "/api/v1/me/auth/status", req, &resp, nil, cookies); err != nil {
		c.debugLog("VerifySessionWithCookies failed: %v", err)
		return nil, nil, err
	}

	c.debugLog("VerifySessionWithCookies response: IsAuthenticated=%t", resp.IsAuthenticated)

	if !resp.IsAuthenticated {
		c.debugLog("VerifySessionWithCookies: session is invalid or expired")
		return nil, nil, &Error{
			Code:    "INVALID_SESSION",
			Message: "Session is invalid or expired",
		}
	}

	c.debugLog("VerifySessionWithCookies successful for user: %s", resp.User.ID)
	return resp.Session, resp.User, nil
}

// GetUserPermissions retrieves user permissions from Frank Auth
func (c *Client) GetUserPermissions(ctx context.Context, userID xid.ID, orgID *xid.ID) ([]string, error) {
	c.debugLog("GetUserPermissions called for user: %s, org: %v", userID, orgID)

	path := fmt.Sprintf("/api/v1/users/%s/permissions", userID.String())
	if orgID != nil {
		path += fmt.Sprintf("?organizationId=%s", orgID.String())
	}

	var resp UserPermissionsResponse
	if err := c.doRequest(ctx, "GET", path, nil, &resp); err != nil {
		c.debugLog("GetUserPermissions failed: %v", err)
		return nil, err
	}

	c.debugLog("GetUserPermissions returned %d permissions", len(resp.Permissions))
	return resp.Permissions, nil
}

// CheckUserPermission checks if a user has a specific permission
func (c *Client) CheckUserPermission(ctx context.Context, userID xid.ID, permission string, orgID *xid.ID) (bool, error) {
	c.debugLog("CheckUserPermission called for user: %s, permission: %s, org: %v", userID, permission, orgID)

	req := CheckPermissionRequest{
		UserID:     userID,
		Permission: permission,
	}

	if orgID != nil {
		req.OrganizationID = orgID
	}

	path := "/api/v1/auth/permissions/check"
	if orgID != nil {
		path = fmt.Sprintf("/api/v1/organizations/%s/users/permissions/check", orgID.String())
	}

	var resp CheckPermissionResponse
	if err := c.doRequest(ctx, "POST", path, req, &resp); err != nil {
		c.debugLog("CheckUserPermission failed: %v", err)
		return false, err
	}

	c.debugLog("CheckUserPermission result: %t", resp.Allowed)
	return resp.Allowed, nil
}

// GetOrganization retrieves organization information
func (c *Client) GetOrganization(ctx context.Context, orgID xid.ID) (*Organization, error) {
	c.debugLog("GetOrganization called for org: %s", orgID)

	path := fmt.Sprintf("/api/v1/organizations/%s", orgID.String())

	var resp Organization
	if err := c.doRequest(ctx, "GET", path, nil, &resp); err != nil {
		c.debugLog("GetOrganization failed: %v", err)
		return nil, err
	}

	c.debugLog("GetOrganization successful for org: %s", resp.Name)
	return &resp, nil
}

// GetUser retrieves user information
func (c *Client) GetUser(ctx context.Context, userID xid.ID) (*User, error) {
	c.debugLog("GetUser called for user: %s", userID)

	path := fmt.Sprintf("/api/v1/users/%s", userID.String())

	var resp User
	if err := c.doRequest(ctx, "GET", path, nil, &resp); err != nil {
		c.debugLog("GetUser failed: %v", err)
		return nil, err
	}

	c.debugLog("GetUser successful for user: %s", resp.Email)
	return &resp, nil
}

// Health endpoints

// Health checks Frank Auth service health
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	c.debugLog("Health check called")

	var resp HealthResponse
	if err := c.doRequest(ctx, "GET", "/health", nil, &resp); err != nil {
		c.debugLog("Health check failed: %v", err)
		return nil, err
	}

	c.debugLog("Health check successful: %s", resp.Status)
	return &resp, nil
}

// ReadinessCheck checks if service is ready
func (c *Client) ReadinessCheck(ctx context.Context) (*HealthResponse, error) {
	c.debugLog("Readiness check called")

	var resp HealthResponse
	if err := c.doRequest(ctx, "GET", "/ready", nil, &resp); err != nil {
		c.debugLog("Readiness check failed: %v", err)
		return nil, err
	}

	c.debugLog("Readiness check successful: %s", resp.Status)
	return &resp, nil
}

// LivenessCheck checks if service is alive
func (c *Client) LivenessCheck(ctx context.Context) (*HealthResponse, error) {
	c.debugLog("Liveness check called")

	var resp HealthResponse
	if err := c.doRequest(ctx, "GET", "/live", nil, &resp); err != nil {
		c.debugLog("Liveness check failed: %v", err)
		return nil, err
	}

	c.debugLog("Liveness check successful: %s", resp.Status)
	return &resp, nil
}

// DetailedHealthCheck gets comprehensive health information
func (c *Client) DetailedHealthCheck(ctx context.Context) (*HealthResponse, error) {
	c.debugLog("Detailed health check called")

	var resp HealthResponse
	if err := c.doRequest(ctx, "GET", "/health/detailed", nil, &resp); err != nil {
		c.debugLog("Detailed health check failed: %v", err)
		return nil, err
	}

	c.debugLog("Detailed health check successful: %s", resp.Status)
	return &resp, nil
}

// WaitForReady waits for Frank Auth service to be ready
func (c *Client) WaitForReady(ctx context.Context, timeout time.Duration) error {
	c.debugLog("WaitForReady called with timeout: %v", timeout)

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.debugLog("WaitForReady cancelled: %v", ctx.Err())
			return ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				c.debugLog("WaitForReady timed out after %v", timeout)
				return fmt.Errorf("timeout waiting for Frank Auth service to be ready")
			}

			health, err := c.ReadinessCheck(ctx)
			if err == nil && health.Status == "healthy" {
				c.debugLog("WaitForReady completed successfully")
				return nil
			}
			c.debugLog("WaitForReady: service not ready yet, retrying...")
		}
	}
}

// Helper methods

func (c *Client) GetConfig() *Config {
	return c.config
}

// debugLog logs debug messages when debug mode is enabled
func (c *Client) debugLog(format string, args ...interface{}) {
	if c.config.Debug && c.logger != nil {
		c.logger.Printf(format, args...)
	}
}

// debugLogRequest logs HTTP request details
func (c *Client) debugLogRequest(req *http.Request, body []byte) {
	if !c.config.Debug || c.logger == nil {
		return
	}

	c.debugLog("→ HTTP Request: %s %s", req.Method, req.URL.String())

	// Log headers (excluding sensitive ones)
	for name, values := range req.Header {
		if c.isSensitiveHeader(name) {
			c.debugLog("  %s: [REDACTED]", name)
		} else {
			c.debugLog("  %s: %s", name, strings.Join(values, ", "))
		}
	}

	// Log cookies (names only for security)
	if cookies := req.Cookies(); len(cookies) > 0 {
		cookieNames := make([]string, len(cookies))
		for i, cookie := range cookies {
			cookieNames[i] = cookie.Name
		}
		c.debugLog("  Cookies: %s", strings.Join(cookieNames, ", "))
	}

	// Log request body if present
	if body != nil && len(body) > 0 {
		c.debugLog("  Body: %s", string(body))
	}
}

// debugLogResponse logs HTTP response details
func (c *Client) debugLogResponse(resp *http.Response, body []byte, duration time.Duration) {
	if !c.config.Debug || c.logger == nil {
		return
	}

	c.debugLog("← HTTP Response: %d %s (took %v)", resp.StatusCode, resp.Status, duration)

	// Log response headers
	for name, values := range resp.Header {
		c.debugLog("  %s: %s", name, strings.Join(values, ", "))
	}

	// Log response body (truncated if too long)
	if body != nil && len(body) > 0 {
		bodyStr := string(body)
		if len(bodyStr) > 1000 {
			bodyStr = bodyStr[:1000] + "... [truncated]"
		}
		c.debugLog("  Body: %s", bodyStr)
	}
}

// isSensitiveHeader checks if a header contains sensitive information
func (c *Client) isSensitiveHeader(name string) bool {
	sensitiveHeaders := []string{
		"authorization", "x-api-key", "x-publishable-key", "x-user-type",
		"cookie", "set-cookie", "frank_sid",
	}

	lowerName := strings.ToLower(name)
	for _, sensitive := range sensitiveHeaders {
		if lowerName == sensitive || strings.Contains(lowerName, sensitive) {
			return true
		}
	}
	return false
}

// setRequestHeaders sets common request headers
func (c *Client) setRequestHeaders(req *http.Request) {
	// Set default headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", fmt.Sprintf("frank-go-sdk/%s", Version))

	// Set API key authentication
	if c.secretKey != "" {
		req.Header.Set("X-API-Key", c.secretKey)
	}

	// Set project ID if provided
	if c.projectID != "" {
		req.Header.Set("X-Project-ID", c.projectID)
	}

	// Set publishable ID if provided
	if c.publishableKey != "" {
		req.Header.Set("X-Publishable-ID", c.publishableKey)
	}

	// Set user ID if provided
	if c.userType != "" {
		req.Header.Set("X-User-Type", string(c.userType))
	}
}

// buildURLWithParams builds URL with query parameters
func (c *Client) buildURLWithParams(path string, params interface{}) string {
	baseURL := c.baseURL + path

	// Convert params to query string if provided
	if params != nil {
		// This is a simplified implementation - in practice you'd use reflection
		// or a proper query builder to convert struct to query parameters
		u, _ := url.Parse(baseURL)
		q := u.Query()

		// Add pagination params if present
		if p, ok := params.(PaginationParams); ok {
			if p.Page > 0 {
				q.Set("page", fmt.Sprintf("%d", p.Page))
			}
			if p.Limit > 0 {
				q.Set("limit", fmt.Sprintf("%d", p.Limit))
			}
			if p.Sort != "" {
				q.Set("sort", p.Sort)
			}
			if p.Order != "" {
				q.Set("order", p.Order)
			}
		}

		u.RawQuery = q.Encode()
		return u.String()
	}

	return baseURL
}

// doRequest performs an HTTP request to Frank Auth API
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	return c.doRequestWithHeaders(ctx, method, path, body, result, nil)
}

// doRequestWithHeaders performs an HTTP request with custom headers
func (c *Client) doRequestWithHeaders(ctx context.Context, method, path string, body interface{}, result interface{}, headers map[string]string) error {
	startTime := time.Now()
	fullURL := c.baseURL + path

	var bodyReader io.Reader
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			c.debugLog("Failed to marshal request body: %v", err)
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		c.debugLog("Failed to create request: %v", err)
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set common headers
	c.setRequestHeaders(req)

	// Set custom headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Log request details
	c.debugLogRequest(req, bodyBytes)

	// Perform request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		duration := time.Since(startTime)
		c.debugLog("Request failed after %v: %v", duration, err)
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		c.debugLog("Failed to read response body: %v", err)
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Log response details
	duration := time.Since(startTime)
	c.debugLogResponse(resp, respBody, duration)

	// Handle error responses
	if resp.StatusCode >= 400 {
		var errorResp ErrorResponse
		if err := json.Unmarshal(respBody, &errorResp); err == nil && errorResp.Error != nil {
			c.debugLog("API error: %s - %s", errorResp.Error.Code, errorResp.Error.Message)
			return errorResp.Error
		}

		apiError := &Error{
			Code:    fmt.Sprintf("HTTP_%d", resp.StatusCode),
			Message: fmt.Sprintf("Request failed with status %d: %s", resp.StatusCode, string(respBody)),
			Details: map[string]interface{}{
				"status_code": resp.StatusCode,
				"response":    string(respBody),
			},
		}
		c.debugLog("HTTP error: %v", apiError)
		return apiError
	}

	// Parse successful response
	if result != nil {
		if err := json.Unmarshal(respBody, result); err != nil {
			c.debugLog("Failed to parse response: %v", err)
			return fmt.Errorf("failed to parse response: %w", err)
		}
	}

	return nil
}

// doRequestWithHeadersAndCookies performs an HTTP request with custom headers and cookies
func (c *Client) doRequestWithHeadersAndCookies(ctx context.Context, method, path string, body interface{}, result interface{}, headers map[string]string, cookies []*http.Cookie) error {
	startTime := time.Now()
	fullURL := c.baseURL + path

	var bodyReader io.Reader
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			c.debugLog("Failed to marshal request body: %v", err)
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		c.debugLog("Failed to create request: %v", err)
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set common headers
	c.setRequestHeaders(req)

	// Set API key authentication
	if c.secretKey != "" {
		req.Header.Set("X-API-Key", c.secretKey)
		req.Header.Set("X-Publishable-Key", c.secretKey)
	}

	// Set custom headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Forward cookies
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	// Set credential-related headers
	if c.config.IncludeCredentials {
		req.Header.Set("Access-Control-Allow-Credentials", "true")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
	}

	// Log request details
	c.debugLogRequest(req, bodyBytes)

	// Perform request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		duration := time.Since(startTime)
		c.debugLog("Request failed after %v: %v", duration, err)
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		c.debugLog("Failed to read response body: %v", err)
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Log response details
	duration := time.Since(startTime)
	c.debugLogResponse(resp, respBody, duration)

	// Handle error responses
	if resp.StatusCode >= 400 {
		var errorResp ErrorResponse
		if err := json.Unmarshal(respBody, &errorResp); err == nil && errorResp.Error != nil {
			c.debugLog("API error: %s - %s", errorResp.Error.Code, errorResp.Error.Message)
			return errorResp.Error
		}

		apiError := &Error{
			Code:    fmt.Sprintf("HTTP_%d", resp.StatusCode),
			Message: fmt.Sprintf("Request failed with status %d: %s", resp.StatusCode, string(respBody)),
			Details: map[string]interface{}{
				"status_code": resp.StatusCode,
				"response":    string(respBody),
			},
		}
		c.debugLog("HTTP error: %v", apiError)
		return apiError
	}

	// Parse successful response
	if result != nil {
		if err := json.Unmarshal(respBody, result); err != nil {
			c.debugLog("Failed to parse response: %v", err)
			return fmt.Errorf("failed to parse response: %w", err)
		}
	}

	return nil
}
