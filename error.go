package frank

import (
	"encoding/json"
	"fmt"
	"time"
)

// Error represents a Frank Auth error
type Error struct {
	Code      string                 `json:"code"`
	Message   string                 `json:"message"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Timestamp time.Time              `json:"timestamp,omitempty"`
}

// Error implements the error interface
func (e *Error) Error() string {
	if e.Details != nil {
		if detailsJSON, err := json.Marshal(e.Details); err == nil {
			return fmt.Sprintf("[%s] %s: %s", e.Code, e.Message, string(detailsJSON))
		}
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// ErrorResponse represents an API error response
type ErrorResponse struct {
	Error *Error `json:"error"`
}

// Common error codes
const (
	// Authentication errors
	ErrorCodeUnauthorized       = "UNAUTHORIZED"
	ErrorCodeInvalidCredentials = "INVALID_CREDENTIALS"
	ErrorCodeTokenExpired       = "TOKEN_EXPIRED"
	ErrorCodeTokenInvalid       = "TOKEN_INVALID"
	ErrorCodeInvalidAuthHeader  = "INVALID_AUTH_HEADER"
	ErrorCodeNoAuthHeader       = "NO_AUTH_HEADER"
	ErrorCodeInvalidAPIKey      = "INVALID_API_KEY"
	ErrorCodeNoAPIKey           = "NO_API_KEY"
	ErrorCodeInvalidSession     = "INVALID_SESSION"
	ErrorCodeNoSessionToken     = "NO_SESSION_TOKEN"
	ErrorCodeSessionExpired     = "SESSION_EXPIRED"

	// Authorization errors
	ErrorCodeForbidden               = "FORBIDDEN"
	ErrorCodeInsufficientPermissions = "INSUFFICIENT_PERMISSIONS"
	ErrorCodeInsufficientRole        = "INSUFFICIENT_ROLE"
	ErrorCodeInsufficientUserType    = "INSUFFICIENT_USER_TYPE"
	ErrorCodePermissionCheckFailed   = "PERMISSION_CHECK_FAILED"

	// JWT errors
	ErrorCodeInvalidJWT           = "INVALID_JWT"
	ErrorCodeInvalidJWTClaims     = "INVALID_JWT_CLAIMS"
	ErrorCodeInvalidJWTIssuer     = "INVALID_JWT_ISSUER"
	ErrorCodeInvalidJWTAudience   = "INVALID_JWT_AUDIENCE"
	ErrorCodeInvalidSigningMethod = "INVALID_SIGNING_METHOD"

	// User errors
	ErrorCodeUserNotFound     = "USER_NOT_FOUND"
	ErrorCodeUserInactive     = "USER_INACTIVE"
	ErrorCodeUserNotVerified  = "USER_NOT_VERIFIED"
	ErrorCodeEmailNotVerified = "EMAIL_NOT_VERIFIED"
	ErrorCodePhoneNotVerified = "PHONE_NOT_VERIFIED"
	ErrorCodeMFARequired      = "MFA_REQUIRED"
	ErrorCodeMFAInvalid       = "MFA_INVALID"

	// Organization errors
	ErrorCodeOrganizationNotFound     = "ORGANIZATION_NOT_FOUND"
	ErrorCodeOrganizationInactive     = "ORGANIZATION_INACTIVE"
	ErrorCodeNotOrganizationMember    = "NOT_ORGANIZATION_MEMBER"
	ErrorCodeMissingOrganizationID    = "MISSING_ORGANIZATION_ID"
	ErrorCodeInvalidOrganizationID    = "INVALID_ORGANIZATION_ID"
	ErrorCodeOrganizationAccessDenied = "ORGANIZATION_ACCESS_DENIED"

	// Resource errors
	ErrorCodeResourceNotFound  = "RESOURCE_NOT_FOUND"
	ErrorCodeResourceConflict  = "RESOURCE_CONFLICT"
	ErrorCodeMissingResourceID = "MISSING_RESOURCE_ID"
	ErrorCodeInvalidResourceID = "INVALID_RESOURCE_ID"

	// Validation errors
	ErrorCodeValidationFailed = "VALIDATION_FAILED"
	ErrorCodeInvalidInput     = "INVALID_INPUT"
	ErrorCodeMissingParameter = "MISSING_PARAMETER"
	ErrorCodeInvalidParameter = "INVALID_PARAMETER"
	ErrorCodeInvalidFormat    = "INVALID_FORMAT"

	// Rate limiting errors
	ErrorCodeRateLimitExceeded = "RATE_LIMIT_EXCEEDED"
	ErrorCodeTooManyRequests   = "TOO_MANY_REQUESTS"

	// Configuration errors
	ErrorCodeInvalidConfig      = "INVALID_CONFIG"
	ErrorCodeMissingConfig      = "MISSING_CONFIG"
	ErrorCodeConfigurationError = "CONFIGURATION_ERROR"

	// Network errors
	ErrorCodeNetworkError        = "NETWORK_ERROR"
	ErrorCodeTimeout             = "TIMEOUT"
	ErrorCodeServiceUnavailable  = "SERVICE_UNAVAILABLE"
	ErrorCodeInternalServerError = "INTERNAL_SERVER_ERROR"

	// Cache errors
	ErrorCodeCacheError   = "CACHE_ERROR"
	ErrorCodeCacheMiss    = "CACHE_MISS"
	ErrorCodeCacheExpired = "CACHE_EXPIRED"

	// Webhook errors
	ErrorCodeWebhookDeliveryFailed = "WEBHOOK_DELIVERY_FAILED"
	ErrorCodeWebhookTimeout        = "WEBHOOK_TIMEOUT"
	ErrorCodeWebhookInvalidPayload = "WEBHOOK_INVALID_PAYLOAD"

	// Generic errors
	ErrorCodeUnknown = "UNKNOWN_ERROR"
)

// Predefined error constructors

// NewUnauthorizedError creates an unauthorized error
func NewUnauthorizedError(message string) *Error {
	return &Error{
		Code:      ErrorCodeUnauthorized,
		Message:   message,
		Timestamp: time.Now(),
	}
}

// NewForbiddenError creates a forbidden error
func NewForbiddenError(message string) *Error {
	return &Error{
		Code:      ErrorCodeForbidden,
		Message:   message,
		Timestamp: time.Now(),
	}
}

// NewInvalidCredentialsError creates an invalid credentials error
func NewInvalidCredentialsError() *Error {
	return &Error{
		Code:      ErrorCodeInvalidCredentials,
		Message:   "Invalid credentials provided",
		Timestamp: time.Now(),
	}
}

// NewTokenExpiredError creates a token expired error
func NewTokenExpiredError() *Error {
	return &Error{
		Code:      ErrorCodeTokenExpired,
		Message:   "Token has expired",
		Timestamp: time.Now(),
	}
}

// NewTokenInvalidError creates a token invalid error
func NewTokenInvalidError(reason string) *Error {
	message := "Token is invalid"
	if reason != "" {
		message += ": " + reason
	}
	return &Error{
		Code:      ErrorCodeTokenInvalid,
		Message:   message,
		Timestamp: time.Now(),
	}
}

// NewInvalidJWTError creates an invalid JWT error
func NewInvalidJWTError(reason string) *Error {
	return &Error{
		Code:    ErrorCodeInvalidJWT,
		Message: "Invalid JWT token",
		Details: map[string]interface{}{
			"reason": reason,
		},
		Timestamp: time.Now(),
	}
}

// NewInsufficientPermissionsError creates an insufficient permissions error
func NewInsufficientPermissionsError(permission string) *Error {
	return &Error{
		Code:    ErrorCodeInsufficientPermissions,
		Message: "Insufficient permissions",
		Details: map[string]interface{}{
			"required_permission": permission,
		},
		Timestamp: time.Now(),
	}
}

// NewInsufficientRoleError creates an insufficient role error
func NewInsufficientRoleError(role string) *Error {
	return &Error{
		Code:    ErrorCodeInsufficientRole,
		Message: "Insufficient role",
		Details: map[string]interface{}{
			"required_role": role,
		},
		Timestamp: time.Now(),
	}
}

// NewInsufficientUserTypeError creates an insufficient user type error
func NewInsufficientUserTypeError(userType UserType) *Error {
	return &Error{
		Code:    ErrorCodeInsufficientUserType,
		Message: "Insufficient user type",
		Details: map[string]interface{}{
			"required_user_type": string(userType),
		},
		Timestamp: time.Now(),
	}
}

// NewUserNotFoundError creates a user not found error
func NewUserNotFoundError(userID string) *Error {
	return &Error{
		Code:    ErrorCodeUserNotFound,
		Message: "User not found",
		Details: map[string]interface{}{
			"user_id": userID,
		},
		Timestamp: time.Now(),
	}
}

// NewUserInactiveError creates a user inactive error
func NewUserInactiveError(userID string) *Error {
	return &Error{
		Code:    ErrorCodeUserInactive,
		Message: "User account is inactive",
		Details: map[string]interface{}{
			"user_id": userID,
		},
		Timestamp: time.Now(),
	}
}

// NewOrganizationNotFoundError creates an organization not found error
func NewOrganizationNotFoundError(orgID string) *Error {
	return &Error{
		Code:    ErrorCodeOrganizationNotFound,
		Message: "Organization not found",
		Details: map[string]interface{}{
			"organization_id": orgID,
		},
		Timestamp: time.Now(),
	}
}

// NewNotOrganizationMemberError creates a not organization member error
func NewNotOrganizationMemberError(orgID string) *Error {
	return &Error{
		Code:    ErrorCodeNotOrganizationMember,
		Message: "User is not a member of the organization",
		Details: map[string]interface{}{
			"organization_id": orgID,
		},
		Timestamp: time.Now(),
	}
}

// NewValidationFailedError creates a validation failed error
func NewValidationFailedError(field, reason string) *Error {
	return &Error{
		Code:    ErrorCodeValidationFailed,
		Message: "Validation failed",
		Details: map[string]interface{}{
			"field":  field,
			"reason": reason,
		},
		Timestamp: time.Now(),
	}
}

// NewRateLimitExceededError creates a rate limit exceeded error
func NewRateLimitExceededError(limit int, window string) *Error {
	return &Error{
		Code:    ErrorCodeRateLimitExceeded,
		Message: "Rate limit exceeded",
		Details: map[string]interface{}{
			"limit":  limit,
			"window": window,
		},
		Timestamp: time.Now(),
	}
}

// NewConfigurationError creates a configuration error
func NewConfigurationError(field, reason string) *Error {
	return &Error{
		Code:    ErrorCodeConfigurationError,
		Message: "Configuration error",
		Details: map[string]interface{}{
			"field":  field,
			"reason": reason,
		},
		Timestamp: time.Now(),
	}
}

// NewNetworkError creates a network error
func NewNetworkError(reason string) *Error {
	return &Error{
		Code:    ErrorCodeNetworkError,
		Message: "Network error occurred",
		Details: map[string]interface{}{
			"reason": reason,
		},
		Timestamp: time.Now(),
	}
}

// NewServiceUnavailableError creates a service unavailable error
func NewServiceUnavailableError(service string) *Error {
	return &Error{
		Code:    ErrorCodeServiceUnavailable,
		Message: "Service is currently unavailable",
		Details: map[string]interface{}{
			"service": service,
		},
		Timestamp: time.Now(),
	}
}

// NewInternalServerError creates an internal server error
func NewInternalServerError(reason string) *Error {
	return &Error{
		Code:    ErrorCodeInternalServerError,
		Message: "Internal server error",
		Details: map[string]interface{}{
			"reason": reason,
		},
		Timestamp: time.Now(),
	}
}

// Error type checking helpers

// IsUnauthorizedError checks if the error is an unauthorized error
func IsUnauthorizedError(err error) bool {
	if frankErr, ok := err.(*Error); ok {
		return frankErr.Code == ErrorCodeUnauthorized
	}
	return false
}

// IsForbiddenError checks if the error is a forbidden error
func IsForbiddenError(err error) bool {
	if frankErr, ok := err.(*Error); ok {
		return frankErr.Code == ErrorCodeForbidden
	}
	return false
}

// IsTokenExpiredError checks if the error is a token expired error
func IsTokenExpiredError(err error) bool {
	if frankErr, ok := err.(*Error); ok {
		return frankErr.Code == ErrorCodeTokenExpired
	}
	return false
}

// IsTokenInvalidError checks if the error is a token invalid error
func IsTokenInvalidError(err error) bool {
	if frankErr, ok := err.(*Error); ok {
		return frankErr.Code == ErrorCodeTokenInvalid
	}
	return false
}

// IsUserNotFoundError checks if the error is a user not found error
func IsUserNotFoundError(err error) bool {
	if frankErr, ok := err.(*Error); ok {
		return frankErr.Code == ErrorCodeUserNotFound
	}
	return false
}

// IsOrganizationNotFoundError checks if the error is an organization not found error
func IsOrganizationNotFoundError(err error) bool {
	if frankErr, ok := err.(*Error); ok {
		return frankErr.Code == ErrorCodeOrganizationNotFound
	}
	return false
}

// IsValidationFailedError checks if the error is a validation failed error
func IsValidationFailedError(err error) bool {
	if frankErr, ok := err.(*Error); ok {
		return frankErr.Code == ErrorCodeValidationFailed
	}
	return false
}

// IsRateLimitExceededError checks if the error is a rate limit exceeded error
func IsRateLimitExceededError(err error) bool {
	if frankErr, ok := err.(*Error); ok {
		return frankErr.Code == ErrorCodeRateLimitExceeded
	}
	return false
}

// IsConfigurationError checks if the error is a configuration error
func IsConfigurationError(err error) bool {
	if frankErr, ok := err.(*Error); ok {
		return frankErr.Code == ErrorCodeConfigurationError
	}
	return false
}

// IsNetworkError checks if the error is a network error
func IsNetworkError(err error) bool {
	if frankErr, ok := err.(*Error); ok {
		return frankErr.Code == ErrorCodeNetworkError
	}
	return false
}

// IsServiceUnavailableError checks if the error is a service unavailable error
func IsServiceUnavailableError(err error) bool {
	if frankErr, ok := err.(*Error); ok {
		return frankErr.Code == ErrorCodeServiceUnavailable
	}
	return false
}

// IsInternalServerError checks if the error is an internal server error
func IsInternalServerError(err error) bool {
	if frankErr, ok := err.(*Error); ok {
		return frankErr.Code == ErrorCodeInternalServerError
	}
	return false
}

// IsAuthenticationError checks if the error is any authentication-related error
func IsAuthenticationError(err error) bool {
	if frankErr, ok := err.(*Error); ok {
		switch frankErr.Code {
		case ErrorCodeUnauthorized, ErrorCodeInvalidCredentials, ErrorCodeTokenExpired,
			ErrorCodeTokenInvalid, ErrorCodeInvalidAuthHeader, ErrorCodeNoAuthHeader,
			ErrorCodeInvalidAPIKey, ErrorCodeNoAPIKey, ErrorCodeInvalidSession,
			ErrorCodeNoSessionToken, ErrorCodeSessionExpired:
			return true
		}
	}
	return false
}

// IsAuthorizationError checks if the error is any authorization-related error
func IsAuthorizationError(err error) bool {
	if frankErr, ok := err.(*Error); ok {
		switch frankErr.Code {
		case ErrorCodeForbidden, ErrorCodeInsufficientPermissions,
			ErrorCodeInsufficientRole, ErrorCodeInsufficientUserType,
			ErrorCodePermissionCheckFailed:
			return true
		}
	}
	return false
}

// IsJWTError checks if the error is any JWT-related error
func IsJWTError(err error) bool {
	if frankErr, ok := err.(*Error); ok {
		switch frankErr.Code {
		case ErrorCodeInvalidJWT, ErrorCodeInvalidJWTClaims,
			ErrorCodeInvalidJWTIssuer, ErrorCodeInvalidJWTAudience,
			ErrorCodeInvalidSigningMethod:
			return true
		}
	}
	return false
}

// IsUserError checks if the error is any user-related error
func IsUserError(err error) bool {
	if frankErr, ok := err.(*Error); ok {
		switch frankErr.Code {
		case ErrorCodeUserNotFound, ErrorCodeUserInactive, ErrorCodeUserNotVerified,
			ErrorCodeEmailNotVerified, ErrorCodePhoneNotVerified, ErrorCodeMFARequired,
			ErrorCodeMFAInvalid:
			return true
		}
	}
	return false
}

// IsOrganizationError checks if the error is any organization-related error
func IsOrganizationError(err error) bool {
	if frankErr, ok := err.(*Error); ok {
		switch frankErr.Code {
		case ErrorCodeOrganizationNotFound, ErrorCodeOrganizationInactive,
			ErrorCodeNotOrganizationMember, ErrorCodeMissingOrganizationID,
			ErrorCodeInvalidOrganizationID, ErrorCodeOrganizationAccessDenied:
			return true
		}
	}
	return false
}

// IsClientError checks if the error is a client-side error (4xx equivalent)
func IsClientError(err error) bool {
	if frankErr, ok := err.(*Error); ok {
		switch frankErr.Code {
		case ErrorCodeUnauthorized, ErrorCodeForbidden, ErrorCodeUserNotFound,
			ErrorCodeOrganizationNotFound, ErrorCodeResourceNotFound,
			ErrorCodeValidationFailed, ErrorCodeInvalidInput, ErrorCodeMissingParameter,
			ErrorCodeInvalidParameter, ErrorCodeInvalidFormat, ErrorCodeResourceConflict,
			ErrorCodeRateLimitExceeded, ErrorCodeTooManyRequests:
			return true
		}
	}
	return false
}

// IsServerError checks if the error is a server-side error (5xx equivalent)
func IsServerError(err error) bool {
	if frankErr, ok := err.(*Error); ok {
		switch frankErr.Code {
		case ErrorCodeInternalServerError, ErrorCodeServiceUnavailable,
			ErrorCodeTimeout, ErrorCodeNetworkError, ErrorCodeCacheError:
			return true
		}
	}
	return false
}

// GetErrorCode returns the error code from a Frank Auth error
func GetErrorCode(err error) string {
	if frankErr, ok := err.(*Error); ok {
		return frankErr.Code
	}
	return ErrorCodeUnknown
}

// GetErrorDetails returns the error details from a Frank Auth error
func GetErrorDetails(err error) map[string]interface{} {
	if frankErr, ok := err.(*Error); ok {
		return frankErr.Details
	}
	return nil
}

// WrapError wraps an existing error with additional context
func WrapError(err error, code, message string) *Error {
	details := make(map[string]interface{})
	if frankErr, ok := err.(*Error); ok {
		// If it's already a Frank Auth error, preserve details
		if frankErr.Details != nil {
			for k, v := range frankErr.Details {
				details[k] = v
			}
		}
		details["original_error"] = frankErr.Error()
	} else {
		details["original_error"] = err.Error()
	}

	return &Error{
		Code:      code,
		Message:   message,
		Details:   details,
		Timestamp: time.Now(),
	}
}

// UnwrapError attempts to unwrap a Frank Auth error from a generic error
func UnwrapError(err error) *Error {
	if frankErr, ok := err.(*Error); ok {
		return frankErr
	}

	// Try to parse JSON error response
	if jsonErr := tryParseJSONError(err.Error()); jsonErr != nil {
		return jsonErr
	}

	// Create a generic Frank Auth error
	return &Error{
		Code:      ErrorCodeUnknown,
		Message:   err.Error(),
		Timestamp: time.Now(),
	}
}

// tryParseJSONError attempts to parse a JSON error from an error string
func tryParseJSONError(errString string) *Error {
	var errorResp ErrorResponse
	if err := json.Unmarshal([]byte(errString), &errorResp); err == nil && errorResp.Error != nil {
		return errorResp.Error
	}
	return nil
}
