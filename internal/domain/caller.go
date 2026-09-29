package domain

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"time"
	"unicode/utf8"
)

const (
	// DefaultTokenTTL is applied when an enrollment does not request one.
	DefaultTokenTTL = 30 * 24 * time.Hour
	// MinTokenTTL bounds how short an issued token may live.
	MinTokenTTL = 1 * time.Second
	// MaxTokenTTL bounds token lifetime to one year.
	MaxTokenTTL = 365 * 24 * time.Hour

	maxCallerNameLength = 120
	tokenRandomBytes    = 20
)

var (
	tokenPattern     = regexp.MustCompile(`^cellar_[0-9a-f]{40}$`)
	hexSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	callerIDPattern  = regexp.MustCompile(`^cli_[0-9a-f]{20}$`)
)

// Caller is a registered API client. Only the SHA-256 hash of its token is
// retained; the raw token is returned exactly once at enrollment.
type Caller struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	TokenSHA256 string     `json:"token_sha256"`
	IssuedBy    string     `json:"issued_by,omitempty"`
	IssuedAt    time.Time  `json:"issued_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	RevokedBy   string     `json:"revoked_by,omitempty"`
}

// Clone returns a copy that does not share the caller's pointer fields.
func (c Caller) Clone() Caller {
	cloned := c
	if c.RevokedAt != nil {
		revoked := *c.RevokedAt
		cloned.RevokedAt = &revoked
	}
	return cloned
}

// NewToken returns a fresh opaque bearer token: cellar_ followed by 40
// lowercase hex characters derived from 20 random bytes.
func NewToken() (string, error) {
	buffer := make([]byte, tokenRandomBytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return "cellar_" + hex.EncodeToString(buffer), nil
}

// HashToken returns the lowercase hex SHA-256 digest of a raw bearer token.
func HashToken(rawToken string) string {
	digest := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(digest[:])
}

// ValidateToken reports whether rawToken has the issued token shape.
func ValidateToken(rawToken, field string) error {
	if !tokenPattern.MatchString(rawToken) {
		return FieldError(CodeAuthMalformed, field,
			"must be a bearer token shaped cellar_ followed by 40 lowercase hexadecimal characters")
	}
	return nil
}

// ValidateCallerName checks a whitespace-normalized caller name.
func ValidateCallerName(name, field string) error {
	if name == "" {
		return FieldError(CodeInvalidInput, field, "caller name is required")
	}
	if utf8.RuneCountInString(name) > maxCallerNameLength {
		return FieldError(CodeInvalidInput, field,
			"caller name must contain at most 120 characters")
	}
	return nil
}

// Validate checks a caller recovered from durable storage.
func (c Caller) Validate() error {
	if !callerIDPattern.MatchString(c.ID) {
		return errors.New("stored caller id must be cli_ followed by 20 lowercase hexadecimal characters")
	}
	normalized := NormalizeName(c.Name)
	if normalized != c.Name {
		return errors.New("stored caller name is not whitespace normalized")
	}
	if err := ValidateCallerName(c.Name, "name"); err != nil {
		return err
	}
	if !hexSHA256Pattern.MatchString(c.TokenSHA256) {
		return errors.New("stored token hash must be 64 lowercase hexadecimal characters")
	}
	if c.IssuedAt.IsZero() || c.ExpiresAt.IsZero() || !c.ExpiresAt.After(c.IssuedAt) {
		return errors.New("stored caller timestamps are invalid")
	}
	if c.RevokedAt != nil && c.RevokedAt.Before(c.IssuedAt) {
		return errors.New("stored revocation time precedes issuance")
	}
	return nil
}

// ValidateTokenTTL checks an enrollment lifetime request.
func ValidateTokenTTL(ttl time.Duration, field string) error {
	if ttl < MinTokenTTL || ttl > MaxTokenTTL {
		return FieldError(CodeInvalidInput, field,
			"token lifetime must be between 1 second and 365 days")
	}
	return nil
}
