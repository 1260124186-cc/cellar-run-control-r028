package domain

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	tokenSecretBytes   = 32
	MaxCallerNameBytes = 64
)

var (
	tokenIDPattern     = regexp.MustCompile(`^tok_[0-9a-f]{20}$`)
	tokenSecretPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type TokenStatus string

const (
	TokenActive  TokenStatus = "active"
	TokenExpired TokenStatus = "expired"
	TokenRevoked TokenStatus = "revoked"
)

// AuthToken is the persisted record for one issued caller token. The
// presented secret is never stored; only its SHA-256 hash is kept, so a
// leaked snapshot does not reveal usable credentials.
type AuthToken struct {
	ID         string     `json:"id"`
	Caller     string     `json:"caller"`
	SecretHash string     `json:"secret_hash"`
	IssuedAt   time.Time  `json:"issued_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

func (t AuthToken) Clone() AuthToken {
	if t.RevokedAt != nil {
		copied := *t.RevokedAt
		t.RevokedAt = &copied
	}
	return t
}

// Status resolves the lifecycle state of a token at the given time. A
// revoked token stays revoked even after it would have expired.
func (t AuthToken) Status(now time.Time) TokenStatus {
	if t.RevokedAt != nil {
		return TokenRevoked
	}
	if !now.Before(t.ExpiresAt) {
		return TokenExpired
	}
	return TokenActive
}

func ValidateCallerName(value string) error {
	if value == "" {
		return FieldError(CodeInvalidInput, "caller", "must not be empty")
	}
	if len(value) > MaxCallerNameBytes {
		return FieldError(CodeInvalidInput, "caller", "must be at most 64 characters")
	}
	return nil
}

// NewTokenSecret generates the random secret half of a presented token.
func NewTokenSecret() (string, error) {
	buffer := make([]byte, tokenSecretBytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate token secret: %w", err)
	}
	return hex.EncodeToString(buffer), nil
}

func HashTokenSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// ParsePresentedToken splits a presented bearer token into its record
// identifier and secret. Anything outside the exact issued format is
// rejected as malformed before any lookup happens.
func ParsePresentedToken(value string) (string, string, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 ||
		!tokenIDPattern.MatchString(parts[0]) ||
		!tokenSecretPattern.MatchString(parts[1]) {
		return "", "", NewError(CodeTokenMalformed,
			"the presented token has an invalid format")
	}
	return parts[0], parts[1], nil
}
