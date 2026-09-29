package service

import (
	"crypto/subtle"
	"sort"
	"time"

	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/domain"
)

const (
	// DefaultTokenTTL is used when neither configuration nor a registration
	// request specifies a lifetime.
	DefaultTokenTTL = 24 * time.Hour
	// MaxTokenTTL bounds a single issued token to 30 days.
	MaxTokenTTL = 30 * 24 * time.Hour
)

type RegisterTokenInput struct {
	Caller     string
	TTLSeconds int64
}

// IssuedToken pairs the persisted record with the presented token string.
// The presented value is available only once, at registration time.
type IssuedToken struct {
	Record domain.AuthToken
	Token  string
}

func normalizeTokenTTL(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		return DefaultTokenTTL
	}
	if ttl > MaxTokenTTL {
		return MaxTokenTTL
	}
	return ttl
}

// RegisterToken issues a new token for a caller. A caller can hold at most
// one non-revoked token; an expired token must be revoked before the caller
// can register again.
func (s *Service) RegisterToken(input RegisterTokenInput) (IssuedToken, error) {
	caller := domain.NormalizeName(input.Caller)
	if err := domain.ValidateCallerName(caller); err != nil {
		return IssuedToken{}, err
	}
	ttl := s.tokenTTL
	if input.TTLSeconds != 0 {
		if input.TTLSeconds < 0 || input.TTLSeconds > int64(MaxTokenTTL/time.Second) {
			return IssuedToken{}, domain.FieldError(domain.CodeInvalidInput,
				"ttl_seconds", "must be between 1 and 2592000 seconds")
		}
		ttl = time.Duration(input.TTLSeconds) * time.Second
	}
	id, err := generateEntityID("tok")
	if err != nil {
		return IssuedToken{}, domain.NewError(domain.CodeStorage, err.Error())
	}
	secret, err := domain.NewTokenSecret()
	if err != nil {
		return IssuedToken{}, domain.NewError(domain.CodeStorage, err.Error())
	}
	now := s.clock.Now()
	record := domain.AuthToken{
		ID:         id,
		Caller:     caller,
		SecretHash: domain.HashTokenSecret(secret),
		IssuedAt:   now,
		ExpiresAt:  now.Add(ttl),
	}
	err = s.store.Execute(func(snapshot *domain.Snapshot) error {
		key := domain.NameKey(caller)
		if _, exists := snapshot.CallerIndex[key]; exists {
			return domain.NewError(domain.CodeTokenCallerConflict,
				"caller already has an active token; revoke it before registering again")
		}
		snapshot.Tokens[id] = record
		snapshot.CallerIndex[key] = id
		return nil
	})
	if err != nil {
		return IssuedToken{}, err
	}
	return IssuedToken{Record: record.Clone(), Token: id + "." + secret}, nil
}

// RevokeToken marks a token revoked and releases its caller name. Revocation
// is serialized with every other snapshot mutation, so requests
// authenticated before it commits proceed and everything after is rejected
// with token_revoked.
func (s *Service) RevokeToken(id string) (domain.AuthToken, error) {
	var updated domain.AuthToken
	err := s.store.Execute(func(snapshot *domain.Snapshot) error {
		record, ok := snapshot.Tokens[id]
		if !ok {
			return domain.NewError(domain.CodeTokenNotFound, "token was not found")
		}
		if record.RevokedAt != nil {
			return domain.NewError(domain.CodeTokenState, "token is already revoked")
		}
		now := s.clock.Now()
		record.RevokedAt = &now
		snapshot.Tokens[id] = record
		delete(snapshot.CallerIndex, domain.NameKey(record.Caller))
		updated = record.Clone()
		return nil
	})
	if err != nil {
		return domain.AuthToken{}, err
	}
	return updated, nil
}

// Authenticate resolves a presented bearer token to its caller record. The
// whole check reads one consistent snapshot, so it cannot observe a partial
// revocation.
func (s *Service) Authenticate(presented string) (domain.AuthToken, error) {
	tokenID, secret, err := domain.ParsePresentedToken(presented)
	if err != nil {
		return domain.AuthToken{}, err
	}
	now := s.clock.Now()
	var record domain.AuthToken
	err = s.store.View(func(snapshot domain.Snapshot) error {
		stored, ok := snapshot.Tokens[tokenID]
		if !ok || subtle.ConstantTimeCompare(
			[]byte(stored.SecretHash),
			[]byte(domain.HashTokenSecret(secret)),
		) != 1 {
			return domain.NewError(domain.CodeTokenInvalid,
				"the presented token is not recognized")
		}
		if stored.RevokedAt != nil {
			return domain.NewError(domain.CodeTokenRevoked,
				"the presented token has been revoked")
		}
		if !now.Before(stored.ExpiresAt) {
			return domain.NewError(domain.CodeTokenExpired,
				"the presented token has expired")
		}
		record = stored.Clone()
		return nil
	})
	if err != nil {
		return domain.AuthToken{}, err
	}
	return record, nil
}

// ListTokens returns all issued token records, active and retired, sorted by
// caller and issue time. Secret hashes are part of the internal record but
// are never exposed by the HTTP layer.
func (s *Service) ListTokens() ([]domain.AuthToken, error) {
	var tokens []domain.AuthToken
	err := s.store.View(func(snapshot domain.Snapshot) error {
		tokens = make([]domain.AuthToken, 0, len(snapshot.Tokens))
		for _, token := range snapshot.Tokens {
			tokens = append(tokens, token.Clone())
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(tokens, func(i, j int) bool {
		if tokens[i].Caller == tokens[j].Caller {
			return tokens[i].IssuedAt.Before(tokens[j].IssuedAt)
		}
		return tokens[i].Caller < tokens[j].Caller
	})
	return tokens, nil
}

// TokenState reports the current state of a token using the service clock.
func (s *Service) TokenState(record domain.AuthToken) domain.TokenStatus {
	return record.Status(s.clock.Now())
}
