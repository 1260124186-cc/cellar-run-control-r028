package service

import (
	"sort"
	"time"

	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/domain"
)

// RegisterCallerInput carries an enrollment request. TTLSeconds of nil keeps
// the default lifetime; IssuerID of nil marks the one-time bootstrap caller.
type RegisterCallerInput struct {
	Name       string
	TTLSeconds *int64
	IssuerID   *string
}

// Enrollment is returned once: the raw token cannot be recovered afterwards.
type Enrollment struct {
	Caller    domain.Caller
	RawToken  string
	ExpiresAt time.Time
}

// HasCallers reports whether bootstrap enrollment is still open.
func (s *Service) HasCallers() bool {
	return s.store.HasCallers()
}

// Authenticate resolves a raw bearer token to an active caller. The store
// read lock and write serialization make revocation visible consistently to
// concurrent requests: a state cannot authenticate once the revocation write
// has been committed.
func (s *Service) Authenticate(rawToken string) (domain.Caller, error) {
	caller, found := s.store.CallerByTokenHash(domain.HashToken(rawToken))
	if !found {
		return domain.Caller{}, domain.NewError(domain.CodeTokenUnknown,
			"no caller matches the supplied token")
	}
	if caller.RevokedAt != nil {
		return domain.Caller{}, domain.NewError(domain.CodeTokenRevoked,
			"the supplied token has been revoked")
	}
	if !s.clock.Now().Before(caller.ExpiresAt) {
		return domain.Caller{}, domain.NewError(domain.CodeTokenExpired,
			"the supplied token has expired")
	}
	return caller, nil
}

func (s *Service) RegisterCaller(input RegisterCallerInput) (Enrollment, error) {
	name := domain.NormalizeName(input.Name)
	if err := domain.ValidateCallerName(name, "name"); err != nil {
		return Enrollment{}, err
	}

	ttl := domain.DefaultTokenTTL
	if input.TTLSeconds != nil {
		ttl = time.Duration(*input.TTLSeconds) * time.Second
		if err := domain.ValidateTokenTTL(ttl, "ttl_seconds"); err != nil {
			return Enrollment{}, err
		}
	}

	var enrollment Enrollment
	err := s.store.Execute(func(snapshot *domain.Snapshot) error {
		bootstrap := input.IssuerID == nil
		if bootstrap && len(snapshot.Callers) > 0 {
			return domain.NewError(domain.CodeCallersEstablished,
				"the bootstrap caller has already been enrolled")
		}
		if !bootstrap {
			issuer, ok := snapshot.Callers[*input.IssuerID]
			if !ok || issuer.RevokedAt != nil || !s.clock.Now().Before(issuer.ExpiresAt) {
				return domain.NewError(domain.CodeTokenUnknown,
					"the enrolling caller is no longer valid")
			}
		}
		nameKey := domain.NameKey(name)
		if _, exists := snapshot.CallerNameIdx[nameKey]; exists {
			return domain.NewError(domain.CodeCallerNameConflict,
				"a caller with the same normalized name already exists")
		}

		var id, rawToken, tokenHash string
		collided := true
		for attempt := 0; attempt < 3 && collided; attempt++ {
			var err error
			id, err = domain.NewID("cli")
			if err != nil {
				return domain.NewError(domain.CodeStorage, err.Error())
			}
			rawToken, err = domain.NewToken()
			if err != nil {
				return domain.NewError(domain.CodeStorage, err.Error())
			}
			tokenHash = domain.HashToken(rawToken)
			_, idTaken := snapshot.Callers[id]
			_, hashTaken := snapshot.TokenIndex[tokenHash]
			collided = idTaken || hashTaken
		}
		if collided {
			return domain.NewError(domain.CodeStorage,
				"could not allocate a unique caller identifier or token")
		}

		now := s.clock.Now()
		caller := domain.Caller{
			ID:          id,
			Name:        name,
			TokenSHA256: tokenHash,
			IssuedAt:    now,
			ExpiresAt:   now.Add(ttl),
		}
		if !bootstrap {
			caller.IssuedBy = *input.IssuerID
		}
		snapshot.Callers[id] = caller
		snapshot.TokenIndex[tokenHash] = id
		snapshot.CallerNameIdx[nameKey] = id
		enrollment = Enrollment{
			Caller:    caller.Clone(),
			RawToken:  rawToken,
			ExpiresAt: caller.ExpiresAt,
		}
		return nil
	})
	if err != nil {
		return Enrollment{}, err
	}
	return enrollment, nil
}

// RevokeCaller revokes the caller token. Revoking an already revoked caller
// is idempotent and returns the unchanged record.
func (s *Service) RevokeCaller(id string, issuerID string) (domain.Caller, error) {
	var updated domain.Caller
	err := s.store.Execute(func(snapshot *domain.Snapshot) error {
		caller, ok := snapshot.Callers[id]
		if !ok {
			return domain.NewError(domain.CodeCallerNotFound, "caller was not found")
		}
		if issuerID == "" {
			return domain.NewError(domain.CodeAuthMissing, "an authenticated caller is required")
		}
		issuer, ok := snapshot.Callers[issuerID]
		if !ok || issuer.RevokedAt != nil || !s.clock.Now().Before(issuer.ExpiresAt) {
			return domain.NewError(domain.CodeTokenUnknown,
				"the revoking caller is no longer valid")
		}
		if caller.RevokedAt == nil {
			now := s.clock.Now()
			caller.RevokedAt = &now
			caller.RevokedBy = issuerID
			snapshot.Callers[id] = caller
		}
		updated = caller.Clone()
		return nil
	})
	if err != nil {
		return domain.Caller{}, err
	}
	return updated, nil
}

func (s *Service) GetCaller(id string) (domain.Caller, error) {
	var found domain.Caller
	err := s.store.View(func(snapshot domain.Snapshot) error {
		caller, ok := snapshot.Callers[id]
		if !ok {
			return domain.NewError(domain.CodeCallerNotFound, "caller was not found")
		}
		found = caller.Clone()
		return nil
	})
	if err != nil {
		return domain.Caller{}, err
	}
	return found, nil
}

func (s *Service) ListCallers() ([]domain.Caller, error) {
	var callers []domain.Caller
	err := s.store.View(func(snapshot domain.Snapshot) error {
		callers = make([]domain.Caller, 0, len(snapshot.Callers))
		for _, caller := range snapshot.Callers {
			callers = append(callers, caller.Clone())
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(callers, func(i, j int) bool {
		if callers[i].Name == callers[j].Name {
			return callers[i].ID < callers[j].ID
		}
		return callers[i].Name < callers[j].Name
	})
	return callers, nil
}
