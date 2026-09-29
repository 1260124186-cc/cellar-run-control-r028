package storage

import "github.com/1260124186-cc/solo-0016-cellar-run-control/internal/domain"

// HasCallers reports whether at least one caller is enrolled. It is used to
// gate the one-time unauthenticated bootstrap enrollment.
func (s *Store) HasCallers() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.snapshot.Callers) > 0
}

// CallerByTokenHash resolves a caller record through the token hash index.
// The returned caller is a value copy; its pointer fields are not shared.
func (s *Store) CallerByTokenHash(tokenHash string) (domain.Caller, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.snapshot.TokenIndex[tokenHash]
	if !ok {
		return domain.Caller{}, false
	}
	caller, ok := s.snapshot.Callers[id]
	if !ok {
		return domain.Caller{}, false
	}
	return caller.Clone(), true
}
