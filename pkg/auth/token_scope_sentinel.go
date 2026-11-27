package auth

import "sync"

// TokenScopeSentinel tracks unauthorized scope access attempts.
type TokenScopeSentinel struct {
	mu         sync.Mutex
	violations []string
}

func NewTokenScopeSentinel() *TokenScopeSentinel {
	return &TokenScopeSentinel{}
}

func (s *TokenScopeSentinel) Check(allowed []string, requested string) bool {
	for _, a := range allowed {
		if a == requested {
			return true
		}
	}
	s.mu.Lock()
	s.violations = append(s.violations, requested)
	s.mu.Unlock()
	return false
}

func (s *TokenScopeSentinel) Violations() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.violations)
}
