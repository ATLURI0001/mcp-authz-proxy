package auth

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	// ErrPrivilegeEscalation is returned when a child token requests scopes not held by the parent.
	ErrPrivilegeEscalation = errors.New("delegation error: requested scopes exceed parent token scope set")

	// ErrTTLBoundsExceeded is returned when delegated token expiration exceeds parent expiration.
	ErrTTLBoundsExceeded = errors.New("delegation error: child expiration exceeds parent expiration")

	// ErrDelegationDepthExceeded is returned when the delegation chain depth breaches configured limits.
	ErrDelegationDepthExceeded = errors.New("delegation error: maximum delegation depth exceeded")

	// ErrInvalidDelegationSubject is returned when parent or child identity is missing or invalid.
	ErrInvalidDelegationSubject = errors.New("delegation error: invalid delegator or delegatee subject")

	// ErrEmptyAllowedTools is returned when no tool bindings are specified for a delegated grant.
	ErrEmptyAllowedTools = errors.New("delegation error: delegated grant must restrict to at least one tool name")
)

// DelegationGrant encapsulates a subordinate token downscoping request.
type DelegationGrant struct {
	ParentTokenID    string
	ParentSubject    string
	ChildSubject     string
	ParentScopes     []string
	DelegatedScopes  []string
	ParentExpiresAt  time.Time
	ChildExpiresAt   time.Time
	CurrentDepth     int
	MaxAllowedDepth  int
	AllowedToolNames []string
}

// DelegationContractValidator enforces strict privilege attenuation and lifetime boundaries.
type DelegationContractValidator struct {
	DefaultMaxDepth int
}

// NewDelegationContractValidator initializes a validator with standard defaults.
func NewDelegationContractValidator(defaultMaxDepth int) *DelegationContractValidator {
	if defaultMaxDepth <= 0 {
		defaultMaxDepth = 3
	}
	return &DelegationContractValidator{
		DefaultMaxDepth: defaultMaxDepth,
	}
}

// ValidateDelegation enforces all invariants on a delegation grant proposal.
func (v *DelegationContractValidator) ValidateDelegation(grant DelegationGrant, now time.Time) error {
	// 1. Subject validation
	if strings.TrimSpace(grant.ParentTokenID) == "" || strings.TrimSpace(grant.ParentSubject) == "" {
		return fmt.Errorf("%w: missing parent token or delegator subject", ErrInvalidDelegationSubject)
	}
	if strings.TrimSpace(grant.ChildSubject) == "" {
		return fmt.Errorf("%w: missing child delegatee subject", ErrInvalidDelegationSubject)
	}
	if strings.EqualFold(grant.ParentSubject, grant.ChildSubject) {
		return fmt.Errorf("%w: self-delegation is forbidden", ErrInvalidDelegationSubject)
	}

	// 2. Delegation Depth Bound
	maxDepth := grant.MaxAllowedDepth
	if maxDepth <= 0 {
		maxDepth = v.DefaultMaxDepth
	}
	if grant.CurrentDepth+1 > maxDepth {
		return fmt.Errorf("%w: depth %d exceeds ceiling %d", ErrDelegationDepthExceeded, grant.CurrentDepth+1, maxDepth)
	}

	// 3. TTL & Expiration Boundary
	if grant.ChildExpiresAt.Before(now) || grant.ChildExpiresAt.Equal(now) {
		return fmt.Errorf("%w: child token already expired at %v", ErrTTLBoundsExceeded, grant.ChildExpiresAt)
	}
	if grant.ChildExpiresAt.After(grant.ParentExpiresAt) {
		return fmt.Errorf("%w: child expiration (%v) exceeds parent expiration (%v)", ErrTTLBoundsExceeded, grant.ChildExpiresAt, grant.ParentExpiresAt)
	}

	// 4. Scope Attenuation (Non-Escalation Invariant)
	parentScopeSet := make(map[string]struct{}, len(grant.ParentScopes))
	for _, s := range grant.ParentScopes {
		sClean := strings.TrimSpace(s)
		if sClean != "" {
			parentScopeSet[sClean] = struct{}{}
		}
	}

	if len(grant.DelegatedScopes) == 0 {
		return fmt.Errorf("%w: delegated scopes cannot be empty", ErrPrivilegeEscalation)
	}

	for _, childScope := range grant.DelegatedScopes {
		cClean := strings.TrimSpace(childScope)
		if cClean == "" {
			continue
		}
		if _, exists := parentScopeSet[cClean]; !exists {
			return fmt.Errorf("%w: scope '%s' not present in delegator scope set", ErrPrivilegeEscalation, cClean)
		}
	}

	// 5. Allowed Tool Binding Boundary
	if len(grant.AllowedToolNames) == 0 {
		return ErrEmptyAllowedTools
	}
	for _, tool := range grant.AllowedToolNames {
		if strings.TrimSpace(tool) == "" {
			return fmt.Errorf("%w: empty tool name detected in grant", ErrEmptyAllowedTools)
		}
	}

	return nil
}
