package auth

import (
	"errors"
	"testing"
	"time"
)

func TestDelegationContractValidator_Nominal(t *testing.T) {
	v := NewDelegationContractValidator(3)
	now := time.Now()

	grant := DelegationGrant{
		ParentTokenID:    "tok-parent-123",
		ParentSubject:    "agent-coordinator",
		ChildSubject:     "agent-worker-1",
		ParentScopes:     []string{"tools:read", "tools:execute", "prompts:read"},
		DelegatedScopes:  []string{"tools:read", "tools:execute"},
		ParentExpiresAt:  now.Add(1 * time.Hour),
		ChildExpiresAt:   now.Add(15 * time.Minute),
		CurrentDepth:     0,
		MaxAllowedDepth:  3,
		AllowedToolNames: []string{"search_web", "read_file"},
	}

	if err := v.ValidateDelegation(grant, now); err != nil {
		t.Fatalf("expected nominal grant to succeed, got: %v", err)
	}
}

func TestDelegationContractValidator_PrivilegeEscalation(t *testing.T) {
	v := NewDelegationContractValidator(3)
	now := time.Now()

	grant := DelegationGrant{
		ParentTokenID:    "tok-parent-123",
		ParentSubject:    "agent-coordinator",
		ChildSubject:     "agent-worker-1",
		ParentScopes:     []string{"tools:read"},
		DelegatedScopes:  []string{"tools:read", "admin:write"}, // Escalation!
		ParentExpiresAt:  now.Add(1 * time.Hour),
		ChildExpiresAt:   now.Add(15 * time.Minute),
		CurrentDepth:     0,
		MaxAllowedDepth:  3,
		AllowedToolNames: []string{"search_web"},
	}

	err := v.ValidateDelegation(grant, now)
	if err == nil {
		t.Fatal("expected privilege escalation error, got nil")
	}
	if !errors.Is(err, ErrPrivilegeEscalation) {
		t.Fatalf("expected ErrPrivilegeEscalation, got %v", err)
	}
}

func TestDelegationContractValidator_TTLBoundsExceeded(t *testing.T) {
	v := NewDelegationContractValidator(3)
	now := time.Now()

	grant := DelegationGrant{
		ParentTokenID:    "tok-parent-123",
		ParentSubject:    "agent-coordinator",
		ChildSubject:     "agent-worker-1",
		ParentScopes:     []string{"tools:read"},
		DelegatedScopes:  []string{"tools:read"},
		ParentExpiresAt:  now.Add(30 * time.Minute),
		ChildExpiresAt:   now.Add(2 * time.Hour), // Exceeds parent!
		CurrentDepth:     0,
		MaxAllowedDepth:  3,
		AllowedToolNames: []string{"search_web"},
	}

	err := v.ValidateDelegation(grant, now)
	if err == nil {
		t.Fatal("expected TTL error, got nil")
	}
	if !errors.Is(err, ErrTTLBoundsExceeded) {
		t.Fatalf("expected ErrTTLBoundsExceeded, got %v", err)
	}
}

func TestDelegationContractValidator_DepthLimit(t *testing.T) {
	v := NewDelegationContractValidator(2)
	now := time.Now()

	grant := DelegationGrant{
		ParentTokenID:    "tok-parent-123",
		ParentSubject:    "agent-worker-2",
		ChildSubject:     "agent-subworker-3",
		ParentScopes:     []string{"tools:read"},
		DelegatedScopes:  []string{"tools:read"},
		ParentExpiresAt:  now.Add(1 * time.Hour),
		ChildExpiresAt:   now.Add(10 * time.Minute),
		CurrentDepth:     2, // Exceeds max depth of 2
		MaxAllowedDepth:  2,
		AllowedToolNames: []string{"search_web"},
	}

	err := v.ValidateDelegation(grant, now)
	if err == nil {
		t.Fatal("expected depth error, got nil")
	}
	if !errors.Is(err, ErrDelegationDepthExceeded) {
		t.Fatalf("expected ErrDelegationDepthExceeded, got %v", err)
	}
}

func TestDelegationContractValidator_ToolRestrictionMissing(t *testing.T) {
	v := NewDelegationContractValidator(3)
	now := time.Now()

	grant := DelegationGrant{
		ParentTokenID:    "tok-parent-123",
		ParentSubject:    "agent-coordinator",
		ChildSubject:     "agent-worker-1",
		ParentScopes:     []string{"tools:read"},
		DelegatedScopes:  []string{"tools:read"},
		ParentExpiresAt:  now.Add(1 * time.Hour),
		ChildExpiresAt:   now.Add(15 * time.Minute),
		CurrentDepth:     0,
		MaxAllowedDepth:  3,
		AllowedToolNames: []string{}, // Missing tool restriction!
	}

	err := v.ValidateDelegation(grant, now)
	if err == nil {
		t.Fatal("expected empty tool error, got nil")
	}
	if !errors.Is(err, ErrEmptyAllowedTools) {
		t.Fatalf("expected ErrEmptyAllowedTools, got %v", err)
	}
}
