package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateAndParseScope_Valid(t *testing.T) {
	tests := []struct {
		raw    string
		server string
		tool   string
		action string
	}{
		{"mcp:*", "*", "", ""},
		{"mcp:filesystem:*", "filesystem", "*", ""},
		{"mcp:filesystem:read_file:*", "filesystem", "read_file", "*"},
		{"mcp:filesystem:read_file:execute", "filesystem", "read_file", "execute"},
		{"MCP:GITHUB:CREATE_ISSUE:WRITE", "github", "create_issue", "write"},
	}

	for _, tt := range tests {
		vs, err := ValidateAndParseScope(tt.raw)
		if err != nil {
			t.Fatalf("unexpected error parsing '%s': %v", tt.raw, err)
		}
		if vs.Server != tt.server {
			t.Errorf("for '%s', expected server '%s', got '%s'", tt.raw, tt.server, vs.Server)
		}
	}
}

func TestValidateAndParseScope_Invalid(t *testing.T) {
	invalids := []string{
		"",
		"   ",
		"http:filesystem:read",
		"mcp",
		"mcp:",
		"mcp:filesystem:read_file:execute:extra_segment",
		"mcp:file..system:read:execute",
		strings.Repeat("a", 130),
	}

	for _, inv := range invalids {
		_, err := ValidateAndParseScope(inv)
		if err == nil {
			t.Errorf("expected error for invalid scope '%s', got nil", inv)
		}
	}
}

func TestScopeMatching_Wildcards(t *testing.T) {
	starScope, _ := ValidateAndParseScope("mcp:*")
	serverScope, _ := ValidateAndParseScope("mcp:filesystem:*")
	toolScope, _ := ValidateAndParseScope("mcp:filesystem:read_file:*")
	exactScope, _ := ValidateAndParseScope("mcp:filesystem:read_file:execute")

	otherServerTarget, _ := ValidateAndParseScope("mcp:database:query:execute")
	exactTarget, _ := ValidateAndParseScope("mcp:filesystem:read_file:execute")

	// mcp:* matches everything
	if !starScope.Matches(otherServerTarget) || !starScope.Matches(exactTarget) {
		t.Errorf("mcp:* should match any target scope")
	}

	// mcp:filesystem:* matches filesystem, not database
	if !serverScope.Matches(exactTarget) {
		t.Errorf("mcp:filesystem:* should match filesystem target")
	}
	if serverScope.Matches(otherServerTarget) {
		t.Errorf("mcp:filesystem:* should not match database target")
	}

	// mcp:filesystem:read_file:* matches exactTarget
	if !toolScope.Matches(exactTarget) {
		t.Errorf("mcp:filesystem:read_file:* should match exact target")
	}

	// exactScope matches exactTarget
	if !exactScope.Matches(exactTarget) {
		t.Errorf("exact scope should match identical target")
	}
}

func TestValidateScopeContractPolicy_Success(t *testing.T) {
	policy := ScopeContractPolicy{
		Subject: "agent-planner@mcp.cluster.local",
		Roles:   []string{"operator", "auditor"},
		AllowedScopes: []string{
			"mcp:filesystem:*",
			"mcp:github:read_issue:read",
		},
		DeniedScopes: []string{
			"mcp:filesystem:delete_file:*",
		},
	}

	manifest, err := ValidateScopeContractPolicy(policy)
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	if manifest.Subject != "agent-planner@mcp.cluster.local" {
		t.Errorf("expected subject 'agent-planner@mcp.cluster.local', got '%s'", manifest.Subject)
	}
	if len(manifest.CanonicalDigest) != 64 {
		t.Errorf("expected 64-char sha256 hex digest, got '%s'", manifest.CanonicalDigest)
	}

	// Test Authorization
	// 1. Allowed tool invocation
	err = manifest.AuthorizeToolInvocation("mcp:filesystem:read_file:execute")
	if err != nil {
		t.Errorf("expected authorization to succeed, got %v", err)
	}

	// 2. Denied tool invocation (even though covered by mcp:filesystem:*)
	err = manifest.AuthorizeToolInvocation("mcp:filesystem:delete_file:execute")
	if !errors.Is(err, ErrScopeExplicitlyDenied) {
		t.Errorf("expected ErrScopeExplicitlyDenied, got %v", err)
	}

	// 3. Not granted
	err = manifest.AuthorizeToolInvocation("mcp:database:drop_table:execute")
	if !errors.Is(err, ErrScopeNotGranted) {
		t.Errorf("expected ErrScopeNotGranted, got %v", err)
	}
}

func TestValidateScopeContractPolicy_DuplicatesAndBounds(t *testing.T) {
	// Duplicate allowed scope
	pDup := ScopeContractPolicy{
		Subject:       "agent-1",
		Roles:         []string{"reader"},
		AllowedScopes: []string{"mcp:fs:read:execute", "mcp:fs:read:execute"},
	}
	_, err := ValidateScopeContractPolicy(pDup)
	if !errors.Is(err, ErrDuplicateScope) {
		t.Errorf("expected ErrDuplicateScope, got %v", err)
	}

	// Empty roles
	pNoRoles := ScopeContractPolicy{
		Subject:       "agent-1",
		Roles:         []string{},
		AllowedScopes: []string{"mcp:fs:read:execute"},
	}
	_, err = ValidateScopeContractPolicy(pNoRoles)
	if err == nil {
		t.Errorf("expected error on empty roles, got nil")
	}

	// Empty allowed scopes
	pEmptyScopes := ScopeContractPolicy{
		Subject:       "agent-1",
		Roles:         []string{"reader"},
		AllowedScopes: []string{},
	}
	_, err = ValidateScopeContractPolicy(pEmptyScopes)
	if !errors.Is(err, ErrEmptyScopeList) {
		t.Errorf("expected ErrEmptyScopeList, got %v", err)
	}
}
