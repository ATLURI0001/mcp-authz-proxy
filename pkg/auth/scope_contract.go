package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var (
	ErrInvalidScopeFormat   = errors.New("scope does not conform to 'mcp:<server>:<tool>:<action>' or wildcard format")
	ErrScopeLengthExceeded  = errors.New("scope string exceeds maximum length limit of 128 characters")
	ErrInvalidSubject       = errors.New("subject must be a valid non-empty identifier")
	ErrEmptyScopeList       = errors.New("allowed scopes list cannot be empty")
	ErrDuplicateScope       = errors.New("duplicate scope detected in specification")
	ErrScopeCapacityExceed  = errors.New("allowed scopes count exceeds maximum ceiling of 100")
	ErrScopeExplicitlyDenied = errors.New("tool invocation scope is explicitly denied by RBAC policy")
	ErrScopeNotGranted      = errors.New("tool invocation scope is not authorized by subject policy")
)

var (
	scopePattern    = regexp.MustCompile(`^mcp:(?:\*|[a-z0-9_-]+:(?:\*|[a-z0-9_-]+:(?:\*|[a-z0-9_-]+)))$`)
	subjectPattern  = regexp.MustCompile(`^[a-zA-Z0-9_\-\.@]{3,64}$`)
	roleNamePattern = regexp.MustCompile(`^[a-z0-9_\-]{2,32}$`)
)

// ValidatedScope represents a canonical, validated authorization scope.
type ValidatedScope struct {
	Raw    string
	Server string
	Tool   string
	Action string
}

// ScopeContractPolicy defines formal ingress constraints for RBAC tool authorization.
type ScopeContractPolicy struct {
	Subject       string   `json:"subject"`
	Roles         []string `json:"roles"`
	AllowedScopes []string `json:"allowed_scopes"`
	DeniedScopes  []string `json:"denied_scopes,omitempty"`
}

// ValidatedPolicyManifest contains validated RBAC policy specifications and cryptographic digest.
type ValidatedPolicyManifest struct {
	Subject          string
	Roles            []string
	AllowedScopes    []ValidatedScope
	DeniedScopes     []ValidatedScope
	CanonicalDigest  string
}

// ValidateAndParseScope parses and validates a scope string against formal ingress invariants.
func ValidateAndParseScope(raw string) (ValidatedScope, error) {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) == 0 {
		return ValidatedScope{}, ErrInvalidScopeFormat
	}
	if len(trimmed) > 128 {
		return ValidatedScope{}, ErrScopeLengthExceeded
	}

	lower := strings.ToLower(trimmed)
	if !scopePattern.MatchString(lower) {
		return ValidatedScope{}, fmt.Errorf("%w: '%s'", ErrInvalidScopeFormat, trimmed)
	}

	parts := strings.Split(lower, ":")
	vs := ValidatedScope{Raw: lower}

	if len(parts) >= 2 {
		vs.Server = parts[1]
	}
	if len(parts) >= 3 {
		vs.Tool = parts[2]
	}
	if len(parts) >= 4 {
		vs.Action = parts[3]
	}

	return vs, nil
}

// Matches checks if a granted scope covers a requested target scope (supporting wildcards).
func (vs ValidatedScope) Matches(target ValidatedScope) bool {
	if vs.Raw == "mcp:*" {
		return true
	}
	if vs.Server != "*" && vs.Server != target.Server {
		return false
	}
	if vs.Tool == "*" {
		return true
	}
	if vs.Tool != target.Tool {
		return false
	}
	if vs.Action == "*" {
		return true
	}
	return vs.Action == target.Action
}

// ValidateScopeContractPolicy validates an entire RBAC policy manifest.
func ValidateScopeContractPolicy(p ScopeContractPolicy) (*ValidatedPolicyManifest, error) {
	trimmedSubject := strings.TrimSpace(p.Subject)
	if !subjectPattern.MatchString(trimmedSubject) {
		return nil, fmt.Errorf("%w: '%s'", ErrInvalidSubject, trimmedSubject)
	}

	if len(p.Roles) == 0 {
		return nil, errors.New("roles list must contain at least one valid role")
	}
	validatedRoles := make([]string, 0, len(p.Roles))
	for _, r := range p.Roles {
		tr := strings.ToLower(strings.TrimSpace(r))
		if !roleNamePattern.MatchString(tr) {
			return nil, fmt.Errorf("role '%s' does not match pattern '^[a-z0-9_\\-]{2,32}$'", r)
		}
		validatedRoles = append(validatedRoles, tr)
	}

	if len(p.AllowedScopes) == 0 {
		return nil, ErrEmptyScopeList
	}
	if len(p.AllowedScopes) > 100 {
		return nil, ErrScopeCapacityExceed
	}

	seenAllowed := make(map[string]struct{})
	allowed := make([]ValidatedScope, 0, len(p.AllowedScopes))
	for _, rawScope := range p.AllowedScopes {
		vs, err := ValidateAndParseScope(rawScope)
		if err != nil {
			return nil, err
		}
		if _, exists := seenAllowed[vs.Raw]; exists {
			return nil, fmt.Errorf("%w: '%s'", ErrDuplicateScope, vs.Raw)
		}
		seenAllowed[vs.Raw] = struct{}{}
		allowed = append(allowed, vs)
	}

	seenDenied := make(map[string]struct{})
	denied := make([]ValidatedScope, 0, len(p.DeniedScopes))
	for _, rawScope := range p.DeniedScopes {
		vs, err := ValidateAndParseScope(rawScope)
		if err != nil {
			return nil, err
		}
		if _, exists := seenDenied[vs.Raw]; exists {
			return nil, fmt.Errorf("%w in denied_scopes: '%s'", ErrDuplicateScope, vs.Raw)
		}
		seenDenied[vs.Raw] = struct{}{}
		denied = append(denied, vs)
	}

	// Canonical digest computation
	sort.Strings(validatedRoles)
	rawAllowed := make([]string, len(allowed))
	for i, a := range allowed {
		rawAllowed[i] = a.Raw
	}
	sort.Strings(rawAllowed)

	rawDenied := make([]string, len(denied))
	for i, d := range denied {
		rawDenied[i] = d.Raw
	}
	sort.Strings(rawDenied)

	canonicalMap := map[string]interface{}{
		"sub":     trimmedSubject,
		"roles":   validatedRoles,
		"allowed": rawAllowed,
		"denied":  rawDenied,
	}
	b, _ := json.Marshal(canonicalMap)
	hash := sha256.Sum256(b)
	digest := hex.EncodeToString(hash[:])

	return &ValidatedPolicyManifest{
		Subject:         trimmedSubject,
		Roles:           validatedRoles,
		AllowedScopes:   allowed,
		DeniedScopes:    denied,
		CanonicalDigest: digest,
	}, nil
}

// AuthorizeToolInvocation verifies whether a validated policy authorizes a requested tool scope.
func (vpm *ValidatedPolicyManifest) AuthorizeToolInvocation(requestedScope string) error {
	target, err := ValidateAndParseScope(requestedScope)
	if err != nil {
		return err
	}

	// 1. Check explicit denial (denial overrides grants)
	for _, denied := range vpm.DeniedScopes {
		if denied.Matches(target) {
			return fmt.Errorf("%w: scope '%s' matches explicit denial '%s'", ErrScopeExplicitlyDenied, target.Raw, denied.Raw)
		}
	}

	// 2. Check allowed scopes
	for _, allowed := range vpm.AllowedScopes {
		if allowed.Matches(target) {
			return nil
		}
	}

	return fmt.Errorf("%w: subject '%s' lacks grant for '%s'", ErrScopeNotGranted, vpm.Subject, target.Raw)
}
