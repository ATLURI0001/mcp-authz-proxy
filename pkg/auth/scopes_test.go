package auth

import "testing"

func TestScopeSet(t *testing.T) {
	scopes := ParseScopes("read:tools  write:prompts   admin:all")

	if !scopes.Has("read:tools") {
		t.Fatal("expected read:tools to be present")
	}
	if !scopes.Has("write:prompts") {
		t.Fatal("expected write:prompts to be present")
	}
	if !scopes.Has("admin:all") {
		t.Fatal("expected admin:all to be present")
	}
	if scopes.Has("unknown:scope") {
		t.Fatal("did not expect unknown:scope to be present")
	}

	if !scopes.HasAll("read:tools", "admin:all") {
		t.Fatal("expected HasAll to return true for subset")
	}
	if scopes.HasAll("read:tools", "missing:scope") {
		t.Fatal("expected HasAll to return false when missing scope")
	}

	// Empty string
	empty := ParseScopes("   ")
	if len(empty) != 0 {
		t.Fatalf("expected 0 scopes from whitespace string, got %d", len(empty))
	}
}
