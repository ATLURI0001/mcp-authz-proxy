package auth

import "testing"

func TestAssertSafeAuthzPath(t *testing.T) {
	if err := AssertSafeAuthzPath("/v1/tools/call"); err != nil {
		t.Fatalf("expected valid path, got %v", err)
	}
	if err := AssertSafeAuthzPath("/v1/../admin"); err == nil {
		t.Fatal("expected traversal sentinel violation")
	}
}
