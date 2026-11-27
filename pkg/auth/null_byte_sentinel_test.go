package auth

import "testing"

func TestAssertNoNullByte(t *testing.T) {
	if err := AssertNoNullByte("tool:read"); err != nil {
		t.Fatalf("expected clean input, got %v", err)
	}
	if err := AssertNoNullByte("tool\x00admin"); err == nil {
		t.Fatal("expected null byte sentinel violation")
	}
}
