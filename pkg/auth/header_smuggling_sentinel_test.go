package auth

import (
	"net/http"
	"testing"
)

func TestHeaderSmugglingSentinel(t *testing.T) {
	s := &HeaderSmugglingSentinel{}

	clean := http.Header{}
	clean.Add("Authorization", "Bearer tok1")
	if ok, code := s.InspectHeaders(clean); !ok || code != "OK" {
		t.Fatalf("expected clean headers to pass, got %v, %s", ok, code)
	}

	dup := http.Header{}
	dup.Add("Authorization", "Bearer tok1")
	dup.Add("Authorization", "Bearer tok2")
	if ok, code := s.InspectHeaders(dup); ok || code != "ERR_DUPLICATE_AUTHORIZATION_HEADER" {
		t.Fatalf("expected duplicate auth rejection, got %v, %s", ok, code)
	}
}
