package auth

import (
	"errors"
	"testing"
	"time"
)

func TestJwksCircuitBreaker_CachedFallbackAndRecovery(t *testing.T) {
	cb := NewJwksCircuitBreaker(2, 2, 50*time.Millisecond)
	okFetcher := func() (map[string]string, error) {
		return map[string]string{"kid-1": "pub-key-1"}, nil
	}
	failFetcher := func() (map[string]string, error) {
		return nil, errors.New("idp 503")
	}

	// Prime cache
	keys, fb, err := cb.FetchKeys(okFetcher)
	if err != nil || fb || keys["kid-1"] != "pub-key-1" {
		t.Fatalf("expected clean initial fetch, got %v, %v, %v", keys, fb, err)
	}

	// 2 failures -> trip OPEN
	cb.FetchKeys(failFetcher)
	cb.FetchKeys(failFetcher)

	// Short circuit with cached fallback
	keys, fb, err = cb.FetchKeys(okFetcher)
	if !fb || !errors.Is(err, ErrJwksCircuitOpen) || keys["kid-1"] != "pub-key-1" {
		t.Fatalf("expected cached fallback on open circuit, got %v, %v, %v", keys, fb, err)
	}

	// Wait cooldown -> HALF_OPEN -> CLOSED
	time.Sleep(60 * time.Millisecond)
	cb.FetchKeys(okFetcher)
	keys, fb, err = cb.FetchKeys(okFetcher)
	if err != nil || fb {
		t.Fatalf("expected full recovery, got %v, %v", fb, err)
	}
}
