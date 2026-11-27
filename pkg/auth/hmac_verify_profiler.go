package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"time"
)

// BenchmarkHmacVerify measures HMAC-SHA256 verification throughput.
func BenchmarkHmacVerify(key, msg []byte, iterations int) time.Duration {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	sig := mac.Sum(nil)
	start := time.Now()
	for i := 0; i < iterations; i++ {
		m := hmac.New(sha256.New, key)
		m.Write(msg)
		_ = hmac.Equal(m.Sum(nil), sig)
	}
	return time.Since(start)
}
