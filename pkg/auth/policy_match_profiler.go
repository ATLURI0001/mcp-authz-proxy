package auth

import (
	"strings"
	"time"
)

// BenchmarkPolicyMatch measures wildcard tool policy matching throughput.
func BenchmarkPolicyMatch(patterns []string, tool string, iterations int) (matched bool, elapsed time.Duration) {
	start := time.Now()
	for i := 0; i < iterations; i++ {
		matched = false
		for _, p := range patterns {
			if p == tool || (strings.HasSuffix(p, "*") && strings.HasPrefix(tool, strings.TrimSuffix(p, "*"))) {
				matched = true
				break
			}
		}
	}
	return matched, time.Since(start)
}
