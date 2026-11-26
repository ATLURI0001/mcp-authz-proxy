package auth

import (
	"sort"
	"sync"
	"time"
)

// PolicyEvalRecord captures an authorization policy decision and latency.
type PolicyEvalRecord struct {
	PolicyID  string
	Allowed   bool
	LatencyUs int64
	Timestamp time.Time
}

// PolicyTelemetrySummary aggregates authorization evaluation stats.
type PolicyTelemetrySummary struct {
	SampleCount   int
	AllowCount    int
	DenyCount     int
	DenyRatePct   float64
	P50LatencyUs  int64
	P90LatencyUs  int64
	P99LatencyUs  int64
}

// PolicyTelemetryRotary is a thread-safe ring buffer for authz policy decisions.
type PolicyTelemetryRotary struct {
	mu       sync.RWMutex
	capacity int
	buffer   []PolicyEvalRecord
	head     int
	count    int
}

// NewPolicyTelemetryRotary creates a new bounded telemetry rotary.
func NewPolicyTelemetryRotary(capacity int) *PolicyTelemetryRotary {
	if capacity <= 0 {
		capacity = 500
	}
	return &PolicyTelemetryRotary{
		capacity: capacity,
		buffer:   make([]PolicyEvalRecord, capacity),
	}
}

// Record stores an authorization evaluation outcome.
func (r *PolicyTelemetryRotary) Record(policyID string, allowed bool, latencyUs int64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.buffer[r.head] = PolicyEvalRecord{
		PolicyID:  policyID,
		Allowed:   allowed,
		LatencyUs: latencyUs,
		Timestamp: time.Now(),
	}
	r.head = (r.head + 1) % r.capacity
	if r.count < r.capacity {
		r.count++
	}
}

// GetSummary computes allow/deny ratios and latency quantiles.
func (r *PolicyTelemetryRotary) GetSummary() PolicyTelemetrySummary {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.count == 0 {
		return PolicyTelemetrySummary{}
	}

	latencies := make([]int64, r.count)
	allows := 0
	denies := 0

	for i := 0; i < r.count; i++ {
		rec := r.buffer[i]
		if rec.Allowed {
			allows++
		} else {
			denies++
		}
		latencies[i] = rec.LatencyUs
	}

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	denyRate := float64(denies) / float64(r.count) * 100.0

	return PolicyTelemetrySummary{
		SampleCount:  r.count,
		AllowCount:   allows,
		DenyCount:    denies,
		DenyRatePct:  denyRate,
		P50LatencyUs: latencies[int(float64(r.count)*0.5)],
		P90LatencyUs: latencies[int(float64(r.count)*0.9)],
		P99LatencyUs: latencies[int(float64(r.count)*0.99)],
	}
}
