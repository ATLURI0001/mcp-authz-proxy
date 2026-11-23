package gateway

import (
	"errors"
	"sync"
	"time"
)

// Priority represents the classification tier of an incoming MCP gateway request.
type Priority int

const (
	PriorityLow Priority = iota
	PriorityStandard
	PriorityCritical
)

func (p Priority) String() string {
	switch p {
	case PriorityLow:
		return "LOW"
	case PriorityStandard:
		return "STANDARD"
	case PriorityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// HealthStatus represents the load state of the gateway queue.
type HealthStatus string

const (
	StatusOptimal   HealthStatus = "OPTIMAL"
	StatusThrottled HealthStatus = "THROTTLED"
	StatusShedding  HealthStatus = "SHEDDING"
)

var (
	ErrLoadShedLowPriority = errors.New("load shed: dropping low-priority request under queue pressure")
	ErrLoadShedStandard    = errors.New("load shed: dropping standard-priority request under severe queue pressure")
	ErrCapacityExhausted   = errors.New("load shed: queue capacity fully exhausted, dropping critical request")
)

// LoadShedderConfig configures thresholds for the adaptive load shedder.
type LoadShedderConfig struct {
	MaxCapacity          int
	LowPriorityLimit     int
	StandardPriorityLimit int
	LatencyThreshold     time.Duration
}

// DefaultLoadShedderConfig provides production-tuned baseline parameters.
func DefaultLoadShedderConfig() LoadShedderConfig {
	return LoadShedderConfig{
		MaxCapacity:           1000,
		LowPriorityLimit:      750,  // 75% capacity
		StandardPriorityLimit: 950,  // 95% capacity
		LatencyThreshold:      200 * time.Millisecond,
	}
}

// LoadShedderStats holds atomic telemetry snapshots.
type LoadShedderStats struct {
	ActiveInFlight   int
	TotalAdmitted    uint64
	TotalShedLow     uint64
	TotalShedStd     uint64
	TotalShedCrit    uint64
	CurrentStatus    HealthStatus
	RecentAvgLatency time.Duration
}

// AdaptiveLoadShedder dynamically sheds traffic based on queue saturation and target latency.
type AdaptiveLoadShedder struct {
	mu            sync.RWMutex
	cfg           LoadShedderConfig
	inFlight      int
	totalAdmitted uint64
	totalShedLow  uint64
	totalShedStd  uint64
	totalShedCrit uint64

	// Sliding window latency samples
	latencySamples []time.Duration
	sampleIdx      int
}

// NewAdaptiveLoadShedder constructs a new shedder instance.
func NewAdaptiveLoadShedder(cfg LoadShedderConfig) *AdaptiveLoadShedder {
	if cfg.MaxCapacity <= 0 {
		cfg = DefaultLoadShedderConfig()
	}
	if cfg.LowPriorityLimit <= 0 || cfg.LowPriorityLimit >= cfg.MaxCapacity {
		cfg.LowPriorityLimit = int(float64(cfg.MaxCapacity) * 0.75)
	}
	if cfg.StandardPriorityLimit <= cfg.LowPriorityLimit || cfg.StandardPriorityLimit > cfg.MaxCapacity {
		cfg.StandardPriorityLimit = int(float64(cfg.MaxCapacity) * 0.95)
	}
	if cfg.LatencyThreshold <= 0 {
		cfg.LatencyThreshold = 200 * time.Millisecond
	}

	return &AdaptiveLoadShedder{
		cfg:            cfg,
		latencySamples: make([]time.Duration, 32),
	}
}

// Acquire attempts to admit an incoming request given its priority tier.
// Returns a release function if admitted, or an error if shed.
func (s *AdaptiveLoadShedder) Acquire(priority Priority) (func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	avgLatency := s.calculateAvgLatencyLocked()

	// Check if queue latency exceeds threshold or capacity limits
	isLatencyElevated := avgLatency > s.cfg.LatencyThreshold

	switch priority {
	case PriorityLow:
		if s.inFlight >= s.cfg.LowPriorityLimit || isLatencyElevated {
			s.totalShedLow++
			return nil, ErrLoadShedLowPriority
		}
	case PriorityStandard:
		if s.inFlight >= s.cfg.StandardPriorityLimit || (isLatencyElevated && s.inFlight >= s.cfg.LowPriorityLimit) {
			s.totalShedStd++
			return nil, ErrLoadShedStandard
		}
	case PriorityCritical:
		if s.inFlight >= s.cfg.MaxCapacity {
			s.totalShedCrit++
			return nil, ErrCapacityExhausted
		}
	}

	s.inFlight++
	s.totalAdmitted++

	start := time.Now()
	var once sync.Once
	release := func() {
		once.Do(func() {
			duration := time.Since(start)
			s.recordCompletion(duration)
		})
	}

	return release, nil
}

func (s *AdaptiveLoadShedder) recordCompletion(dur time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.inFlight > 0 {
		s.inFlight--
	}

	s.latencySamples[s.sampleIdx] = dur
	s.sampleIdx = (s.sampleIdx + 1) % len(s.latencySamples)
}

func (s *AdaptiveLoadShedder) calculateAvgLatencyLocked() time.Duration {
	var total time.Duration
	var count int
	for _, sample := range s.latencySamples {
		if sample > 0 {
			total += sample
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return total / time.Duration(count)
}

// Stats returns current diagnostic statistics.
func (s *AdaptiveLoadShedder) Stats() LoadShedderStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	avgLatency := s.calculateAvgLatencyLocked()
	status := StatusOptimal
	if s.inFlight >= s.cfg.StandardPriorityLimit || avgLatency > s.cfg.LatencyThreshold {
		status = StatusShedding
	} else if s.inFlight >= s.cfg.LowPriorityLimit || avgLatency > (s.cfg.LatencyThreshold/2) {
		status = StatusThrottled
	}

	return LoadShedderStats{
		ActiveInFlight:   s.inFlight,
		TotalAdmitted:    s.totalAdmitted,
		TotalShedLow:     s.totalShedLow,
		TotalShedStd:     s.totalShedStd,
		TotalShedCrit:    s.totalShedCrit,
		CurrentStatus:    status,
		RecentAvgLatency: avgLatency,
	}
}
