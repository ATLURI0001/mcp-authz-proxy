package gateway

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// ExecutionOutcome categorizes the result of a proxied gateway request.
type ExecutionOutcome string

const (
	OutcomeSuccess       ExecutionOutcome = "SUCCESS"
	OutcomeRateLimited   ExecutionOutcome = "RATE_LIMITED"
	OutcomeLoadShed      ExecutionOutcome = "LOAD_SHED"
	OutcomeCircuitBroken ExecutionOutcome = "CIRCUIT_BROKEN"
	OutcomeTimeout       ExecutionOutcome = "TIMEOUT"
	OutcomeInternalError ExecutionOutcome = "INTERNAL_ERROR"
)

// GatewayTelemetryConfig configures the gateway telemetry profiler.
type GatewayTelemetryConfig struct {
	WindowDuration      time.Duration `json:"window_duration"`
	MaxTrackedRoutes    int           `json:"max_tracked_routes"`
	LatencySLAThreshold time.Duration `json:"latency_sla_threshold"`
	AlertErrorRatePct   float64       `json:"alert_error_rate_pct"`
}

// DefaultGatewayTelemetryConfig provides robust production defaults.
func DefaultGatewayTelemetryConfig() GatewayTelemetryConfig {
	return GatewayTelemetryConfig{
		WindowDuration:      15 * time.Minute,
		MaxTrackedRoutes:    500,
		LatencySLAThreshold: 200 * time.Millisecond,
		AlertErrorRatePct:   5.0, // Alert if > 5% errors
	}
}

type trafficEvent struct {
	timestamp time.Time
	route     string
	duration  time.Duration
	bytesIn   int64
	bytesOut  int64
	outcome   ExecutionOutcome
}

// RouteMetrics summarizes telemetry for an individual route or MCP tool endpoint.
type RouteMetrics struct {
	Route        string           `json:"route"`
	TotalCalls   int64            `json:"total_calls"`
	SuccessCount int64            `json:"success_count"`
	ErrorCount   int64            `json:"error_count"`
	ErrorRatePct float64          `json:"error_rate_pct"`
	BytesIn      int64            `json:"bytes_in"`
	BytesOut     int64            `json:"bytes_out"`
	P50Latency   time.Duration    `json:"p50_latency"`
	P90Latency   time.Duration    `json:"p90_latency"`
	P99Latency   time.Duration    `json:"p99_latency"`
	MeanLatency  time.Duration    `json:"mean_latency"`
	Outcomes     map[string]int64 `json:"outcomes"`
	LastSeen     time.Time        `json:"last_seen"`
}

// GatewayTelemetrySnapshot provides a system-wide telemetry overview.
type GatewayTelemetrySnapshot struct {
	TotalCalls      int64                   `json:"total_calls"`
	SuccessCount    int64                   `json:"success_count"`
	ErrorCount      int64                   `json:"error_count"`
	GlobalErrorRate float64                 `json:"global_error_rate"`
	TotalBytesIn    int64                   `json:"total_bytes_in"`
	TotalBytesOut   int64                   `json:"total_bytes_out"`
	P50Latency      time.Duration           `json:"p50_latency"`
	P90Latency      time.Duration           `json:"p90_latency"`
	P99Latency      time.Duration           `json:"p99_latency"`
	MeanLatency     time.Duration           `json:"mean_latency"`
	Outcomes        map[string]int64        `json:"outcomes"`
	Routes          map[string]RouteMetrics `json:"routes"`
	SLABreached     bool                    `json:"sla_breached"`
	BreachReason    string                  `json:"breach_reason,omitempty"`
	SampleCount     int                     `json:"sample_count"`
}

// GatewayTelemetryEngine tracks low-overhead real-time telemetry across MCP proxy routes.
type GatewayTelemetryEngine struct {
	mu     sync.RWMutex
	config GatewayTelemetryConfig
	events []trafficEvent
}

// NewGatewayTelemetryEngine constructs a new telemetry engine.
func NewGatewayTelemetryEngine(cfg GatewayTelemetryConfig) *GatewayTelemetryEngine {
	if cfg.WindowDuration <= 0 {
		cfg.WindowDuration = 15 * time.Minute
	}
	if cfg.MaxTrackedRoutes <= 0 {
		cfg.MaxTrackedRoutes = 500
	}
	if cfg.LatencySLAThreshold <= 0 {
		cfg.LatencySLAThreshold = 200 * time.Millisecond
	}
	if cfg.AlertErrorRatePct <= 0 {
		cfg.AlertErrorRatePct = 5.0
	}

	return &GatewayTelemetryEngine{
		config: cfg,
		events: make([]trafficEvent, 0, 1024),
	}
}

// RecordCall registers a completed or rejected gateway invocation.
func (e *GatewayTelemetryEngine) RecordCall(
	route string,
	duration time.Duration,
	bytesIn, bytesOut int64,
	outcome ExecutionOutcome,
) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.pruneOldEventsLocked(time.Now())

	e.events = append(e.events, trafficEvent{
		timestamp: time.Now(),
		route:     route,
		duration:  duration,
		bytesIn:   bytesIn,
		bytesOut:  bytesOut,
		outcome:   outcome,
	})
}

// Snapshot aggregates metrics over the configured sliding window.
func (e *GatewayTelemetryEngine) Snapshot() GatewayTelemetrySnapshot {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	e.pruneOldEventsLocked(now)

	n := len(e.events)
	if n == 0 {
		return GatewayTelemetrySnapshot{
			Outcomes: make(map[string]int64),
			Routes:   make(map[string]RouteMetrics),
		}
	}

	var totalIn, totalOut, errCount int64
	var sumDur time.Duration
	allDurations := make([]time.Duration, 0, n)
	globalOutcomes := make(map[string]int64)

	type routeData struct {
		totalCalls int64
		successes  int64
		errors     int64
		bytesIn    int64
		bytesOut   int64
		durations  []time.Duration
		outcomes   map[string]int64
		lastSeen   time.Time
	}
	byRoute := make(map[string]*routeData)

	for _, ev := range e.events {
		allDurations = append(allDurations, ev.duration)
		sumDur += ev.duration
		totalIn += ev.bytesIn
		totalOut += ev.bytesOut

		outcomeStr := string(ev.outcome)
		globalOutcomes[outcomeStr]++

		isError := ev.outcome != OutcomeSuccess
		if isError {
			errCount++
		}

		rd, ok := byRoute[ev.route]
		if !ok {
			rd = &routeData{
				durations: make([]time.Duration, 0, 16),
				outcomes:  make(map[string]int64),
			}
			byRoute[ev.route] = rd
		}

		rd.totalCalls++
		rd.bytesIn += ev.bytesIn
		rd.bytesOut += ev.bytesOut
		rd.durations = append(rd.durations, ev.duration)
		rd.outcomes[outcomeStr]++
		if isError {
			rd.errors++
		} else {
			rd.successes++
		}
		if ev.timestamp.After(rd.lastSeen) {
			rd.lastSeen = ev.timestamp
		}
	}

	sort.Slice(allDurations, func(i, j int) bool {
		return allDurations[i] < allDurations[j]
	})

	p50 := allDurations[n*50/100]
	p90 := allDurations[n*90/100]
	p99 := allDurations[n*99/100]
	mean := sumDur / time.Duration(n)
	errRate := (float64(errCount) / float64(n)) * 100.0

	routeMap := make(map[string]RouteMetrics, len(byRoute))
	for r, rd := range byRoute {
		sort.Slice(rd.durations, func(i, j int) bool {
			return rd.durations[i] < rd.durations[j]
		})
		rdN := len(rd.durations)
		var rMean time.Duration
		var rSum time.Duration
		for _, d := range rd.durations {
			rSum += d
		}
		if rdN > 0 {
			rMean = rSum / time.Duration(rdN)
		}

		routeMap[r] = RouteMetrics{
			Route:        r,
			TotalCalls:   rd.totalCalls,
			SuccessCount: rd.successes,
			ErrorCount:   rd.errors,
			ErrorRatePct: (float64(rd.errors) / float64(rd.totalCalls)) * 100.0,
			BytesIn:      rd.bytesIn,
			BytesOut:     rd.bytesOut,
			P50Latency:   rd.durations[rdN*50/100],
			P90Latency:   rd.durations[rdN*90/100],
			P99Latency:   rd.durations[rdN*99/100],
			MeanLatency:  rMean,
			Outcomes:     rd.outcomes,
			LastSeen:     rd.lastSeen,
		}
	}

	slaBreached := false
	var breachReason string
	if errRate > e.config.AlertErrorRatePct {
		slaBreached = true
		breachReason = fmt.Sprintf("Error rate %.2f%% exceeded SLA threshold %.2f%%", errRate, e.config.AlertErrorRatePct)
	} else if p99 > e.config.LatencySLAThreshold {
		slaBreached = true
		breachReason = fmt.Sprintf("P99 latency %v exceeded SLA threshold %v", p99, e.config.LatencySLAThreshold)
	}

	return GatewayTelemetrySnapshot{
		TotalCalls:      int64(n),
		SuccessCount:    int64(n) - errCount,
		ErrorCount:      errCount,
		GlobalErrorRate: errRate,
		TotalBytesIn:    totalIn,
		TotalBytesOut:   totalOut,
		P50Latency:      p50,
		P90Latency:      p90,
		P99Latency:      p99,
		MeanLatency:     mean,
		Outcomes:        globalOutcomes,
		Routes:          routeMap,
		SLABreached:     slaBreached,
		BreachReason:    breachReason,
		SampleCount:     n,
	}
}

// Reset clears all historical events.
func (e *GatewayTelemetryEngine) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = e.events[:0]
}

func (e *GatewayTelemetryEngine) pruneOldEventsLocked(now time.Time) {
	cutoff := now.Add(-e.config.WindowDuration)
	validIdx := 0
	for validIdx < len(e.events) && e.events[validIdx].timestamp.Before(cutoff) {
		validIdx++
	}
	if validIdx > 0 {
		e.events = append(e.events[:0], e.events[validIdx:]...)
	}
}
