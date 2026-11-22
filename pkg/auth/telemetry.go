package auth

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// DenialReason categorizes the root cause of an authorization rejection.
type DenialReason string

const (
	DenialExpiredToken      DenialReason = "EXPIRED_TOKEN"
	DenialInsufficientScope DenialReason = "INSUFFICIENT_SCOPE"
	DenialRevokedToken      DenialReason = "REVOKED_TOKEN"
	DenialInvalidSignature  DenialReason = "INVALID_SIGNATURE"
	DenialMalformedHeader   DenialReason = "MALFORMED_HEADER"
	DenialRateLimited       DenialReason = "RATE_LIMITED"
)

// AuthTelemetryConfig configures the audit telemetry collector.
type AuthTelemetryConfig struct {
	WindowDuration      time.Duration `json:"window_duration"`
	MaxTrackedClients   int           `json:"max_tracked_clients"`
	AlertFailureRatePct float64       `json:"alert_failure_rate_pct"`
}

// DefaultAuthTelemetryConfig provides production default configurations.
func DefaultAuthTelemetryConfig() AuthTelemetryConfig {
	return AuthTelemetryConfig{
		WindowDuration:      10 * time.Minute,
		MaxTrackedClients:   1000,
		AlertFailureRatePct: 15.0, // Alert if > 15% rejections
	}
}

// ClientAuthMetrics tracks per-client authentication activity.
type ClientAuthMetrics struct {
	ClientID        string    `json:"client_id"`
	TotalRequests   int64     `json:"total_requests"`
	AuthorizedCount int64     `json:"authorized_count"`
	DeniedCount     int64     `json:"denied_count"`
	LastSeen        time.Time `json:"last_seen"`
}

type auditEvent struct {
	timestamp time.Time
	success   bool
}

// AuthAuditTelemetry tracks real-time authentication and denial statistics.
type AuthAuditTelemetry struct {
	mu             sync.RWMutex
	config         AuthTelemetryConfig
	totalRequests  int64
	authorized     int64
	denied         int64
	denialReasons  map[DenialReason]int64
	clientMetrics  map[string]*ClientAuthMetrics
	eventsWindow   []auditEvent
}

// NewAuthAuditTelemetry creates an initialized telemetry collector.
func NewAuthAuditTelemetry(cfg AuthTelemetryConfig) *AuthAuditTelemetry {
	if cfg.WindowDuration <= 0 {
		cfg.WindowDuration = 10 * time.Minute
	}
	if cfg.MaxTrackedClients <= 0 {
		cfg.MaxTrackedClients = 1000
	}
	if cfg.AlertFailureRatePct <= 0 {
		cfg.AlertFailureRatePct = 15.0
	}
	return &AuthAuditTelemetry{
		config:        cfg,
		denialReasons: make(map[DenialReason]int64),
		clientMetrics: make(map[string]*ClientAuthMetrics),
		eventsWindow:  make([]auditEvent, 0),
	}
}

// RecordAuthorized records a successfully verified and authorized request.
func (t *AuthAuditTelemetry) RecordAuthorized(clientID string, now ...time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()

	ts := time.Now()
	if len(now) > 0 {
		ts = now[0]
	}

	t.totalRequests++
	t.authorized++
	t.eventsWindow = append(t.eventsWindow, auditEvent{timestamp: ts, success: true})
	t.pruneWindow(ts)

	cid := strings.TrimSpace(clientID)
	if cid != "" {
		m, exists := t.clientMetrics[cid]
		if !exists {
			if len(t.clientMetrics) < t.config.MaxTrackedClients {
				m = &ClientAuthMetrics{ClientID: cid}
				t.clientMetrics[cid] = m
			}
		}
		if m != nil {
			m.TotalRequests++
			m.AuthorizedCount++
			m.LastSeen = ts
		}
	}
}

// RecordDenied records an authorization denial with specific categorized reason.
func (t *AuthAuditTelemetry) RecordDenied(clientID string, reason DenialReason, now ...time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()

	ts := time.Now()
	if len(now) > 0 {
		ts = now[0]
	}

	t.totalRequests++
	t.denied++
	t.denialReasons[reason]++
	t.eventsWindow = append(t.eventsWindow, auditEvent{timestamp: ts, success: false})
	t.pruneWindow(ts)

	cid := strings.TrimSpace(clientID)
	if cid != "" {
		m, exists := t.clientMetrics[cid]
		if !exists {
			if len(t.clientMetrics) < t.config.MaxTrackedClients {
				m = &ClientAuthMetrics{ClientID: cid}
				t.clientMetrics[cid] = m
			}
		}
		if m != nil {
			m.TotalRequests++
			m.DeniedCount++
			m.LastSeen = ts
		}
	}
}

func (t *AuthAuditTelemetry) pruneWindow(now time.Time) {
	cutoff := now.Add(-t.config.WindowDuration)
	idx := 0
	for idx < len(t.eventsWindow) && t.eventsWindow[idx].timestamp.Before(cutoff) {
		idx++
	}
	if idx > 0 {
		t.eventsWindow = t.eventsWindow[idx:]
	}
}

// GetSummary returns consolidated telemetry and sliding window failure rates.
func (t *AuthAuditTelemetry) GetSummary() map[string]any {
	t.mu.RLock()
	defer t.mu.RUnlock()

	total := t.totalRequests
	denied := t.denied
	lifetimeFailureRate := 0.0
	if total > 0 {
		lifetimeFailureRate = round2((float64(denied) / float64(total)) * 100.0)
	}

	// Rolling window failure rate
	windowTotal := len(t.eventsWindow)
	windowDenied := 0
	for _, ev := range t.eventsWindow {
		if !ev.success {
			windowDenied++
		}
	}
	windowFailureRate := 0.0
	if windowTotal > 0 {
		windowFailureRate = round2((float64(windowDenied) / float64(windowTotal)) * 100.0)
	}

	isAlerting := windowFailureRate >= t.config.AlertFailureRatePct && windowTotal >= 10

	reasons := make(map[string]int64)
	for k, v := range t.denialReasons {
		reasons[string(k)] = v
	}

	return map[string]any{
		"total_requests":         total,
		"authorized_count":       t.authorized,
		"denied_count":           denied,
		"lifetime_failure_rate":  lifetimeFailureRate,
		"window_total_requests":  windowTotal,
		"window_failure_rate":    windowFailureRate,
		"is_security_alert":      isAlerting,
		"denial_reasons":         reasons,
		"tracked_client_count":   len(t.clientMetrics),
	}
}

// GenerateDiagnosticMarkdown renders a formatted Markdown diagnostic table.
func (t *AuthAuditTelemetry) GenerateDiagnosticMarkdown() string {
	s := t.GetSummary()

	var sb strings.Builder
	sb.WriteString("# MCP AuthZ Proxy - Authentication Telemetry Diagnostic\n\n")
	sb.WriteString(fmt.Sprintf("- **Total Ingress Requests**: %d\n", s["total_requests"].(int64)))
	sb.WriteString(fmt.Sprintf("- **Authorized Requests**: %d\n", s["authorized_count"].(int64)))
	sb.WriteString(fmt.Sprintf("- **Denied Requests**: %d\n", s["denied_count"].(int64)))
	sb.WriteString(fmt.Sprintf("- **Rolling Window Failure Rate**: %.2f%%\n", s["window_failure_rate"].(float64)))

	if s["is_security_alert"].(bool) {
		sb.WriteString("\n> [!WARNING] High Authorization Failure Rate Alert Active! Rolling failure rate exceeds threshold.\n")
	}

	sb.WriteString("\n## Denial Reasons Breakdown\n")
	sb.WriteString("| Denial Reason | Occurrence Count |\n| :--- | :--- |\n")

	reasons := s["denial_reasons"].(map[string]int64)
	keys := make([]string, 0, len(reasons))
	for k := range reasons {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		sb.WriteString(fmt.Sprintf("| `%s` | %d |\n", k, reasons[k]))
	}

	return sb.String()
}

// ExportPrometheusMetrics outputs Prometheus gauges and counters.
func (t *AuthAuditTelemetry) ExportPrometheusMetrics() string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var sb strings.Builder
	sb.WriteString("# HELP mcp_authz_requests_total Total authorization requests processed\n")
	sb.WriteString("# TYPE mcp_authz_requests_total counter\n")
	sb.WriteString(fmt.Sprintf("mcp_authz_requests_total{status=\"authorized\"} %d\n", t.authorized))
	sb.WriteString(fmt.Sprintf("mcp_authz_requests_total{status=\"denied\"} %d\n", t.denied))

	sb.WriteString("# HELP mcp_authz_denials_by_reason_total Total authorization rejections by reason\n")
	sb.WriteString("# TYPE mcp_authz_denials_by_reason_total counter\n")
	for reason, count := range t.denialReasons {
		sb.WriteString(fmt.Sprintf("mcp_authz_denials_by_reason_total{reason=\"%s\"} %d\n", reason, count))
	}

	return sb.String()
}

func round2(val float64) float64 {
	return float64(int(val*100+0.5)) / 100
}
