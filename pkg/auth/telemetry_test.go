package auth

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAuthAuditTelemetry_BasicRecordingAndSummary(t *testing.T) {
	cfg := DefaultAuthTelemetryConfig()
	telemetry := NewAuthAuditTelemetry(cfg)

	// Record 8 authorizations
	for i := 0; i < 8; i++ {
		telemetry.RecordAuthorized("client-alice")
	}

	// Record 2 denials
	telemetry.RecordDenied("client-bob", DenialExpiredToken)
	telemetry.RecordDenied("client-mallory", DenialInvalidSignature)

	summary := telemetry.GetSummary()
	if summary["total_requests"].(int64) != 10 {
		t.Errorf("expected 10 total requests, got %d", summary["total_requests"].(int64))
	}
	if summary["authorized_count"].(int64) != 8 {
		t.Errorf("expected 8 authorized, got %d", summary["authorized_count"].(int64))
	}
	if summary["denied_count"].(int64) != 2 {
		t.Errorf("expected 2 denied, got %d", summary["denied_count"].(int64))
	}

	rate := summary["lifetime_failure_rate"].(float64)
	if rate != 20.0 {
		t.Errorf("expected 20.0%% lifetime failure rate, got %.2f", rate)
	}

	reasons := summary["denial_reasons"].(map[string]int64)
	if reasons[string(DenialExpiredToken)] != 1 {
		t.Errorf("expected 1 expired token denial, got %d", reasons[string(DenialExpiredToken)])
	}
	if reasons[string(DenialInvalidSignature)] != 1 {
		t.Errorf("expected 1 invalid signature denial, got %d", reasons[string(DenialInvalidSignature)])
	}
}

func TestAuthAuditTelemetry_RollingWindowAndAlert(t *testing.T) {
	cfg := AuthTelemetryConfig{
		WindowDuration:      1 * time.Minute,
		AlertFailureRatePct: 25.0, // Alert on >= 25% failures
	}
	telemetry := NewAuthAuditTelemetry(cfg)

	now := time.Now()

	// 10 events: 7 success, 3 denied = 30% failure rate (> 25% alert threshold)
	for i := 0; i < 7; i++ {
		telemetry.RecordAuthorized("agent-1", now)
	}
	for i := 0; i < 3; i++ {
		telemetry.RecordDenied("agent-1", DenialInsufficientScope, now)
	}

	summary := telemetry.GetSummary()
	if summary["window_total_requests"].(int) != 10 {
		t.Errorf("expected 10 window requests, got %d", summary["window_total_requests"].(int))
	}
	if !summary["is_security_alert"].(bool) {
		t.Errorf("expected is_security_alert=true at 30%% failures, got false")
	}

	// Fast forward 2 minutes -> old events pruned from rolling window
	future := now.Add(2 * time.Minute)
	telemetry.RecordAuthorized("agent-1", future)

	futureSummary := telemetry.GetSummary()
	// Previous 10 events should have expired
	if futureSummary["window_total_requests"].(int) != 1 {
		t.Errorf("expected 1 window request after expiry, got %d", futureSummary["window_total_requests"].(int))
	}
	if futureSummary["is_security_alert"].(bool) {
		t.Errorf("expected alert to clear after window expiry")
	}
}

func TestAuthAuditTelemetry_Exporters(t *testing.T) {
	telemetry := NewAuthAuditTelemetry(DefaultAuthTelemetryConfig())
	telemetry.RecordAuthorized("client-app")
	telemetry.RecordDenied("client-app", DenialRateLimited)

	md := telemetry.GenerateDiagnosticMarkdown()
	if !strings.Contains(md, "# MCP AuthZ Proxy - Authentication Telemetry Diagnostic") {
		t.Errorf("markdown report missing header")
	}
	if !strings.Contains(md, "RATE_LIMITED") {
		t.Errorf("markdown report missing denial reason")
	}

	prom := telemetry.ExportPrometheusMetrics()
	if !strings.Contains(prom, "mcp_authz_requests_total{status=\"authorized\"} 1") {
		t.Errorf("prom metrics missing authorized count")
	}
	if !strings.Contains(prom, "mcp_authz_denials_by_reason_total{reason=\"RATE_LIMITED\"} 1") {
		t.Errorf("prom metrics missing rate_limited denial")
	}
}

func TestAuthAuditTelemetry_Concurrency(t *testing.T) {
	telemetry := NewAuthAuditTelemetry(DefaultAuthTelemetryConfig())
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				if j%5 == 0 {
					telemetry.RecordDenied("concurrent-client", DenialExpiredToken)
				} else {
					telemetry.RecordAuthorized("concurrent-client")
				}
			}
		}(i)
	}

	wg.Wait()

	summary := telemetry.GetSummary()
	if summary["total_requests"].(int64) != 500 {
		t.Errorf("expected 500 total requests, got %d", summary["total_requests"].(int64))
	}
}
