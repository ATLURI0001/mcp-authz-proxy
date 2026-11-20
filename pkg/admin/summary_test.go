package admin

import (
	"testing"
	"time"
)

func TestServiceSummary(t *testing.T) {
	start := time.Now().Add(-2 * time.Second)
	summary := ServiceSummary{
		ServiceName: "mcp-authz-proxy",
		Version:     "1.4.0",
		StartTime:   start,
		UpstreamOK:  true,
	}

	if !summary.IsHealthy() {
		t.Fatal("expected summary with upstream OK and service name to be healthy")
	}

	if summary.UptimeDuration() < 1*time.Second {
		t.Fatalf("expected uptime >= 1s, got %v", summary.UptimeDuration())
	}

	// Unhealthy cases
	unhealthy1 := ServiceSummary{
		ServiceName: "mcp-authz-proxy",
		UpstreamOK:  false,
	}
	if unhealthy1.IsHealthy() {
		t.Fatal("expected summary with UpstreamOK=false to be unhealthy")
	}

	unhealthy2 := ServiceSummary{
		ServiceName: "",
		UpstreamOK:  true,
	}
	if unhealthy2.IsHealthy() {
		t.Fatal("expected summary with empty ServiceName to be unhealthy")
	}

	// Zero start time
	zeroSummary := ServiceSummary{}
	if zeroSummary.UptimeDuration() != 0 {
		t.Fatalf("expected zero duration for zero start time, got %v", zeroSummary.UptimeDuration())
	}
}
