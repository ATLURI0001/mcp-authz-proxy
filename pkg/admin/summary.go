package admin

import "time"

// ServiceSummary provides runtime diagnostic metrics for health endpoints.
type ServiceSummary struct {
	ServiceName string    `json:"service_name"`
	Version     string    `json:"version"`
	StartTime   time.Time `json:"start_time"`
	UpstreamOK  bool      `json:"upstream_ok"`
}

// UptimeDuration calculates running duration since StartTime.
func (s ServiceSummary) UptimeDuration() time.Duration {
	if s.StartTime.IsZero() {
		return 0
	}
	return time.Since(s.StartTime)
}

// IsHealthy returns true if essential downstream dependencies are reachable.
func (s ServiceSummary) IsHealthy() bool {
	return s.UpstreamOK && s.ServiceName != ""
}
