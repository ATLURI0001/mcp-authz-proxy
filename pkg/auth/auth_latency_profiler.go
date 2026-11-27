package auth

import "time"

// AuthLatencyProfiler records auth operation durations.
type AuthLatencyProfiler struct {
	samples []time.Duration
}

func NewAuthLatencyProfiler() *AuthLatencyProfiler {
	return &AuthLatencyProfiler{}
}

func (p *AuthLatencyProfiler) Record(d time.Duration) {
	p.samples = append(p.samples, d)
}

func (p *AuthLatencyProfiler) Avg() time.Duration {
	if len(p.samples) == 0 {
		return 0
	}
	var total time.Duration
	for _, s := range p.samples {
		total += s
	}
	return total / time.Duration(len(p.samples))
}
