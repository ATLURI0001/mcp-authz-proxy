package auth

// AuthzLatencyRotary tracks bounded authorization decision latencies in ms.
type AuthzLatencyRotary struct {
	samples []float64
	cap     int
}

func NewAuthzLatencyRotary(capacity int) *AuthzLatencyRotary {
	return &AuthzLatencyRotary{cap: capacity}
}

func (r *AuthzLatencyRotary) Record(ms float64) {
	if len(r.samples) >= r.cap {
		r.samples = r.samples[1:]
	}
	r.samples = append(r.samples, ms)
}

func (r *AuthzLatencyRotary) Avg() float64 {
	if len(r.samples) == 0 {
		return 0
	}
	var sum float64
	for _, s := range r.samples {
		sum += s
	}
	return sum / float64(len(r.samples))
}
