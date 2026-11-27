package auth

// TokenRejectRotary tracks bounded rejected token counts.
type TokenRejectRotary struct {
	samples []int
	cap     int
}

func NewTokenRejectRotary(capacity int) *TokenRejectRotary {
	return &TokenRejectRotary{cap: capacity}
}

func (r *TokenRejectRotary) Record(count int) {
	if len(r.samples) >= r.cap {
		r.samples = r.samples[1:]
	}
	r.samples = append(r.samples, count)
}

func (r *TokenRejectRotary) Avg() float64 {
	if len(r.samples) == 0 {
		return 0
	}
	sum := 0
	for _, s := range r.samples {
		sum += s
	}
	return float64(sum) / float64(len(r.samples))
}
