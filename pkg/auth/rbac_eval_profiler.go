package auth

import "time"

// RbacEvalProfiler tracks RBAC policy evaluation durations.
type RbacEvalProfiler struct {
	samples []time.Duration
}

func NewRbacEvalProfiler() *RbacEvalProfiler {
	return &RbacEvalProfiler{}
}

func (p *RbacEvalProfiler) Record(d time.Duration) {
	p.samples = append(p.samples, d)
}

func (p *RbacEvalProfiler) Count() int {
	return len(p.samples)
}
