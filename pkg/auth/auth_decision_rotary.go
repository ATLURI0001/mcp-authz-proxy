package auth

// AuthDecisionRotary is a bounded ring buffer for recent authz decisions.
type AuthDecisionRotary struct {
	buf  []bool
	size int
	head int
	cnt  int
}

func NewAuthDecisionRotary(size int) *AuthDecisionRotary {
	return &AuthDecisionRotary{buf: make([]bool, size), size: size}
}

func (r *AuthDecisionRotary) Push(allowed bool) {
	r.buf[r.head%r.size] = allowed
	r.head++
	if r.cnt < r.size {
		r.cnt++
	}
}

func (r *AuthDecisionRotary) Count() int {
	return r.cnt
}
