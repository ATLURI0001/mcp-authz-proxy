package auth

import "fmt"

// JwtClaimContract enforces required claims on JWT payloads.
type JwtClaimContract struct {
	Required []string
}

func NewJwtClaimContract(required []string) *JwtClaimContract {
	return &JwtClaimContract{Required: required}
}

func (c *JwtClaimContract) Validate(claims map[string]string) error {
	for _, r := range c.Required {
		if claims[r] == "" {
			return fmt.Errorf("missing claim: %s", r)
		}
	}
	return nil
}
