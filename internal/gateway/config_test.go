package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigValidation(t *testing.T) {
	t.Setenv("TEST_DOWNSTREAM_TOKEN", "a-valid-long-test-secret")
	good := Config{Resource: "https://gateway.example/mcp", Issuer: "https://id.example", JWKSURL: "https://id.example/certs", Upstream: "https://upstream.example/mcp", Rate: 60, Tools: map[string]Rule{"echo": {Scope: "tools:read"}}, Credentials: map[string]string{"alice": "TEST_DOWNSTREAM_TOKEN"}}
	for _, tt := range []struct {
		name   string
		change func(*Config)
		ok     bool
	}{
		{"valid", func(*Config) {}, true},
		{"cleartext", func(c *Config) { c.Upstream = "http://upstream.example/mcp" }, false},
		{"userinfo", func(c *Config) { c.Upstream = "https://user:password@upstream.example/mcp" }, false},
		{"query", func(c *Config) { c.Upstream = "https://upstream.example/mcp?token=secret" }, false},
		{"invalid rate", func(c *Config) { c.Rate = 0 }, false},
		{"missing credential", func(c *Config) { c.Credentials = map[string]string{"alice": "ABSENT_TOKEN"} }, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := good
			tt.change(&c)
			b, _ := json.Marshal(c)
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if (err == nil) != tt.ok {
				t.Fatal(err)
			}
		})
	}
}
