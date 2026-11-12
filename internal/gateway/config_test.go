package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigValidation(t *testing.T) {
	t.Setenv("TEST_DOWNSTREAM_TOKEN", "a-valid-long-test-secret")
	good := Config{
		Resource:    "https://gateway.example/mcp",
		Issuer:      "https://id.example",
		JWKSURL:     "https://id.example/certs",
		Upstream:    "https://upstream.example/mcp",
		Origins:     []string{"https://app.example.com", "https://client.example.com:8443"},
		Rate:        60,
		Tools:       map[string]Rule{"echo": {Scope: "tools:read"}},
		Credentials: map[string]string{"alice": "TEST_DOWNSTREAM_TOKEN"},
	}
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
		{"origin with path", func(c *Config) { c.Origins = []string{"https://app.example.com/invalid/path"} }, false},
		{"cleartext origin", func(c *Config) { c.Origins = []string{"http://insecure.example.com"} }, false},
		{"cleartext origin allowed when allow_http is true", func(c *Config) {
			c.AllowHTTP = true
			c.Origins = []string{"http://localhost:3000"}
			c.Resource = "http://gateway.example/mcp"
			c.Issuer = "http://id.example"
			c.JWKSURL = "http://id.example/certs"
			c.Upstream = "http://upstream.example/mcp"
		}, true},
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
				t.Fatalf("Load(path) error = %v, expected ok = %v", err, tt.ok)
			}
		})
	}
}

func TestConfigNormalizesOriginsAndRejectsBlankSubject(t *testing.T) {
	t.Setenv("TEST_DOWNSTREAM_TOKEN", "a-valid-long-test-secret")
	c := Config{
		Resource:    "https://gateway.example/mcp",
		Issuer:      "https://id.example",
		JWKSURL:     "https://id.example/certs",
		Upstream:    "https://upstream.example/mcp",
		Origins:     []string{"HTTPS://APP.Example.COM/"},
		Rate:        60,
		Tools:       map[string]Rule{"echo": {Scope: "tools:read"}},
		Credentials: map[string]string{"alice": "TEST_DOWNSTREAM_TOKEN"},
	}
	b, _ := json.Marshal(c)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load(path) unexpected error = %v", err)
	}
	if loaded.Origins[0] != "https://app.example.com" {
		t.Fatalf("expected canonical origin https://app.example.com, got %q", loaded.Origins[0])
	}

	c.Credentials = map[string]string{"   ": "TEST_DOWNSTREAM_TOKEN"}
	b, _ = json.Marshal(c)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected Load(path) to reject whitespace-only credential subject")
	}
}
