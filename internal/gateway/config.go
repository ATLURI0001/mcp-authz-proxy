package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

type Rule struct {
	Scope    string `json:"scope"`
	Approval bool   `json:"approval"`
}
type Config struct {
	Resource    string            `json:"resource"`
	Issuer      string            `json:"issuer"`
	JWKSURL     string            `json:"jwks_url"`
	Upstream    string            `json:"upstream"`
	Origins     []string          `json:"origins"`
	Tools       map[string]Rule   `json:"tools"`
	Credentials map[string]string `json:"credentials"`
	Rate        int               `json:"requests_per_minute"`
	AllowHTTP   bool              `json:"allow_http"`
}

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	if c.Rate < 1 || c.Rate > 100000 || len(c.Tools) == 0 {
		return c, errors.New("invalid rate or no tools")
	}
	for _, raw := range []string{c.Resource, c.Issuer, c.JWKSURL, c.Upstream} {
		u, e := url.Parse(raw)
		if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return c, errors.New("invalid configured URL")
		}
		if u.Scheme != "https" && !(c.AllowHTTP && u.Scheme == "http") {
			return c, errors.New("HTTPS required; allow_http is local demo only")
		}
	}
	for i, raw := range c.Origins {
		u, e := url.Parse(raw)
		if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return c, fmt.Errorf("invalid configured origin %q", raw)
		}
		scheme := strings.ToLower(u.Scheme)
		if scheme != "https" && !(c.AllowHTTP && scheme == "http") {
			return c, fmt.Errorf("HTTPS required for origin %q; allow_http is local demo only", raw)
		}
		// Canonicalize origin to lowercase scheme + host without trailing slash so exact Origin header matches succeed.
		c.Origins[i] = scheme + "://" + strings.ToLower(u.Host)
	}
	for name, rule := range c.Tools {
		if name == "" || rule.Scope == "" || strings.ContainsAny(rule.Scope, " \"\r\n") {
			return c, fmt.Errorf("invalid tool rule %q", name)
		}
	}
	for sub, env := range c.Credentials {
		value := os.Getenv(env)
		if strings.TrimSpace(sub) == "" || len(value) < 16 || strings.ContainsAny(value, "\r\n") {
			return c, fmt.Errorf("missing or invalid credential environment variable %s", env)
		}
		c.Credentials[sub] = value
	}
	return c, nil
}
