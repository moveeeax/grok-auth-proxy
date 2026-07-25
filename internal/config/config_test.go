package config

import (
	"os"
	"testing"
	"time"
)

func TestValidateRequiresAdminKey(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Addr: ":8080"},
		Auth: AuthConfig{
			File:         "./auth.json",
			UpstreamBase: "https://api.x.ai/v1",
			RefreshSkew:  5 * time.Minute,
		},
		DB:        DBConfig{Driver: "sqlite", DSN: "./data.db"},
		RateLimit: RateLimitConfig{RPS: 10, Burst: 20},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing admin key")
	}
	cfg.Server.AdminKey = "secret"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateTrimsUpstreamBase(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{AdminKey: "k", Addr: ":8080"},
		Auth: AuthConfig{
			File:         "./auth.json",
			UpstreamBase: "https://api.x.ai/v1/",
			RefreshSkew:  time.Minute,
		},
		DB:        DBConfig{Driver: "sqlite", DSN: "x"},
		RateLimit: RateLimitConfig{RPS: 1, Burst: 1},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Auth.UpstreamBase != "https://api.x.ai/v1" {
		t.Fatalf("got %q", cfg.Auth.UpstreamBase)
	}
}

func baseConfig() *Config {
	return &Config{
		Server: ServerConfig{AdminKey: "k", Addr: ":8080"},
		Auth: AuthConfig{
			File:         "./auth.json",
			UpstreamBase: "https://api.x.ai/v1",
			RefreshSkew:  time.Minute,
		},
		DB:        DBConfig{Driver: "sqlite", DSN: "x"},
		RateLimit: RateLimitConfig{RPS: 1, Burst: 1},
	}
}

// The upstream call carries the Grok access token, and the issuer call carries
// the refresh token. Neither may go out over plaintext HTTP to a remote host.
func TestValidateRejectsCleartextCredentialEndpoints(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"https upstream", func(c *Config) { c.Auth.UpstreamBase = "https://api.x.ai/v1" }, false},
		{"http upstream remote", func(c *Config) { c.Auth.UpstreamBase = "http://api.x.ai/v1" }, true},
		{"http upstream localhost", func(c *Config) { c.Auth.UpstreamBase = "http://localhost:9999/v1" }, false},
		{"http upstream 127.0.0.1", func(c *Config) { c.Auth.UpstreamBase = "http://127.0.0.1:9999/v1" }, false},
		{"http upstream ::1", func(c *Config) { c.Auth.UpstreamBase = "http://[::1]:9999/v1" }, false},
		{"bad scheme", func(c *Config) { c.Auth.UpstreamBase = "ftp://api.x.ai/v1" }, true},
		{"relative", func(c *Config) { c.Auth.UpstreamBase = "api.x.ai/v1" }, true},
		{"https issuer", func(c *Config) { c.Auth.Issuer = "https://auth.x.ai" }, false},
		{"http issuer remote", func(c *Config) { c.Auth.Issuer = "http://auth.x.ai" }, true},
		{"empty issuer defaults later", func(c *Config) { c.Auth.Issuer = "" }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseConfig()
			tc.mutate(cfg)
			err := cfg.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected a validation error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateFillsServerHardeningDefaults(t *testing.T) {
	cfg := baseConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Server.ReadTimeout <= 0 {
		t.Fatal("read_timeout must default to a non-zero value (slowloris guard)")
	}
	if cfg.Server.IdleTimeout <= 0 {
		t.Fatal("idle_timeout must default to a non-zero value")
	}
	if cfg.Server.MaxRequestBytes <= 0 {
		t.Fatal("max_request_bytes must default to a non-zero value")
	}

	// Explicit values are preserved.
	cfg = baseConfig()
	cfg.Server.ReadTimeout = 5 * time.Second
	cfg.Server.IdleTimeout = 7 * time.Second
	cfg.Server.MaxRequestBytes = 123
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Server.ReadTimeout != 5*time.Second || cfg.Server.IdleTimeout != 7*time.Second || cfg.Server.MaxRequestBytes != 123 {
		t.Fatalf("explicit server settings were overwritten: %+v", cfg.Server)
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("GAP_SERVER_ADMIN_KEY", "env-admin")
	t.Setenv("GAP_AUTH_FILE", "/tmp/auth.json")
	t.Setenv("GAP_DB_DSN", "/tmp/test.db")
	t.Setenv("GAP_LOG_LEVEL", "debug")

	// Clear argv noise for pflag
	oldArgs := os.Args
	os.Args = []string{"test"}
	defer func() { os.Args = oldArgs }()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.AdminKey != "env-admin" {
		t.Fatalf("admin key = %q", cfg.Server.AdminKey)
	}
	if cfg.Auth.File != "/tmp/auth.json" {
		t.Fatalf("auth file = %q", cfg.Auth.File)
	}
	if cfg.DB.DSN != "/tmp/test.db" {
		t.Fatalf("dsn = %q", cfg.DB.DSN)
	}
}
