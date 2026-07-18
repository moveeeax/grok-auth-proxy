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
