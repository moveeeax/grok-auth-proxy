package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	defaultReadTimeout = 60 * time.Second
	defaultIdleTimeout = 120 * time.Second
	// 10 MiB is well above any OpenAI-compatible chat payload while still
	// bounding how much memory one client request can pin.
	defaultMaxRequestBytes = 10 << 20
)

// Config holds all application settings.
type Config struct {
	Server    ServerConfig    `mapstructure:"server"`
	Auth      AuthConfig      `mapstructure:"auth"`
	DB        DBConfig        `mapstructure:"db"`
	RateLimit RateLimitConfig `mapstructure:"rate_limit"`
	CORS      CORSConfig      `mapstructure:"cors"`
	Log       LogConfig       `mapstructure:"log"`
	Metrics   MetricsConfig   `mapstructure:"metrics"`
	Audit     AuditConfig     `mapstructure:"audit"`
}

// AuditConfig controls request/response audit logging to the database.
type AuditConfig struct {
	Enabled      bool `mapstructure:"enabled"`
	MaxBodyBytes int  `mapstructure:"max_body_bytes"`
}

type ServerConfig struct {
	Addr            string        `mapstructure:"addr"`
	AdminKey        string        `mapstructure:"admin_key"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
	// ReadTimeout bounds how long a client may take to send headers plus body.
	// Without it a single idle socket can pin a connection forever (slowloris).
	ReadTimeout time.Duration `mapstructure:"read_timeout"`
	// IdleTimeout bounds how long an idle keep-alive connection is kept open.
	IdleTimeout time.Duration `mapstructure:"idle_timeout"`
	// MaxRequestBytes caps the proxied client request body. Requests above it
	// are rejected with 413 rather than silently truncated.
	MaxRequestBytes int `mapstructure:"max_request_bytes"`
}

type AuthConfig struct {
	File         string        `mapstructure:"file"`
	UpstreamBase string        `mapstructure:"upstream_base"`
	RefreshSkew  time.Duration `mapstructure:"refresh_skew"`
	Issuer       string        `mapstructure:"issuer"`
	ClientID     string        `mapstructure:"client_id"`
	Account      string        `mapstructure:"account"`
}

type DBConfig struct {
	Driver string `mapstructure:"driver"`
	DSN    string `mapstructure:"dsn"`
}

type RateLimitConfig struct {
	RPS   float64 `mapstructure:"rps"`
	Burst int     `mapstructure:"burst"`
}

type CORSConfig struct {
	AllowedOrigins []string `mapstructure:"allowed_origins"`
}

type LogConfig struct {
	Level  string `mapstructure:"level"`
	Redact bool   `mapstructure:"redact"`
}

type MetricsConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Path    string `mapstructure:"path"`
}

// Load reads configuration from flags, environment, and optional config file.
func Load() (*Config, error) {
	v := viper.New()

	setDefaults(v)
	bindFlags(v)
	bindEnv(v)

	configFile := v.GetString("config")
	if configFile != "" {
		v.SetConfigFile(configFile)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("read config file: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("server.addr", ":8080")
	v.SetDefault("server.shutdown_timeout", 15*time.Second)
	v.SetDefault("server.read_timeout", 60*time.Second)
	v.SetDefault("server.idle_timeout", 120*time.Second)
	v.SetDefault("server.max_request_bytes", defaultMaxRequestBytes)
	v.SetDefault("auth.file", "./auth.json")
	v.SetDefault("auth.upstream_base", "https://api.x.ai/v1")
	v.SetDefault("auth.refresh_skew", 5*time.Minute)
	v.SetDefault("db.driver", "sqlite")
	v.SetDefault("db.dsn", "./data/proxy.db")
	v.SetDefault("rate_limit.rps", 10.0)
	v.SetDefault("rate_limit.burst", 20)
	v.SetDefault("cors.allowed_origins", []string{"*"})
	v.SetDefault("log.level", "info")
	v.SetDefault("log.redact", true)
	v.SetDefault("metrics.enabled", true)
	v.SetDefault("metrics.path", "/metrics")
	v.SetDefault("audit.enabled", true)
	v.SetDefault("audit.max_body_bytes", 65536)
}

func bindFlags(v *viper.Viper) {
	pflag.String("config", "", "Path to config file (yaml/json/toml)")
	pflag.String("server.addr", "", "HTTP listen address")
	pflag.String("server.admin_key", "", "Admin API key")
	pflag.String("auth.file", "", "Path to Grok auth.json")
	pflag.String("auth.upstream_base", "", "Upstream xAI API base URL")
	pflag.String("db.driver", "", "Database driver: sqlite|postgres")
	pflag.String("db.dsn", "", "Database DSN or SQLite path")
	pflag.String("log.level", "", "Log level: debug|info|warn|error")
	pflag.Parse()

	_ = v.BindPFlags(pflag.CommandLine)
}

func bindEnv(v *viper.Viper) {
	v.SetEnvPrefix("GAP")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Explicit bindings for nested keys that AutomaticEnv may miss with some shells.
	_ = v.BindEnv("server.addr", "GAP_SERVER_ADDR")
	_ = v.BindEnv("server.admin_key", "GAP_SERVER_ADMIN_KEY")
	_ = v.BindEnv("server.shutdown_timeout", "GAP_SERVER_SHUTDOWN_TIMEOUT")
	_ = v.BindEnv("server.read_timeout", "GAP_SERVER_READ_TIMEOUT")
	_ = v.BindEnv("server.idle_timeout", "GAP_SERVER_IDLE_TIMEOUT")
	_ = v.BindEnv("server.max_request_bytes", "GAP_SERVER_MAX_REQUEST_BYTES")
	_ = v.BindEnv("auth.file", "GAP_AUTH_FILE")
	_ = v.BindEnv("auth.upstream_base", "GAP_AUTH_UPSTREAM_BASE")
	_ = v.BindEnv("auth.refresh_skew", "GAP_AUTH_REFRESH_SKEW")
	_ = v.BindEnv("auth.issuer", "GAP_AUTH_ISSUER")
	_ = v.BindEnv("auth.client_id", "GAP_AUTH_CLIENT_ID")
	_ = v.BindEnv("auth.account", "GAP_AUTH_ACCOUNT")
	_ = v.BindEnv("db.driver", "GAP_DB_DRIVER")
	_ = v.BindEnv("db.dsn", "GAP_DB_DSN")
	_ = v.BindEnv("rate_limit.rps", "GAP_RATE_LIMIT_RPS")
	_ = v.BindEnv("rate_limit.burst", "GAP_RATE_LIMIT_BURST")
	_ = v.BindEnv("log.level", "GAP_LOG_LEVEL")
	_ = v.BindEnv("log.redact", "GAP_LOG_REDACT")
	_ = v.BindEnv("metrics.enabled", "GAP_METRICS_ENABLED")
	_ = v.BindEnv("metrics.path", "GAP_METRICS_PATH")
	_ = v.BindEnv("audit.enabled", "GAP_AUDIT_ENABLED")
	_ = v.BindEnv("audit.max_body_bytes", "GAP_AUDIT_MAX_BODY_BYTES")
	_ = v.BindEnv("config", "GAP_CONFIG")
}

// Validate checks required fields.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.Server.AdminKey) == "" {
		return fmt.Errorf("server.admin_key is required (set GAP_SERVER_ADMIN_KEY or --server.admin_key)")
	}
	if strings.TrimSpace(c.Auth.File) == "" {
		return fmt.Errorf("auth.file is required")
	}
	if strings.TrimSpace(c.Auth.UpstreamBase) == "" {
		return fmt.Errorf("auth.upstream_base is required")
	}
	// The upstream request carries the Grok access token in an Authorization
	// header, so plaintext HTTP to a remote host would leak it on the wire.
	if err := requireSecureURL("auth.upstream_base", c.Auth.UpstreamBase); err != nil {
		return err
	}
	// The issuer receives the refresh_token during token exchange.
	if strings.TrimSpace(c.Auth.Issuer) != "" {
		if err := requireSecureURL("auth.issuer", c.Auth.Issuer); err != nil {
			return err
		}
	}
	driver := strings.ToLower(c.DB.Driver)
	if driver != "sqlite" && driver != "postgres" {
		return fmt.Errorf("db.driver must be sqlite or postgres, got %q", c.DB.Driver)
	}
	c.DB.Driver = driver
	if c.RateLimit.RPS <= 0 {
		return fmt.Errorf("rate_limit.rps must be > 0")
	}
	if c.RateLimit.Burst <= 0 {
		return fmt.Errorf("rate_limit.burst must be > 0")
	}
	if c.Server.ShutdownTimeout <= 0 {
		c.Server.ShutdownTimeout = 15 * time.Second
	}
	if c.Auth.RefreshSkew <= 0 {
		c.Auth.RefreshSkew = 5 * time.Minute
	}
	if c.Audit.MaxBodyBytes <= 0 {
		c.Audit.MaxBodyBytes = 65536
	}
	if c.Server.ReadTimeout <= 0 {
		c.Server.ReadTimeout = defaultReadTimeout
	}
	if c.Server.IdleTimeout <= 0 {
		c.Server.IdleTimeout = defaultIdleTimeout
	}
	if c.Server.MaxRequestBytes <= 0 {
		c.Server.MaxRequestBytes = defaultMaxRequestBytes
	}
	// Strip trailing slash from upstream base for consistent path join.
	c.Auth.UpstreamBase = strings.TrimRight(c.Auth.UpstreamBase, "/")
	return nil
}

// requireSecureURL rejects URLs that would carry credentials in cleartext.
// Plain HTTP is tolerated only for loopback hosts, which never leave the machine
// and are the common case for local mock upstreams in tests and development.
func requireSecureURL(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s is not a valid URL: %w", field, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("%s must use https (got %q): credentials would be sent in cleartext", field, raw)
	case "":
		return fmt.Errorf("%s must be an absolute http(s) URL, got %q", field, raw)
	default:
		return fmt.Errorf("%s must use http or https, got scheme %q", field, u.Scheme)
	}
}

func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
