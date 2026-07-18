package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	keyPrefix      = "sk-gap-"
	prefixDisplay  = 12 // characters of random part shown in prefix
	bcryptCost     = 12
	randomKeyBytes = 32
)

// APIKey is the persisted API key record. The plaintext key is never stored.
type APIKey struct {
	ID           string     `gorm:"primaryKey;size:36" json:"id"`
	Name         string     `gorm:"size:128" json:"name"`
	KeyHash      string     `gorm:"size:128;not null" json:"-"`
	KeyLookup    string     `gorm:"size:64;uniqueIndex;not null" json:"-"` // sha256 of full key for O(1) lookup
	KeyPrefix    string     `gorm:"size:32" json:"key_prefix"`
	RateLimitRPS *float64   `json:"rate_limit_rps,omitempty"`
	Enabled      bool       `gorm:"not null;default:true" json:"enabled"`
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

// CreateKeyResult is returned once on key creation (includes plaintext).
type CreateKeyResult struct {
	Key       APIKey `json:"key"`
	Plaintext string `json:"plaintext"`
}

// Store abstracts API key persistence.
type Store struct {
	db *gorm.DB
}

// Open opens a SQLite or PostgreSQL database and runs migrations.
func Open(driver, dsn string) (*Store, error) {
	var dialector gorm.Dialector
	switch strings.ToLower(driver) {
	case "sqlite":
		if dir := filepath.Dir(dsn); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return nil, fmt.Errorf("create db dir: %w", err)
			}
		}
		// Pure Go SQLite (modernc) — works with CGO_ENABLED=0.
		dialector = sqlite.Open(dsn)
	case "postgres":
		dialector = postgres.Open(dsn)
	default:
		return nil, fmt.Errorf("unsupported db driver %q", driver)
	}

	db, err := gorm.Open(dialector, &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err := db.AutoMigrate(&APIKey{}); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying DB.
func (s *Store) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// Ping checks database connectivity.
func (s *Store) Ping() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Ping()
}

// CreateKey generates a new API key.
func (s *Store) CreateKey(name string, rateLimitRPS *float64) (*CreateKeyResult, error) {
	plaintext, err := generatePlaintext()
	if err != nil {
		return nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcryptCost)
	if err != nil {
		return nil, err
	}
	id, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	rec := APIKey{
		ID:           id,
		Name:         name,
		KeyHash:      string(hash),
		KeyLookup:    lookupHash(plaintext),
		KeyPrefix:    displayPrefix(plaintext),
		RateLimitRPS: rateLimitRPS,
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
	}
	if err := s.db.Create(&rec).Error; err != nil {
		return nil, err
	}
	return &CreateKeyResult{Key: rec, Plaintext: plaintext}, nil
}

// ListKeys returns all keys (no secrets).
func (s *Store) ListKeys() ([]APIKey, error) {
	var keys []APIKey
	if err := s.db.Order("created_at desc").Find(&keys).Error; err != nil {
		return nil, err
	}
	return keys, nil
}

// RevokeKey soft-disables a key by ID.
func (s *Store) RevokeKey(id string) error {
	now := time.Now().UTC()
	res := s.db.Model(&APIKey{}).Where("id = ? AND revoked_at IS NULL", id).Updates(map[string]any{
		"enabled":    false,
		"revoked_at": now,
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// ValidatePlaintext checks a bearer token against the store.
// Returns the key record if valid.
func (s *Store) ValidatePlaintext(plaintext string) (*APIKey, error) {
	if plaintext == "" {
		return nil, ErrUnauthorized
	}
	var rec APIKey
	err := s.db.Where("key_lookup = ? AND enabled = ? AND revoked_at IS NULL", lookupHash(plaintext), true).
		First(&rec).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUnauthorized
	}
	if err != nil {
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(rec.KeyHash), []byte(plaintext)); err != nil {
		return nil, ErrUnauthorized
	}
	now := time.Now().UTC()
	_ = s.db.Model(&APIKey{}).Where("id = ?", rec.ID).Update("last_used_at", now).Error
	rec.LastUsedAt = &now
	return &rec, nil
}

// ErrNotFound is returned when a key id does not exist.
var ErrNotFound = errors.New("api key not found")

// ErrUnauthorized is returned when a key is invalid or revoked.
var ErrUnauthorized = errors.New("invalid api key")

func generatePlaintext() (string, error) {
	b, err := randomHex(randomKeyBytes)
	if err != nil {
		return "", err
	}
	return keyPrefix + b, nil
}

func displayPrefix(plaintext string) string {
	// sk-gap- + first N hex chars
	if len(plaintext) < len(keyPrefix)+prefixDisplay {
		return plaintext
	}
	return plaintext[:len(keyPrefix)+prefixDisplay] + "…"
}

func lookupHash(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
