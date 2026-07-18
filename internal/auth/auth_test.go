package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseAndSelectEntry(t *testing.T) {
	raw := []byte(`{
		"https://auth.x.ai::aaa": {
			"key": "tok-a",
			"auth_mode": "oidc",
			"refresh_token": "ref-a",
			"expires_at": "2026-01-01T00:00:00Z"
		},
		"https://auth.x.ai::bbb": {
			"key": "tok-b",
			"auth_mode": "oidc",
			"refresh_token": "ref-b",
			"expires_at": "2030-01-01T00:00:00Z"
		}
	}`)
	fd, err := ParseFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	key, entry, err := selectEntry(fd, "")
	if err != nil {
		t.Fatal(err)
	}
	// Prefer later expiry
	if entry.Key != "tok-b" {
		t.Fatalf("expected tok-b, got %s (mapKey=%s)", entry.Key, key)
	}

	_, entry, err = selectEntry(fd, "aaa")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Key != "tok-a" {
		t.Fatalf("expected tok-a for account filter, got %s", entry.Key)
	}
}

func TestGetAccessTokenNoRefreshWhenFresh(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	writeTestAuth(t, path, "fresh-token", "refresh", time.Now().Add(2*time.Hour))

	m, err := NewManager(Options{Path: path, RefreshSkew: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := m.GetAccessToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "fresh-token" {
		t.Fatalf("got %q", tok)
	}
}

func TestRefreshUpdatesToken(t *testing.T) {
	var refreshHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"token_endpoint": "http://" + r.Host + "/oauth/token",
			})
		case r.URL.Path == "/oauth/token":
			refreshHits++
			_ = r.ParseForm()
			if r.Form.Get("grant_type") != "refresh_token" {
				t.Errorf("grant_type=%s", r.Form.Get("grant_type"))
			}
			if r.Form.Get("refresh_token") != "old-refresh" {
				t.Errorf("refresh_token=%s", r.Form.Get("refresh_token"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "new-access",
				"refresh_token": "new-refresh",
				"expires_in":    3600,
				"token_type":    "Bearer",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	// Expires soon so GetAccessToken will refresh
	writeTestAuthWithIssuer(t, path, "old-access", "old-refresh", time.Now().Add(30*time.Second), srv.URL, "cid")

	m, err := NewManager(Options{
		Path:        path,
		Issuer:      srv.URL,
		ClientID:    "cid",
		RefreshSkew: 5 * time.Minute,
		HTTPClient:  srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	tok, err := m.GetAccessToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "new-access" {
		t.Fatalf("got %q, hits=%d", tok, refreshHits)
	}
	if refreshHits != 1 {
		t.Fatalf("expected 1 refresh, got %d", refreshHits)
	}

	// File should be updated
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := ParseFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range fd {
		if e.Key != "new-access" {
			t.Fatalf("file key = %q", e.Key)
		}
		if e.RefreshToken != "new-refresh" {
			t.Fatalf("file refresh = %q", e.RefreshToken)
		}
	}
}

func writeTestAuth(t *testing.T, path, key, refresh string, exp time.Time) {
	t.Helper()
	writeTestAuthWithIssuer(t, path, key, refresh, exp, "", "")
}

func writeTestAuthWithIssuer(t *testing.T, path, key, refresh string, exp time.Time, issuer, clientID string) {
	t.Helper()
	entry := Entry{
		Key:          key,
		AuthMode:     "oidc",
		RefreshToken: refresh,
		ExpiresAt:    exp.UTC(),
		Issuer:       issuer,
		ClientID:     clientID,
	}
	fd := FileData{"https://auth.x.ai::test": entry}
	raw, err := json.MarshalIndent(fd, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
