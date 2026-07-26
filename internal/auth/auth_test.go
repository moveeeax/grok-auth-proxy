package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
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

func TestGrokCLIAuthFieldsForRefresh(t *testing.T) {
	var gotClientID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"token_endpoint": "http://" + r.Host + "/oauth/token",
			})
		case r.URL.Path == "/oauth/token":
			_ = r.ParseForm()
			gotClientID = r.Form.Get("client_id")
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
	// Real Grok CLI shape: oidc_client_id / oidc_issuer, no client_id / issuer.
	raw := []byte(`{
		"https://auth.x.ai::test": {
			"key": "old-access",
			"auth_mode": "oidc",
			"refresh_token": "old-refresh",
			"expires_at": "` + time.Now().Add(30*time.Second).UTC().Format(time.RFC3339Nano) + `",
			"oidc_client_id": "grok-cli-client",
			"oidc_issuer": "` + srv.URL + `"
		}
	}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	m, err := NewManager(Options{
		Path:        path,
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
		t.Fatalf("got %q", tok)
	}
	if gotClientID != "grok-cli-client" {
		t.Fatalf("client_id sent to token endpoint = %q, want grok-cli-client", gotClientID)
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

// TestConcurrentGetAccessTokenDedupesRefresh guards against a real race: many
// requests arriving right at token expiry each observe the same stale
// refresh_token and, without serialization, would each POST it to the
// provider concurrently. Real OAuth providers commonly rotate (single-use)
// refresh tokens, so a second use of the same token is rejected — meaning the
// losing goroutine would fail even though a sibling goroutine successfully
// refreshed the credential moments earlier. This simulates that rotation
// behavior and asserts every concurrent caller still gets the fresh token,
// and that only one refresh request actually reaches the provider.
func TestConcurrentGetAccessTokenDedupesRefresh(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]bool{}
	hits := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"token_endpoint": "http://" + r.Host + "/oauth/token",
			})
		case r.URL.Path == "/oauth/token":
			_ = r.ParseForm()
			rt := r.Form.Get("refresh_token")
			mu.Lock()
			hits++
			reused := seen[rt]
			seen[rt] = true
			mu.Unlock()
			if reused {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
				return
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
	writeTestAuthWithIssuer(t, path, "old-access", "old-refresh", time.Now().Add(2*time.Second), srv.URL, "cid")

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

	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	toks := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			toks[i], errs[i] = m.GetAccessToken(context.Background())
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: GetAccessToken failed: %v", i, err)
		}
		if toks[i] != "new-access" {
			t.Fatalf("goroutine %d: got token %q, want new-access", i, toks[i])
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 1 {
		t.Fatalf("expected exactly 1 refresh request to reach the provider, got %d", hits)
	}
}
