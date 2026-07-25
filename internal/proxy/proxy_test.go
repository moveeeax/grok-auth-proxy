package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/moveeeax/grok-auth-proxy/internal/store"
)

type fakeTokens struct {
	token   string
	refresh int
}

func (f *fakeTokens) GetAccessToken(ctx context.Context) (string, error) {
	return f.token, nil
}

func (f *fakeTokens) ForceRefresh(ctx context.Context) error {
	f.refresh++
	f.token = "refreshed-token"
	return nil
}

type fakeAuditor struct {
	mu   sync.Mutex
	rows []*store.AuditLog
}

func (a *fakeAuditor) InsertAuditLog(row *store.AuditLog) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rows = append(a.rows, row)
	return nil
}

func (a *fakeAuditor) all() []*store.AuditLog {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]*store.AuditLog(nil), a.rows...)
}

func TestProxyForwardsAndInjectsAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var gotAuth string
	var gotBody string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("path=%s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"1","choices":[]}`))
	}))
	defer up.Close()

	tokens := &fakeTokens{token: "upstream-jwt"}
	p, err := New(up.URL+"/v1", tokens, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	r := gin.New()
	r.POST("/v1/chat/completions", p.Handler())

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"grok"}`))
	req.Header.Set("Authorization", "Bearer client-key")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if gotAuth != "Bearer upstream-jwt" {
		t.Fatalf("upstream auth=%q", gotAuth)
	}
	if !strings.Contains(gotBody, "grok") {
		t.Fatalf("body=%q", gotBody)
	}
	if !strings.Contains(w.Body.String(), `"id":"1"`) {
		t.Fatalf("response=%s", w.Body.String())
	}
}

func TestProxyRetriesOn401(t *testing.T) {
	gin.SetMode(gin.TestMode)

	hits := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		auth := r.Header.Get("Authorization")
		if auth == "Bearer old" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer up.Close()

	tokens := &fakeTokens{token: "old"}
	p, err := New(up.URL, tokens, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	r := gin.New()
	r.POST("/v1/chat/completions", p.Handler())
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	if tokens.refresh != 1 {
		t.Fatalf("refresh=%d", tokens.refresh)
	}
	if hits < 2 {
		t.Fatalf("hits=%d", hits)
	}
}

// The audit body cap must never reach the wire. Before the fix, a request
// larger than MaxBodyBytes was silently cut mid-JSON and the truncated bytes
// were forwarded to xAI, which answered with a parse error the client could not
// explain.
func TestProxyForwardsBodiesLargerThanAuditCap(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var gotBody []byte
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer up.Close()

	// A ~200 KiB request with a 1 KiB audit cap.
	content := strings.Repeat("x", 200*1024)
	sent := `{"model":"grok","messages":[{"role":"user","content":"` + content + `"}]}`

	p, err := NewWithOptions(Options{
		BaseURL:      up.URL,
		Tokens:       &fakeTokens{token: "t"},
		Log:          zap.NewNop(),
		MaxBodyBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	r.POST("/v1/chat/completions", p.Handler())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(sent)))

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if string(gotBody) != sent {
		t.Fatalf("upstream received %d bytes, want %d (body was truncated in flight)", len(gotBody), len(sent))
	}
	if !json.Valid(gotBody) {
		t.Fatal("upstream received invalid JSON")
	}
}

// The audit row still respects MaxBodyBytes even though the wire body does not.
func TestProxyAuditTruncatesStoredBodyOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer up.Close()

	aud := &fakeAuditor{}
	p, err := NewWithOptions(Options{
		BaseURL:      up.URL,
		Tokens:       &fakeTokens{token: "t"},
		Log:          zap.NewNop(),
		Auditor:      aud,
		AuditEnabled: true,
		MaxBodyBytes: 256,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	r.POST("/v1/chat/completions", p.Handler())

	sent := `{"model":"grok","pad":"` + strings.Repeat("y", 4096) + `"}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(sent)))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}

	rows := aud.all()
	if len(rows) != 1 {
		t.Fatalf("audit rows=%d, want 1", len(rows))
	}
	if len(rows[0].RequestBody) != 256 {
		t.Fatalf("stored request body=%d bytes, want 256", len(rows[0].RequestBody))
	}
	if !rows[0].RequestTruncated {
		t.Fatal("request_truncated not set on a clipped audit row")
	}
	// Model is parsed from the full body, before clipping.
	if rows[0].Model != "grok" {
		t.Fatalf("model=%q", rows[0].Model)
	}
}

func TestProxyRejectsOversizedRequestBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	upstreamHits := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits++
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer up.Close()

	p, err := NewWithOptions(Options{
		BaseURL:         up.URL,
		Tokens:          &fakeTokens{token: "t"},
		Log:             zap.NewNop(),
		MaxRequestBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	r.POST("/v1/chat/completions", p.Handler())

	w := httptest.NewRecorder()
	body := strings.NewReader(`{"pad":"` + strings.Repeat("z", 4096) + `"}`)
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", body))

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d, want 413; body=%s", w.Code, w.Body.String())
	}
	if upstreamHits != 0 {
		t.Fatalf("oversized request reached upstream %d times", upstreamHits)
	}

	// A request at the limit still goes through.
	w = httptest.NewRecorder()
	small := strings.NewReader(`{"model":"grok"}`)
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", small))
	if w.Code != http.StatusOK {
		t.Fatalf("in-limit request status=%d", w.Code)
	}
	if upstreamHits != 1 {
		t.Fatalf("upstream hits=%d, want 1", upstreamHits)
	}
}

// Credentials scoped to this proxy must never be relayed to xAI.
func TestProxyStripsClientCredentialHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var got http.Header
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer up.Close()

	p, err := New(up.URL, &fakeTokens{token: "upstream-jwt"}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	r.POST("/v1/chat/completions", p.Handler())

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer sk-gap-clientkey")
	req.Header.Set("X-Admin-Key", "admin-secret")
	req.Header.Set("Proxy-Authorization", "Basic c2VjcmV0")
	req.Header.Set("Cookie", "session=abc123")
	req.Header.Set("X-Trace-Id", "keep-me")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	if v := got.Get("Authorization"); v != "Bearer upstream-jwt" {
		t.Fatalf("upstream Authorization=%q", v)
	}
	for _, h := range []string{"X-Admin-Key", "Proxy-Authorization", "Cookie"} {
		if v := got.Get(h); v != "" {
			t.Fatalf("%s leaked upstream as %q", h, v)
		}
	}
	if v := got.Get("X-Trace-Id"); v != "keep-me" {
		t.Fatalf("benign header dropped: X-Trace-Id=%q", v)
	}
}

func TestProxyStreamSSE(t *testing.T) {
	gin.SetMode(gin.TestMode)

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("no flusher")
		}
		_, _ = io.WriteString(w, "data: {\"c\":1}\n\n")
		flusher.Flush()
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
		flusher.Flush()
	}))
	defer up.Close()

	p, err := New(up.URL, &fakeTokens{token: "t"}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	r.POST("/v1/chat/completions", p.Handler())
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"stream":true}`))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "data: {\"c\":1}") || !strings.Contains(body, "[DONE]") {
		t.Fatalf("sse body=%q", body)
	}
}
