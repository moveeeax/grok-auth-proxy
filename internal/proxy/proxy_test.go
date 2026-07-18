package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
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
