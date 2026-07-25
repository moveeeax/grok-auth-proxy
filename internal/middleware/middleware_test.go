package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func adminRouter(adminKey string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/admin")
	g.Use(AdminAuth(adminKey))
	g.GET("/keys", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	return r
}

func TestAdminAuthAcceptsCorrectKey(t *testing.T) {
	r := adminRouter("s3cret-admin-key")

	for _, tc := range []struct {
		name   string
		header string
		value  string
	}{
		{"x-admin-key", "X-Admin-Key", "s3cret-admin-key"},
		{"bearer", "Authorization", "Bearer s3cret-admin-key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/admin/keys", nil)
			req.Header.Set(tc.header, tc.value)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestAdminAuthRejectsWrongKeys(t *testing.T) {
	r := adminRouter("s3cret-admin-key")

	cases := map[string]string{
		"empty":           "",
		"wrong":           "not-the-key",
		"prefix":          "s3cret-admin-ke",
		"prefix-one-char": "s",
		"extra-suffix":    "s3cret-admin-keyy",
		"case-differs":    "S3CRET-ADMIN-KEY",
		"whitespace":      " s3cret-admin-key",
	}
	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/admin/keys", nil)
			if key != "" {
				req.Header.Set("X-Admin-Key", key)
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401 for %q, got %d", key, w.Code)
			}
		})
	}
}

// An admin key that was never configured must lock the endpoints, not turn them
// into an open door for callers that send nothing or an empty header.
func TestAdminAuthRejectsEverythingWhenKeyUnset(t *testing.T) {
	for _, adminKey := range []string{"", "   "} {
		r := adminRouter(adminKey)
		// "   " is the case a plain `got != adminKey` compare gets wrong: it
		// treats a blank placeholder key as a valid credential.
		for _, sent := range []string{"", " ", "   ", "anything"} {
			req := httptest.NewRequest(http.MethodGet, "/admin/keys", nil)
			req.Header.Set("X-Admin-Key", sent)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("admin_key=%q sent=%q: expected 401, got %d", adminKey, sent, w.Code)
			}
		}
	}
}

// A non-Bearer Authorization scheme must not be accepted as an admin key.
func TestAdminAuthIgnoresNonBearerAuthorization(t *testing.T) {
	r := adminRouter("s3cret-admin-key")
	req := httptest.NewRequest(http.MethodGet, "/admin/keys", nil)
	req.Header.Set("Authorization", "Basic s3cret-admin-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func corsRouter(allowed []string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(CORS(allowed))
	r.GET("/v1/models", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	return r
}

func TestCORSAllowsListedOriginOnly(t *testing.T) {
	r := corsRouter([]string{"https://app.example.com"})

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Origin", "https://app.example.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("allow-origin=%q", got)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("disallowed origin got allow-origin=%q", got)
	}
}

// Without Vary: Origin on every response, a shared cache can hand an allowed
// origin's Access-Control-Allow-Origin header to a disallowed one.
func TestCORSAlwaysVariesOnOriginWhenRestricted(t *testing.T) {
	r := corsRouter([]string{"https://app.example.com"})

	for _, origin := range []string{"https://app.example.com", "https://evil.example.com", ""} {
		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if got := w.Header().Get("Vary"); got != "Origin" {
			t.Fatalf("origin=%q: Vary=%q, want Origin", origin, got)
		}
	}
}

func TestMaskBearerKeepsSecretShort(t *testing.T) {
	if got := maskBearer("Basic abcdef"); got != "***" {
		t.Fatalf("non-bearer masked as %q", got)
	}
	full := "Bearer sk-gap-0123456789abcdef0123456789abcdef"
	got := maskBearer(full)
	if len(got) >= len(full) {
		t.Fatalf("masked value %q is not shorter than the input", got)
	}
	if got == full {
		t.Fatal("token was not masked")
	}
}
