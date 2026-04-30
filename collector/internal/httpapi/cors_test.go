package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORS_PreflightReturnsAllowedHeaders(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("inner handler should not run for OPTIONS preflight")
	})
	h := WithCORS([]string{"http://localhost:3000"}, inner)

	req := httptest.NewRequest(http.MethodOptions, "/v1/events", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "GET")
	req.Header.Set("Access-Control-Request-Headers", "Authorization")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Fatalf("Allow-Origin = %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Fatal("Allow-Methods missing")
	}
	if got := rec.Header().Get("Access-Control-Allow-Headers"); got == "" {
		t.Fatal("Allow-Headers missing")
	}
}

func TestCORS_DisallowedOriginGetsNoHeaders(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := WithCORS([]string{"http://localhost:3000"}, inner)

	req := httptest.NewRequest(http.MethodGet, "/v1/events", nil)
	req.Header.Set("Origin", "http://evil.example")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Allow-Origin should be empty for unallowed origin, got %q", got)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("inner handler should still run, got %d", rec.Code)
	}
}

func TestCORS_NoOriginPassesThrough(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := WithCORS([]string{"http://localhost:3000"}, inner)

	req := httptest.NewRequest(http.MethodGet, "/v1/events", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for non-CORS request, got %d", rec.Code)
	}
}
