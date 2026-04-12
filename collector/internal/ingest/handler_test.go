package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sentinel/collector/internal/auth"
	"sentinel/collector/internal/store"
	"sentinel/collector/internal/wire"
)

func setup(t *testing.T) (*Handler, *store.SQLiteStore) {
	t.Helper()
	s, err := store.OpenSQLite(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	ks := auth.NewKeyStore()
	ks.Add("test-client", "s3cret")

	return New(s, ks), s
}

func validBatchJSON() []byte {
	b := wire.Batch{Events: []wire.Event{{
		SchemaVersion: 1, EventID: "e1", ClientID: "c", SentinelVersion: "1",
		Timestamp: "2026-04-12T00:00:00Z", Source: "driver",
		DetectionType: "DMA_ANOMALY", Severity: "high", Confidence: 80,
		Summary: "x",
		Host:    wire.Host{Hostname: "h", OSVersion: "o", Arch: "x64"},
		Context: map[string]any{},
	}}}
	raw, _ := json.Marshal(b)
	return raw
}

func TestIngest_HappyPath(t *testing.T) {
	h, s := setup(t)
	req := httptest.NewRequest("POST", "/v1/events", bytes.NewReader(validBatchJSON()))
	req.Header.Set("Authorization", "Bearer s3cret")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("status: got %d, want 202; body=%q", w.Code, w.Body.String())
	}
	ev, err := s.GetByID(context.Background(), "e1")
	if err != nil {
		t.Fatalf("event not stored: %v", err)
	}
	if ev.EventID != "e1" {
		t.Errorf("stored event wrong: %+v", ev)
	}
}

func TestIngest_MissingAuth(t *testing.T) {
	h, _ := setup(t)
	req := httptest.NewRequest("POST", "/v1/events", bytes.NewReader(validBatchJSON()))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", w.Code)
	}
}

func TestIngest_BadKey(t *testing.T) {
	h, _ := setup(t)
	req := httptest.NewRequest("POST", "/v1/events", bytes.NewReader(validBatchJSON()))
	req.Header.Set("Authorization", "Bearer wrong")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", w.Code)
	}
}

func TestIngest_MalformedJSON(t *testing.T) {
	h, _ := setup(t)
	req := httptest.NewRequest("POST", "/v1/events", strings.NewReader("not json"))
	req.Header.Set("Authorization", "Bearer s3cret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", w.Code)
	}
}

func TestIngest_BadSchemaVersion(t *testing.T) {
	h, _ := setup(t)
	b := wire.Batch{Events: []wire.Event{{SchemaVersion: 999}}}
	raw, _ := json.Marshal(b)
	req := httptest.NewRequest("POST", "/v1/events", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer s3cret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "schema_version") {
		t.Errorf("body should name failing field, got %q", w.Body.String())
	}
}

func TestIngest_Idempotent(t *testing.T) {
	h, s := setup(t)
	body := validBatchJSON()

	send := func() int {
		req := httptest.NewRequest("POST", "/v1/events", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer s3cret")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}

	if code := send(); code != http.StatusAccepted {
		t.Fatalf("first send: got %d", code)
	}
	if code := send(); code != http.StatusAccepted {
		t.Fatalf("second send: got %d", code)
	}
	events, err := s.ListRecent(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Errorf("expected 1 event after two sends, got %d", len(events))
	}
}

func TestIngest_OversizedBatch(t *testing.T) {
	h, _ := setup(t)
	// 101 events — limit is 100
	events := make([]wire.Event, 101)
	for i := range events {
		events[i] = wire.Event{
			SchemaVersion: 1, EventID: string(rune('a' + i)), ClientID: "c",
			SentinelVersion: "1", Timestamp: "2026-04-12T00:00:00Z",
			Source: "driver", DetectionType: "DMA_ANOMALY",
			Severity: "high", Confidence: 80, Summary: "x",
			Host:    wire.Host{Hostname: "h", OSVersion: "o", Arch: "x64"},
			Context: map[string]any{},
		}
	}
	raw, _ := json.Marshal(wire.Batch{Events: events})
	req := httptest.NewRequest("POST", "/v1/events", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer s3cret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("got %d, want 413", w.Code)
	}
}

// ContextTimeout is not tested here, but the handler should take a ctx.
var _ = time.Second
