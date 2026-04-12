package query

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
	ks.Add("op", "opkey")
	return New(s, ks), s
}

func insertEvents(t *testing.T, s *store.SQLiteStore, ids ...string) {
	t.Helper()
	for _, id := range ids {
		e := wire.Event{
			SchemaVersion: 1, EventID: id, ClientID: "c",
			SentinelVersion: "1", Timestamp: "2026-04-12T10:00:00Z",
			Source: "driver", DetectionType: "DMA_ANOMALY",
			Severity: "high", Confidence: 80, Summary: id,
			Host:    wire.Host{Hostname: "h", OSVersion: "o", Arch: "x64"},
			Context: map[string]any{},
		}
		if _, err := s.InsertBatch(context.Background(), []wire.Event{e}, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestQuery_List(t *testing.T) {
	h, s := setup(t)
	insertEvents(t, s, "a", "b", "c")

	req := httptest.NewRequest("GET", "/v1/events", nil)
	req.Header.Set("Authorization", "Bearer opkey")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body=%q", w.Code, w.Body.String())
	}
	var resp struct {
		Events []wire.Event `json:"events"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Events) != 3 {
		t.Errorf("got %d events, want 3", len(resp.Events))
	}
}

func TestQuery_GetByID(t *testing.T) {
	h, s := setup(t)
	insertEvents(t, s, "x")

	req := httptest.NewRequest("GET", "/v1/events/x", nil)
	req.Header.Set("Authorization", "Bearer opkey")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", w.Code)
	}
	var e wire.Event
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatal(err)
	}
	if e.EventID != "x" {
		t.Errorf("got %q, want x", e.EventID)
	}
}

func TestQuery_GetByID_NotFound(t *testing.T) {
	h, _ := setup(t)
	req := httptest.NewRequest("GET", "/v1/events/nope", nil)
	req.Header.Set("Authorization", "Bearer opkey")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404", w.Code)
	}
}

func TestQuery_NoAuth(t *testing.T) {
	h, _ := setup(t)
	req := httptest.NewRequest("GET", "/v1/events", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", w.Code)
	}
}
