package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"sentinel/collector/internal/wire"
)

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func makeEvent(id string) wire.Event {
	return wire.Event{
		SchemaVersion:   1,
		EventID:         id,
		ClientID:        "c1",
		SentinelVersion: "0.3.1",
		Timestamp:       "2026-04-12T10:00:00Z",
		Source:          "driver",
		DetectionType:   "DMA_ANOMALY",
		Severity:        "high",
		Confidence:      80,
		Summary:         "test event " + id,
		Host:            wire.Host{Hostname: "h", OSVersion: "Win11", Arch: "x64"},
		Context:         map[string]any{"k": "v"},
	}
}

func TestSQLite_InsertAndGet(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	e := makeEvent("id-1")
	inserted, err := s.InsertBatch(ctx, []wire.Event{e}, time.Now().UTC())
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if inserted != 1 {
		t.Errorf("inserted: got %d want 1", inserted)
	}

	got, err := s.GetByID(ctx, "id-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.EventID != "id-1" || got.Summary != "test event id-1" {
		t.Errorf("got back wrong event: %+v", got)
	}
	if got.Context["k"] != "v" {
		t.Errorf("context did not round-trip: %+v", got.Context)
	}
}

func TestSQLite_Idempotency(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	batch := []wire.Event{makeEvent("dup"), makeEvent("dup"), makeEvent("other")}
	inserted, err := s.InsertBatch(ctx, batch, time.Now().UTC())
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if inserted != 2 {
		t.Errorf("inserted: got %d want 2 (1 duplicate should be ignored)", inserted)
	}
}

func TestSQLite_ListRecent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	times := []string{
		"2026-04-12T10:00:00Z",
		"2026-04-12T11:00:00Z",
		"2026-04-12T12:00:00Z",
	}
	for i, ts := range times {
		e := makeEvent(times[i])
		e.Timestamp = ts
		if _, err := s.InsertBatch(ctx, []wire.Event{e}, time.Now().UTC()); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	events, err := s.ListRecent(ctx, 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
	// Newest-first ordering.
	if events[0].EventID != "2026-04-12T12:00:00Z" {
		t.Errorf("expected newest first, got %q", events[0].EventID)
	}
}
