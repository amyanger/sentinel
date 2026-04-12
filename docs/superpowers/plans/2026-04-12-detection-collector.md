# Detection Collector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first piece of infrastructure that turns Sentinel from a single-machine tool into a fleet product: a central HTTP collector that receives detection events from Sentinel clients, plus the client-side code in the service that forwards events to it.

**Architecture:** A new Go binary (`collector/`) exposes a 4-endpoint HTTPS API and persists events to SQLite. A new C++ module (`service/src/collector_client.cpp`) runs inside the existing service on its own thread with a bounded queue, serializing `DetectionEvent`s to JSON and POSTing them to the collector with exponential backoff. The detection engine is untouched — the collector_client is wired in through the existing `AlertCallback` in `main.cpp`. Deployment: customer runs the collector on their own network, no cloud.

**Tech Stack:** Go (collector, `modernc.org/sqlite` pure-Go driver, `log/slog`, `net/http`, `crypto/tls`), C++17 (client-side module in existing service, WinHTTP for HTTPS, hand-rolled JSON serializer, GoogleTest for unit tests), SQLite (collector storage), Windows Credential Store (client-side API key storage).

**Working directory:** `/Users/arjunmyanger/Documents/Dev/sentinel/`

**Spec reference:** `docs/superpowers/specs/2026-04-12-detection-collector-design.md`

---

## Phase 1 — Collector foundation (Go, on macOS)

### Task 1: Scaffold collector module

**Files:**
- Create: `collector/go.mod`
- Create: `collector/cmd/collector/main.go`
- Create: `collector/README.md`

- [ ] **Step 1: Create directory structure and initialize Go module**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
mkdir -p collector/cmd/collector
mkdir -p collector/internal/{ingest,query,store,auth,config,wire}
mkdir -p collector/schema
mkdir -p collector/testdata
cd collector
go mod init sentinel/collector
```

Expected: creates `collector/go.mod` with `module sentinel/collector` and a Go version line.

- [ ] **Step 2: Write minimal main.go that compiles and prints a version banner**

Create `collector/cmd/collector/main.go`:

```go
package main

import (
	"fmt"
	"os"
)

const version = "0.1.0"

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "version" {
		fmt.Println("sentinel-collector", version)
		return
	}
	fmt.Fprintln(os.Stderr, "usage: collector [version|serve|admin]")
	os.Exit(2)
}
```

- [ ] **Step 3: Build and verify it runs**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel/collector
go build ./cmd/collector
./collector version
```

Expected output: `sentinel-collector 0.1.0`

- [ ] **Step 4: Write minimal README**

Create `collector/README.md`:

```markdown
# Sentinel Detection Collector

Central service that receives detection events from Sentinel clients and stores
them in a local SQLite database. Runs as a single static binary on the
customer's own network.

See `docs/superpowers/specs/2026-04-12-detection-collector-design.md` for the
full design.

## Build
    go build ./cmd/collector

## Run
    collector serve --config collector.toml

## Admin
    collector admin add-client <client-name>
```

- [ ] **Step 5: Commit**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
git add collector/
git commit -m "collector: scaffold Go module and version subcommand"
```

---

### Task 2: Wire format types and JSON round-trip

**Files:**
- Create: `collector/internal/wire/event.go`
- Create: `collector/internal/wire/event_test.go`

- [ ] **Step 1: Write the failing test**

Create `collector/internal/wire/event_test.go`:

```go
package wire

import (
	"encoding/json"
	"testing"
)

func TestEvent_RoundTrip(t *testing.T) {
	original := Event{
		SchemaVersion:   1,
		EventID:         "018f4a2c-7e10-7b1a-9c5d-1f2e3a4b5c6d",
		ClientID:        "acme-07",
		SentinelVersion: "0.3.1",
		Timestamp:       "2026-04-12T14:03:27.412Z",
		Source:          "driver",
		DetectionType:   "DMA_ANOMALY",
		Severity:        "high",
		Confidence:      87,
		Summary:         "Unknown PCIe device",
		Host: Host{
			Hostname:  "TRADING-07",
			OSVersion: "Windows 11 23H2",
			Arch:      "x64",
		},
		Context: map[string]any{
			"pcie_vendor_id": "0x10ee",
			"bus":            "03:00.0",
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Event
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.EventID != original.EventID {
		t.Errorf("event_id mismatch: got %q, want %q", decoded.EventID, original.EventID)
	}
	if decoded.SchemaVersion != 1 {
		t.Errorf("schema_version mismatch: got %d, want 1", decoded.SchemaVersion)
	}
	if decoded.Host.Hostname != "TRADING-07" {
		t.Errorf("host.hostname mismatch: got %q", decoded.Host.Hostname)
	}
	if decoded.Context["bus"] != "03:00.0" {
		t.Errorf("context.bus mismatch: got %v", decoded.Context["bus"])
	}
}

func TestBatch_Unmarshal(t *testing.T) {
	raw := `{"events":[{"schema_version":1,"event_id":"a","client_id":"c","sentinel_version":"1","timestamp":"2026-04-12T00:00:00Z","source":"driver","detection_type":"DMA_ANOMALY","severity":"high","confidence":80,"summary":"x","host":{"hostname":"h","os_version":"o","arch":"x64"},"context":{}}]}`

	var batch Batch
	if err := json.Unmarshal([]byte(raw), &batch); err != nil {
		t.Fatalf("unmarshal batch: %v", err)
	}
	if len(batch.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(batch.Events))
	}
	if batch.Events[0].EventID != "a" {
		t.Errorf("event id mismatch: got %q", batch.Events[0].EventID)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel/collector
go test ./internal/wire/
```

Expected: compile error, `undefined: Event` / `undefined: Batch` / `undefined: Host`.

- [ ] **Step 3: Write the minimal implementation**

Create `collector/internal/wire/event.go`:

```go
// Package wire defines the JSON types used on the network between Sentinel
// clients and the collector. These types are the public schema — changing
// them is a versioned operation.
package wire

// CurrentSchemaVersion is the version the collector understands.
const CurrentSchemaVersion = 1

// Event is one detection event as transmitted over the wire.
type Event struct {
	SchemaVersion   int            `json:"schema_version"`
	EventID         string         `json:"event_id"`
	ClientID        string         `json:"client_id"`
	SentinelVersion string         `json:"sentinel_version"`
	Timestamp       string         `json:"timestamp"` // ISO-8601 UTC, from client
	Source          string         `json:"source"`    // "driver" | "service"
	DetectionType   string         `json:"detection_type"`
	Severity        string         `json:"severity"` // "info"|"low"|"medium"|"high"|"critical"
	Confidence      int            `json:"confidence"` // 0-100
	Summary         string         `json:"summary"`
	Host            Host           `json:"host"`
	Context         map[string]any `json:"context"`
}

// Host describes the client machine that produced an event.
type Host struct {
	Hostname  string `json:"hostname"`
	OSVersion string `json:"os_version"`
	Arch      string `json:"arch"`
}

// Batch is the request body of POST /v1/events.
type Batch struct {
	Events []Event `json:"events"`
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel/collector
go test ./internal/wire/ -v
```

Expected: `PASS` for both tests.

- [ ] **Step 5: Commit**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
git add collector/internal/wire/
git commit -m "collector: add wire format types and JSON round-trip test"
```

---

### Task 3: Event validation

**Files:**
- Create: `collector/internal/wire/validate.go`
- Create: `collector/internal/wire/validate_test.go`

- [ ] **Step 1: Write the failing test**

Create `collector/internal/wire/validate_test.go`:

```go
package wire

import "testing"

func validEvent() Event {
	return Event{
		SchemaVersion:   1,
		EventID:         "018f4a2c-7e10-7b1a-9c5d-1f2e3a4b5c6d",
		ClientID:        "c",
		SentinelVersion: "1",
		Timestamp:       "2026-04-12T00:00:00Z",
		Source:          "driver",
		DetectionType:   "DMA_ANOMALY",
		Severity:        "high",
		Confidence:      80,
		Summary:         "x",
		Host:            Host{Hostname: "h", OSVersion: "o", Arch: "x64"},
		Context:         map[string]any{},
	}
}

func TestValidate_Valid(t *testing.T) {
	if err := Validate(validEvent()); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_WrongSchemaVersion(t *testing.T) {
	e := validEvent()
	e.SchemaVersion = 2
	err := Validate(e)
	if err == nil || err.Field != "schema_version" {
		t.Errorf("expected schema_version error, got %v", err)
	}
}

func TestValidate_MissingEventID(t *testing.T) {
	e := validEvent()
	e.EventID = ""
	err := Validate(e)
	if err == nil || err.Field != "event_id" {
		t.Errorf("expected event_id error, got %v", err)
	}
}

func TestValidate_BadSeverity(t *testing.T) {
	e := validEvent()
	e.Severity = "fatal"
	err := Validate(e)
	if err == nil || err.Field != "severity" {
		t.Errorf("expected severity error, got %v", err)
	}
}

func TestValidate_BadSource(t *testing.T) {
	e := validEvent()
	e.Source = "cosmic-ray"
	err := Validate(e)
	if err == nil || err.Field != "source" {
		t.Errorf("expected source error, got %v", err)
	}
}

func TestValidate_ConfidenceOutOfRange(t *testing.T) {
	e := validEvent()
	e.Confidence = 101
	err := Validate(e)
	if err == nil || err.Field != "confidence" {
		t.Errorf("expected confidence error, got %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel/collector
go test ./internal/wire/
```

Expected: compile error, `undefined: Validate`.

- [ ] **Step 3: Write the implementation**

Create `collector/internal/wire/validate.go`:

```go
package wire

import "fmt"

// ValidationError describes a single field that failed validation.
// It is returned from Validate and surfaced to clients as HTTP 400 with
// a body naming the failing field.
type ValidationError struct {
	Field  string
	Reason string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("wire: %s: %s", e.Field, e.Reason)
}

var allowedSeverities = map[string]bool{
	"info": true, "low": true, "medium": true, "high": true, "critical": true,
}

var allowedSources = map[string]bool{
	"driver": true, "service": true,
}

// Validate checks a single Event against schema v1 rules.
// Returns nil if valid, or a *ValidationError describing the first failure.
func Validate(e Event) *ValidationError {
	if e.SchemaVersion != CurrentSchemaVersion {
		return &ValidationError{"schema_version", fmt.Sprintf("want %d, got %d", CurrentSchemaVersion, e.SchemaVersion)}
	}
	if e.EventID == "" {
		return &ValidationError{"event_id", "required"}
	}
	if e.ClientID == "" {
		return &ValidationError{"client_id", "required"}
	}
	if e.Timestamp == "" {
		return &ValidationError{"timestamp", "required"}
	}
	if !allowedSources[e.Source] {
		return &ValidationError{"source", fmt.Sprintf("must be one of driver|service, got %q", e.Source)}
	}
	if e.DetectionType == "" {
		return &ValidationError{"detection_type", "required"}
	}
	if !allowedSeverities[e.Severity] {
		return &ValidationError{"severity", fmt.Sprintf("unknown severity %q", e.Severity)}
	}
	if e.Confidence < 0 || e.Confidence > 100 {
		return &ValidationError{"confidence", fmt.Sprintf("must be 0-100, got %d", e.Confidence)}
	}
	if e.Summary == "" {
		return &ValidationError{"summary", "required"}
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel/collector
go test ./internal/wire/ -v
```

Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
git add collector/internal/wire/
git commit -m "collector: add wire format validation"
```

---

### Task 4: Store package — SQLite schema and insert/read

**Files:**
- Create: `collector/schema/0001_init.sql`
- Create: `collector/internal/store/store.go`
- Create: `collector/internal/store/sqlite.go`
- Create: `collector/internal/store/sqlite_test.go`
- Modify: `collector/go.mod` (add `modernc.org/sqlite` dependency)

- [ ] **Step 1: Add the SQLite driver**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel/collector
go get modernc.org/sqlite
go mod tidy
```

Expected: `go.mod` now has `modernc.org/sqlite` as a dependency, `go.sum` is populated.

- [ ] **Step 2: Write the schema migration file**

Create `collector/schema/0001_init.sql`:

```sql
CREATE TABLE IF NOT EXISTS events (
  event_id       TEXT PRIMARY KEY,
  client_id      TEXT NOT NULL,
  received_at    TEXT NOT NULL,
  client_ts      TEXT NOT NULL,
  detection_type TEXT NOT NULL,
  severity       TEXT NOT NULL,
  confidence     INTEGER NOT NULL,
  source         TEXT NOT NULL,
  summary        TEXT NOT NULL,
  raw_json       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_client_ts
  ON events(client_id, client_ts DESC);

CREATE INDEX IF NOT EXISTS idx_events_received_at
  ON events(received_at DESC);
```

- [ ] **Step 3: Write the failing test**

Create `collector/internal/store/sqlite_test.go`:

```go
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
```

- [ ] **Step 4: Run test to verify it fails**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel/collector
go test ./internal/store/
```

Expected: compile error, `undefined: OpenSQLite`, `undefined: SQLiteStore`.

- [ ] **Step 5: Write the store interface**

Create `collector/internal/store/store.go`:

```go
// Package store persists collector events. The Store interface is the seam
// for future Postgres or other backends — today, only SQLite is implemented.
package store

import (
	"context"
	"time"

	"sentinel/collector/internal/wire"
)

// Store is the persistence interface for detection events.
type Store interface {
	// InsertBatch inserts events transactionally. Returns the number of
	// events actually written (duplicates by event_id are silently skipped).
	// receivedAt is stamped on every event as the collector-side receive time.
	InsertBatch(ctx context.Context, events []wire.Event, receivedAt time.Time) (int, error)

	// GetByID returns one event, or ErrNotFound if none.
	GetByID(ctx context.Context, eventID string) (wire.Event, error)

	// ListRecent returns up to limit events, newest-first by client_ts.
	ListRecent(ctx context.Context, limit int) ([]wire.Event, error)

	Close() error
}
```

- [ ] **Step 6: Write the SQLite implementation**

Create `collector/internal/store/sqlite.go`:

```go
package store

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"sentinel/collector/internal/wire"
)

// ErrNotFound is returned by GetByID when no row exists.
var ErrNotFound = errors.New("store: event not found")

//go:embed ../../schema/0001_init.sql
var schemaInit string

// SQLiteStore is the default storage backend for MVP deployments.
type SQLiteStore struct {
	db *sql.DB
}

// OpenSQLite opens (and creates if needed) a SQLite database at path.
// It enables WAL mode and applies the schema migration.
func OpenSQLite(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// Single connection for writes would be safest, but SQLite + WAL handles
	// concurrent reads fine. We rely on sql.DB's built-in pooling.

	if _, err := db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		return nil, fmt.Errorf("enable wal: %w", err)
	}
	if _, err := db.Exec(`PRAGMA synchronous=NORMAL;`); err != nil {
		return nil, fmt.Errorf("set synchronous: %w", err)
	}
	// busy_timeout handles SQLITE_BUSY at the driver level: any statement
	// that would otherwise return BUSY waits up to this many milliseconds
	// for the lock to become free. This is the idiomatic equivalent of the
	// spec's "retry up to 3x with small backoff" requirement (§4.5).
	if _, err := db.Exec(`PRAGMA busy_timeout=5000;`); err != nil {
		return nil, fmt.Errorf("set busy_timeout: %w", err)
	}
	if _, err := db.Exec(schemaInit); err != nil {
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

func (s *SQLiteStore) InsertBatch(ctx context.Context, events []wire.Event, receivedAt time.Time) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT OR IGNORE INTO events
		  (event_id, client_id, received_at, client_ts, detection_type,
		   severity, confidence, source, summary, raw_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return 0, fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()

	receivedStr := receivedAt.UTC().Format(time.RFC3339Nano)
	inserted := 0
	for _, e := range events {
		raw, err := json.Marshal(e)
		if err != nil {
			return inserted, fmt.Errorf("marshal event %s: %w", e.EventID, err)
		}
		res, err := stmt.ExecContext(ctx,
			e.EventID, e.ClientID, receivedStr, e.Timestamp,
			e.DetectionType, e.Severity, e.Confidence, e.Source, e.Summary,
			string(raw),
		)
		if err != nil {
			return inserted, fmt.Errorf("insert event %s: %w", e.EventID, err)
		}
		n, _ := res.RowsAffected()
		inserted += int(n)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return inserted, nil
}

func (s *SQLiteStore) GetByID(ctx context.Context, eventID string) (wire.Event, error) {
	var raw string
	err := s.db.QueryRowContext(ctx,
		`SELECT raw_json FROM events WHERE event_id = ?`, eventID,
	).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return wire.Event{}, ErrNotFound
	}
	if err != nil {
		return wire.Event{}, fmt.Errorf("query: %w", err)
	}
	var e wire.Event
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		return wire.Event{}, fmt.Errorf("unmarshal stored event: %w", err)
	}
	return e, nil
}

func (s *SQLiteStore) ListRecent(ctx context.Context, limit int) ([]wire.Event, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT raw_json FROM events ORDER BY client_ts DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	var out []wire.Event
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var e wire.Event
		if err := json.Unmarshal([]byte(raw), &e); err != nil {
			return nil, fmt.Errorf("unmarshal row: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
```

- [ ] **Step 7: Run tests to verify they pass**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel/collector
go test ./internal/store/ -v
```

Expected: `TestSQLite_InsertAndGet`, `TestSQLite_Idempotency`, `TestSQLite_ListRecent` all PASS.

- [ ] **Step 8: Commit**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
git add collector/
git commit -m "collector: add SQLite store with insert/get/list and idempotency"
```

---

### Task 5: Auth package — API key validation

**Files:**
- Create: `collector/internal/auth/keys.go`
- Create: `collector/internal/auth/keys_test.go`

- [ ] **Step 1: Write the failing test**

Create `collector/internal/auth/keys_test.go`:

```go
package auth

import "testing"

func TestKeyStore_AddAndVerify(t *testing.T) {
	ks := NewKeyStore()
	ks.Add("client-a", "secret-a")
	ks.Add("client-b", "secret-b")

	if name, ok := ks.Verify("secret-a"); !ok || name != "client-a" {
		t.Errorf("Verify(secret-a): got (%q, %v), want (client-a, true)", name, ok)
	}
	if _, ok := ks.Verify("wrong"); ok {
		t.Errorf("Verify(wrong): expected false")
	}
	if _, ok := ks.Verify(""); ok {
		t.Errorf("Verify(empty): expected false")
	}
}

func TestParseBearer(t *testing.T) {
	cases := map[string]struct {
		header   string
		want     string
		wantOK   bool
	}{
		"ok":          {"Bearer abc123", "abc123", true},
		"no prefix":   {"abc123", "", false},
		"wrong case":  {"bearer abc123", "abc123", true}, // case-insensitive scheme
		"empty":       {"", "", false},
		"only bearer": {"Bearer ", "", false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, ok := ParseBearer(tc.header)
			if ok != tc.wantOK || got != tc.want {
				t.Errorf("got (%q, %v), want (%q, %v)", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel/collector
go test ./internal/auth/
```

Expected: compile error, `undefined: NewKeyStore`, `undefined: ParseBearer`.

- [ ] **Step 3: Write the implementation**

Create `collector/internal/auth/keys.go`:

```go
// Package auth handles API key storage and request authentication.
// Keys are shared-secret bearer tokens. Comparison is constant-time.
package auth

import (
	"crypto/subtle"
	"strings"
	"sync"
)

// KeyStore maps client names to their API keys. Thread-safe.
type KeyStore struct {
	mu   sync.RWMutex
	keys map[string]string // key -> client name
}

func NewKeyStore() *KeyStore {
	return &KeyStore{keys: make(map[string]string)}
}

// Add registers an API key for a client name.
func (ks *KeyStore) Add(clientName, apiKey string) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.keys[apiKey] = clientName
}

// Verify checks whether apiKey matches any registered key.
// Returns the associated client name and true on success.
// Uses constant-time comparison to avoid timing side channels.
func (ks *KeyStore) Verify(apiKey string) (string, bool) {
	if apiKey == "" {
		return "", false
	}
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	for storedKey, name := range ks.keys {
		if subtle.ConstantTimeCompare([]byte(storedKey), []byte(apiKey)) == 1 {
			return name, true
		}
	}
	return "", false
}

// ParseBearer extracts the token from an "Authorization: Bearer <token>"
// header value. Returns (token, true) on success. Scheme match is
// case-insensitive.
func ParseBearer(header string) (string, bool) {
	const prefix = "bearer "
	if len(header) <= len(prefix) {
		return "", false
	}
	if !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return "", false
	}
	return token, true
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel/collector
go test ./internal/auth/ -v
```

Expected: both tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
git add collector/internal/auth/
git commit -m "collector: add API key store with constant-time verify"
```

---

## Phase 2 — Collector HTTP layer

### Task 6: Ingest handler (POST /v1/events)

**Files:**
- Create: `collector/internal/ingest/handler.go`
- Create: `collector/internal/ingest/handler_test.go`

- [ ] **Step 1: Write the failing test**

Create `collector/internal/ingest/handler_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel/collector
go test ./internal/ingest/
```

Expected: compile error, `undefined: Handler`, `undefined: New`.

- [ ] **Step 3: Write the implementation**

Create `collector/internal/ingest/handler.go`:

```go
// Package ingest implements POST /v1/events.
package ingest

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"sentinel/collector/internal/auth"
	"sentinel/collector/internal/store"
	"sentinel/collector/internal/wire"
)

// MaxBatchEvents is the maximum number of events in a single POST body.
const MaxBatchEvents = 100

// MaxBodyBytes is the maximum POST body size (1 MB).
const MaxBodyBytes = 1 << 20

// Handler implements http.Handler for POST /v1/events.
type Handler struct {
	store store.Store
	keys  *auth.KeyStore
}

// New constructs an ingest Handler bound to a store and key store.
func New(s store.Store, ks *auth.KeyStore) *Handler {
	return &Handler{store: s, keys: ks}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Auth
	token, ok := auth.ParseBearer(r.Header.Get("Authorization"))
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing or malformed Authorization header")
		return
	}
	clientName, ok := h.keys.Verify(token)
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid API key")
		return
	}

	// Body size cap
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	var batch wire.Batch
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeError(w, http.StatusBadRequest, fmt.Sprintf("malformed JSON: %v", err))
		return
	}

	// Batch size cap
	if len(batch.Events) > MaxBatchEvents {
		writeError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("batch has %d events, max %d", len(batch.Events), MaxBatchEvents))
		return
	}
	if len(batch.Events) == 0 {
		writeError(w, http.StatusBadRequest, "events array is empty")
		return
	}

	// Validate every event (all-or-nothing)
	for i, e := range batch.Events {
		if verr := wire.Validate(e); verr != nil {
			writeError(w, http.StatusBadRequest,
				fmt.Sprintf("event[%d].%s: %s", i, verr.Field, verr.Reason))
			return
		}
	}

	// Insert
	inserted, err := h.store.InsertBatch(r.Context(), batch.Events, time.Now().UTC())
	if err != nil {
		slog.Error("ingest: store failed", "error", err, "client", clientName)
		writeError(w, http.StatusServiceUnavailable, "storage unavailable")
		return
	}
	slog.Info("ingest: accepted",
		"client", clientName,
		"batch_size", len(batch.Events),
		"inserted", inserted,
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"accepted": inserted,
		"received": len(batch.Events),
	})
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel/collector
go test ./internal/ingest/ -v
```

Expected: all ingest tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
git add collector/internal/ingest/
git commit -m "collector: add ingest handler with validation and idempotency"
```

---

### Task 7: Query handler (GET /v1/events, GET /v1/events/{id})

**Files:**
- Create: `collector/internal/query/handler.go`
- Create: `collector/internal/query/handler_test.go`

- [ ] **Step 1: Write the failing test**

Create `collector/internal/query/handler_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel/collector
go test ./internal/query/
```

Expected: compile error, `undefined: Handler`, `undefined: New`.

- [ ] **Step 3: Write the implementation**

Create `collector/internal/query/handler.go`:

```go
// Package query implements GET /v1/events and GET /v1/events/{id}.
package query

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"sentinel/collector/internal/auth"
	"sentinel/collector/internal/store"
	"sentinel/collector/internal/wire"
)

// Handler serves both list and get-by-id routes. It inspects the URL path to
// decide which operation to run. Routing is kept in main.go; this handler
// takes everything under "/v1/events".
type Handler struct {
	store store.Store
	keys  *auth.KeyStore
}

func New(s store.Store, ks *auth.KeyStore) *Handler {
	return &Handler{store: s, keys: ks}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token, ok := auth.ParseBearer(r.Header.Get("Authorization"))
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing or malformed Authorization header")
		return
	}
	if _, ok := h.keys.Verify(token); !ok {
		writeError(w, http.StatusUnauthorized, "invalid API key")
		return
	}

	// "/v1/events"      → list
	// "/v1/events/{id}" → getByID
	const prefix = "/v1/events"
	path := r.URL.Path
	if path == prefix || path == prefix+"/" {
		h.list(w, r)
		return
	}
	if strings.HasPrefix(path, prefix+"/") {
		id := strings.TrimPrefix(path, prefix+"/")
		if id == "" {
			writeError(w, http.StatusBadRequest, "missing event id")
			return
		}
		h.getByID(w, r, id)
		return
	}
	http.NotFound(w, r)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			limit = n
		}
	}
	events, err := h.store.ListRecent(r.Context(), limit)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "storage unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"events": events,
	})
}

func (h *Handler) getByID(w http.ResponseWriter, r *http.Request, id string) {
	e, err := h.store.GetByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "event not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "storage unavailable")
		return
	}
	// Ensure ListRecent and GetByID return non-empty context
	if e.Context == nil {
		e.Context = map[string]any{}
	}
	_ = e // silence unused if optimizer wants
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(e)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// Ensure wire package is imported (for future use of wire.Event return type
// in list responses). Currently the store returns wire.Event directly.
var _ = wire.Event{}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel/collector
go test ./internal/query/ -v
```

Expected: all query tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
git add collector/internal/query/
git commit -m "collector: add query handler for list and get-by-id"
```

---

### Task 8: Config loading

**Files:**
- Create: `collector/internal/config/config.go`
- Create: `collector/internal/config/config_test.go`
- Create: `collector/testdata/config_valid.toml`

- [ ] **Step 1: Add the TOML parser**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel/collector
go get github.com/BurntSushi/toml
go mod tidy
```

- [ ] **Step 2: Write the fixture and test**

Create `collector/testdata/config_valid.toml`:

```toml
[server]
listen = "127.0.0.1:8443"
tls_cert = "cert.pem"
tls_key = "key.pem"

[storage]
sqlite_path = "events.db"

[clients]
"acme-07" = "s3cret-key-for-acme"
"acme-12" = "s3cret-key-for-acme-12"
```

Create `collector/internal/config/config_test.go`:

```go
package config

import "testing"

func TestLoad_Valid(t *testing.T) {
	cfg, err := Load("../../testdata/config_valid.toml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Server.Listen != "127.0.0.1:8443" {
		t.Errorf("listen: got %q", cfg.Server.Listen)
	}
	if cfg.Storage.SQLitePath != "events.db" {
		t.Errorf("sqlite_path: got %q", cfg.Storage.SQLitePath)
	}
	if len(cfg.Clients) != 2 {
		t.Errorf("clients: got %d, want 2", len(cfg.Clients))
	}
	if cfg.Clients["acme-07"] != "s3cret-key-for-acme" {
		t.Errorf("acme-07 key mismatch")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load("nonexistent.toml")
	if err == nil {
		t.Errorf("expected error for missing file")
	}
}

func TestValidate_RequiresListen(t *testing.T) {
	cfg := &Config{}
	cfg.Storage.SQLitePath = "x"
	if err := cfg.Validate(); err == nil {
		t.Errorf("expected error for missing server.listen")
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel/collector
go test ./internal/config/
```

Expected: compile error, `undefined: Load`, `undefined: Config`.

- [ ] **Step 4: Write the implementation**

Create `collector/internal/config/config.go`:

```go
// Package config loads collector configuration from TOML.
package config

import (
	"errors"
	"fmt"

	"github.com/BurntSushi/toml"
)

// Config is the top-level collector configuration.
type Config struct {
	Server struct {
		Listen  string `toml:"listen"`   // host:port for HTTPS
		TLSCert string `toml:"tls_cert"` // path to PEM cert
		TLSKey  string `toml:"tls_key"`  // path to PEM key
	} `toml:"server"`

	Storage struct {
		SQLitePath string `toml:"sqlite_path"`
	} `toml:"storage"`

	// Clients maps client_name -> api_key. Loaded into the KeyStore at startup.
	Clients map[string]string `toml:"clients"`
}

// Load reads a TOML file and parses it into a Config.
func Load(path string) (*Config, error) {
	var cfg Config
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, fmt.Errorf("load config %s: %w", path, err)
	}
	if cfg.Clients == nil {
		cfg.Clients = make(map[string]string)
	}
	return &cfg, nil
}

// Validate checks required fields.
func (c *Config) Validate() error {
	if c.Server.Listen == "" {
		return errors.New("server.listen is required")
	}
	if c.Storage.SQLitePath == "" {
		return errors.New("storage.sqlite_path is required")
	}
	return nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel/collector
go test ./internal/config/ -v
```

Expected: all three tests PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
git add collector/
git commit -m "collector: add TOML config loader"
```

---

### Task 9: Main.go wiring, TLS, healthz, serve subcommand

**Files:**
- Modify: `collector/cmd/collector/main.go`
- Create: `collector/cmd/collector/serve.go`

- [ ] **Step 1: Replace main.go with dispatch logic**

Replace the contents of `collector/cmd/collector/main.go` entirely with:

```go
package main

import (
	"fmt"
	"os"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Println("sentinel-collector", version)
	case "serve":
		if err := runServe(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "serve:", err)
			os.Exit(1)
		}
	case "admin":
		if err := runAdmin(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "admin:", err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  collector version")
	fmt.Fprintln(os.Stderr, "  collector serve --config <path>")
	fmt.Fprintln(os.Stderr, "  collector admin add-client <name> --config <path>")
}
```

- [ ] **Step 2: Write the serve subcommand**

Create `collector/cmd/collector/serve.go`:

```go
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sentinel/collector/internal/auth"
	"sentinel/collector/internal/config"
	"sentinel/collector/internal/ingest"
	"sentinel/collector/internal/query"
	"sentinel/collector/internal/store"
)

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "path to collector TOML config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return errors.New("--config is required")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	s, err := store.OpenSQLite(cfg.Storage.SQLitePath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer s.Close()

	ks := auth.NewKeyStore()
	for name, key := range cfg.Clients {
		ks.Add(name, key)
	}
	slog.Info("keys loaded", "count", len(cfg.Clients))

	mux := http.NewServeMux()
	mux.Handle("/v1/events", ingestOrQuery(s, ks))
	mux.Handle("/v1/events/", query.New(s, ks))
	mux.HandleFunc("/v1/healthz", handleHealthz)

	srv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		slog.Info("collector listening", "addr", cfg.Server.Listen, "tls", cfg.Server.TLSCert != "")
		if cfg.Server.TLSCert != "" && cfg.Server.TLSKey != "" {
			errCh <- srv.ListenAndServeTLS(cfg.Server.TLSCert, cfg.Server.TLSKey)
		} else {
			// Plain HTTP is allowed ONLY for tests and local dev. Production
			// deployments should always provide a cert; the client will refuse
			// to fall back to plaintext.
			errCh <- srv.ListenAndServe()
		}
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		slog.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// ingestOrQuery dispatches POST to ingest and GET to query, both at the
// exact path "/v1/events".
func ingestOrQuery(s store.Store, ks *auth.KeyStore) http.Handler {
	ingestH := ingest.New(s, ks)
	queryH := query.New(s, ks)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			ingestH.ServeHTTP(w, r)
			return
		}
		if r.Method == http.MethodGet {
			queryH.ServeHTTP(w, r)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"version": version,
	})
}

// runAdmin is defined in admin.go (next task).
func runAdmin(args []string) error {
	return errors.New("admin not yet implemented")
}
```

- [ ] **Step 3: Build and verify**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel/collector
go build ./cmd/collector
./collector version
```

Expected: builds cleanly, prints `sentinel-collector 0.1.0`.

- [ ] **Step 4: Smoke-test serve locally (plaintext, no TLS)**

Create a temporary config at `/tmp/collector-dev.toml`:

```toml
[server]
listen = "127.0.0.1:18443"

[storage]
sqlite_path = "/tmp/collector-dev.db"

[clients]
"dev" = "dev-key-1234"
```

Run in one terminal:

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel/collector
./collector serve --config /tmp/collector-dev.toml
```

In another terminal:

```bash
curl -s http://127.0.0.1:18443/v1/healthz
```

Expected: `{"status":"ok","version":"0.1.0"}`

Stop the collector with Ctrl+C. Expected: it logs "shutting down" and exits cleanly.

- [ ] **Step 5: Commit**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
git add collector/cmd/collector/
git commit -m "collector: wire up serve subcommand with TLS, routes, graceful shutdown"
```

---

### Task 10: Admin CLI — add-client subcommand

**Files:**
- Create: `collector/cmd/collector/admin.go`
- Modify: `collector/cmd/collector/serve.go` (delete the placeholder `runAdmin`)

- [ ] **Step 1: Remove the placeholder**

In `collector/cmd/collector/serve.go`, delete these lines at the bottom:

```go
// runAdmin is defined in admin.go (next task).
func runAdmin(args []string) error {
	return errors.New("admin not yet implemented")
}
```

- [ ] **Step 2: Write the admin subcommand**

Create `collector/cmd/collector/admin.go`:

```go
package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"

	"sentinel/collector/internal/config"
)

func runAdmin(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: collector admin add-client <name> --config <path>")
	}
	switch args[0] {
	case "add-client":
		return runAdminAddClient(args[1:])
	default:
		return fmt.Errorf("unknown admin subcommand %q", args[0])
	}
}

func runAdminAddClient(args []string) error {
	fs := flag.NewFlagSet("admin add-client", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "path to collector TOML config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return errors.New("client name required")
	}
	clientName := fs.Arg(0)
	if strings.ContainsAny(clientName, " \t\n") {
		return errors.New("client name cannot contain whitespace")
	}
	if *cfgPath == "" {
		return errors.New("--config is required")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if _, exists := cfg.Clients[clientName]; exists {
		return fmt.Errorf("client %q already exists", clientName)
	}

	key, err := generateAPIKey()
	if err != nil {
		return err
	}
	if cfg.Clients == nil {
		cfg.Clients = make(map[string]string)
	}
	cfg.Clients[clientName] = key

	if err := writeConfig(*cfgPath, cfg); err != nil {
		return err
	}
	fmt.Println("client added:", clientName)
	fmt.Println("api key:     ", key)
	fmt.Println("(store this key on the client side; it cannot be recovered)")
	return nil
}

// generateAPIKey returns 32 random bytes hex-encoded (64 characters).
func generateAPIKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// writeConfig writes the config back to path. TOML marshaling preserves the
// structure but will not preserve comments from the original file — that's
// acceptable for MVP.
func writeConfig(path string, cfg *config.Config) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := toml.NewEncoder(f)
	return enc.Encode(cfg)
}
```

- [ ] **Step 3: Build and test by hand**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel/collector
go build ./cmd/collector

# Create a fresh config
cat > /tmp/admin-test.toml <<'EOF'
[server]
listen = "127.0.0.1:18443"

[storage]
sqlite_path = "/tmp/admin-test.db"

[clients]
EOF

./collector admin add-client trading-desk-01 --config /tmp/admin-test.toml
```

Expected output:

```
client added: trading-desk-01
api key:      <64 hex characters>
(store this key on the client side; it cannot be recovered)
```

Check the config file:

```bash
cat /tmp/admin-test.toml
```

Expected: `[clients]` section contains `"trading-desk-01" = "<64 hex chars>"`.

Running it again with the same name should fail:

```bash
./collector admin add-client trading-desk-01 --config /tmp/admin-test.toml
```

Expected exit 1 with `admin: client "trading-desk-01" already exists`.

- [ ] **Step 4: Commit**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
git add collector/cmd/collector/
git commit -m "collector: add admin add-client subcommand"
```

---

## Phase 3 — Collector integration tests + fault injection

### Task 11: End-to-end integration test with fault injection

**Files:**
- Create: `collector/e2e/e2e_test.go`

This test spins up the real ingest and query handlers against a real SQLite
store via an in-process `httptest.Server`. It exercises the full stack on
`localhost` with no TLS (TLS is a main.go concern, not a handler concern).

- [ ] **Step 1: Write the test file**

Create `collector/e2e/e2e_test.go`:

```go
// Package e2e contains end-to-end tests that compose ingest + query + store
// against a real httptest.Server.
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"sentinel/collector/internal/auth"
	"sentinel/collector/internal/ingest"
	"sentinel/collector/internal/query"
	"sentinel/collector/internal/store"
	"sentinel/collector/internal/wire"
)

func startCollector(t *testing.T) (*httptest.Server, *store.SQLiteStore) {
	t.Helper()
	s, err := store.OpenSQLite(filepath.Join(t.TempDir(), "e2e.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	ks := auth.NewKeyStore()
	ks.Add("e2e", "e2e-key")

	ingestH := ingest.New(s, ks)
	queryH := query.New(s, ks)

	mux := http.NewServeMux()
	mux.Handle("/v1/events", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			ingestH.ServeHTTP(w, r)
		} else {
			queryH.ServeHTTP(w, r)
		}
	}))
	mux.Handle("/v1/events/", queryH)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, s
}

func syntheticEvent(id string) wire.Event {
	return wire.Event{
		SchemaVersion:   1,
		EventID:         id,
		ClientID:        "e2e",
		SentinelVersion: "0.3.1",
		Timestamp:       "2026-04-12T12:00:00Z",
		Source:          "driver",
		DetectionType:   "DMA_ANOMALY",
		Severity:        "high",
		Confidence:      80,
		Summary:         "synthetic " + id,
		Host:            wire.Host{Hostname: "h", OSVersion: "w11", Arch: "x64"},
		Context:         map[string]any{"pcie_vendor_id": "0x10ee"},
	}
}

func postBatch(t *testing.T, url, key string, events []wire.Event) *http.Response {
	t.Helper()
	raw, err := json.Marshal(wire.Batch{Events: events})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", url+"/v1/events", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestE2E_FullRoundTrip(t *testing.T) {
	srv, _ := startCollector(t)

	// Send 50 events
	events := make([]wire.Event, 50)
	for i := range events {
		events[i] = syntheticEvent(fmt.Sprintf("e2e-%03d", i))
	}
	resp := postBatch(t, srv.URL, "e2e-key", events)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST: got %d, want 202; body=%s", resp.StatusCode, body)
	}

	// List them back
	req, _ := http.NewRequest("GET", srv.URL+"/v1/events?limit=100", nil)
	req.Header.Set("Authorization", "Bearer e2e-key")
	listResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer listResp.Body.Close()
	var listed struct {
		Events []wire.Event `json:"events"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Events) != 50 {
		t.Errorf("list returned %d, want 50", len(listed.Events))
	}

	// Get one by ID
	getReq, _ := http.NewRequest("GET", srv.URL+"/v1/events/e2e-025", nil)
	getReq.Header.Set("Authorization", "Bearer e2e-key")
	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatal(err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get by id: got %d", getResp.StatusCode)
	}
	var got wire.Event
	if err := json.NewDecoder(getResp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.EventID != "e2e-025" {
		t.Errorf("got %q, want e2e-025", got.EventID)
	}
	if got.Context["pcie_vendor_id"] != "0x10ee" {
		t.Errorf("context round-trip failed: %+v", got.Context)
	}
}

func TestE2E_Idempotency(t *testing.T) {
	srv, _ := startCollector(t)
	events := []wire.Event{syntheticEvent("dup")}

	for i := 0; i < 3; i++ {
		resp := postBatch(t, srv.URL, "e2e-key", events)
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("retry %d: got %d", i, resp.StatusCode)
		}
	}

	// Only one should exist.
	req, _ := http.NewRequest("GET", srv.URL+"/v1/events", nil)
	req.Header.Set("Authorization", "Bearer e2e-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var listed struct {
		Events []wire.Event `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Events) != 1 {
		t.Errorf("after 3 duplicate sends, got %d rows, want 1", len(listed.Events))
	}
}

func TestE2E_Fault_BadAuth(t *testing.T) {
	srv, _ := startCollector(t)
	resp := postBatch(t, srv.URL, "not-the-right-key", []wire.Event{syntheticEvent("e1")})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", resp.StatusCode)
	}
}

func TestE2E_Fault_BadSchema(t *testing.T) {
	srv, _ := startCollector(t)
	bad := syntheticEvent("bad")
	bad.Severity = "apocalyptic"
	resp := postBatch(t, srv.URL, "e2e-key", []wire.Event{bad})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("got %d, want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("severity")) {
		t.Errorf("400 body should name the failing field, got %s", body)
	}
}

// TestE2E_Fault_ServerDown verifies client-side behavior is out of scope for
// Go e2e tests — the client lives in C++. We do instead test the "server
// returns 503 when the store errors" path via a broken store in a unit test.
// See store/sqlite_test.go for store-level failures.
```

- [ ] **Step 2: Run the integration test**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel/collector
go test ./e2e/ -v
```

Expected: `TestE2E_FullRoundTrip`, `TestE2E_Idempotency`, `TestE2E_Fault_BadAuth`, `TestE2E_Fault_BadSchema` all PASS.

- [ ] **Step 3: Run the full Go test suite to verify nothing broke**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel/collector
go test ./...
```

Expected: all packages PASS.

- [ ] **Step 4: Commit**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
git add collector/e2e/
git commit -m "collector: add e2e tests covering round-trip, idempotency, and faults"
```

---

## Phase 4 — C++ client-side module (inside service/)

**Note for worker:** Phases 4, 5, and 6 touch C++ code in the existing `service/`. This code requires a Windows VM with the WDK and MSVC to compile and run. On macOS, the code should still at minimum pass `clang` syntax checks under `-DNOT_WINDOWS` or the existing `#ifdef _WIN32` guards — but full tests require the VM. Batch VM roundtrips by finishing an entire phase, then compiling and testing once in the VM.

### Task 12: collector_config.h — defaults and config struct

**Files:**
- Create: `service/include/sentinel/collector_config.h`
- Modify: `service/include/sentinel/service.h` (add fields to `ServiceConfig`)

- [ ] **Step 1: Create the config header**

Create `service/include/sentinel/collector_config.h`:

```cpp
/*
 * sentinel/collector_config.h
 *
 * Compile-time defaults and runtime config struct for the collector client.
 *
 * Runtime values (URL, API key) come from:
 *   - collector_url:  service config file / REST API
 *   - api_key:        Windows credential store (not a config file)
 *
 * Compile-time tuning knobs (queue size, retry policy) live here because
 * MVP does not expose them via runtime config. Change them and rebuild.
 */

#ifndef SENTINEL_COLLECTOR_CONFIG_H
#define SENTINEL_COLLECTOR_CONFIG_H

#include <cstddef>
#include <cstdint>
#include <string>

namespace sentinel {

/* -------------------------------------------------------------------------
 * Compile-time defaults
 * ------------------------------------------------------------------------- */

/* Maximum number of events the in-memory send queue will hold.
 * When full, the OLDEST event is dropped (not the newest) and the
 * dropped_events_total counter is incremented. */
constexpr std::size_t COLLECTOR_QUEUE_CAPACITY = 10000;

/* Maximum number of events per HTTPS POST batch. Must match the collector's
 * MaxBatchEvents constant in collector/internal/ingest/handler.go. */
constexpr std::size_t COLLECTOR_MAX_BATCH_SIZE = 100;

/* Send-trigger thresholds: flush when either condition is met. */
constexpr std::size_t COLLECTOR_BATCH_THRESHOLD = 10;    /* events */
constexpr int         COLLECTOR_FLUSH_INTERVAL_MS = 5000; /* ms */

/* Exponential backoff on retryable errors. */
constexpr int COLLECTOR_BACKOFF_INITIAL_MS = 1000;
constexpr int COLLECTOR_BACKOFF_MAX_MS     = 30000;

/* Credential store target name for the API key. */
constexpr const char* COLLECTOR_CREDENTIAL_TARGET = "SentinelCollectorApiKey";

/* -------------------------------------------------------------------------
 * Runtime config struct
 * ------------------------------------------------------------------------- */

struct CollectorConfig {
    bool        enabled = false;
    std::string url;           /* e.g., "https://collector.internal:8443" */
    std::string client_id;     /* registered with the collector */
    std::string api_key;       /* loaded from credential store at startup */
};

} /* namespace sentinel */

#endif /* SENTINEL_COLLECTOR_CONFIG_H */
```

- [ ] **Step 2: Extend `ServiceConfig`**

In `service/include/sentinel/service.h`, find the `ServiceConfig` struct (around line 142) and add `CollectorConfig collector;` as the last field. The change is:

Before:

```cpp
struct ServiceConfig {
    int poll_interval_ms    = DEFAULT_POLL_INTERVAL_MS;
    int scan_interval_ms    = DEFAULT_SCAN_INTERVAL_MS;
    double detection_threshold = 0.7;  /* Confidence to trigger alert  */
    bool enable_process_monitor = true;
    bool enable_signature_scan  = true;
    bool enable_module_integrity = true;
};
```

After:

```cpp
struct ServiceConfig {
    int poll_interval_ms    = DEFAULT_POLL_INTERVAL_MS;
    int scan_interval_ms    = DEFAULT_SCAN_INTERVAL_MS;
    double detection_threshold = 0.7;  /* Confidence to trigger alert  */
    bool enable_process_monitor = true;
    bool enable_signature_scan  = true;
    bool enable_module_integrity = true;
    CollectorConfig collector;          /* Forwarding to central collector */
};
```

And add, near the top with the other includes inside the `sentinel` namespace block (after the `#include <sentinel/shared_types.h>` line):

```cpp
#include <sentinel/collector_config.h>
```

- [ ] **Step 3: macOS syntax check**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
clang -std=c++17 -fsyntax-only -Iservice/include -Ishared/include -x c++ service/include/sentinel/collector_config.h
```

Expected: no output (success). The existing `#ifdef _WIN32` guards in `service.h` make it parseable on macOS.

- [ ] **Step 4: Commit**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
git add service/include/sentinel/collector_config.h service/include/sentinel/service.h
git commit -m "service: add CollectorConfig struct and compile-time defaults"
```

---

### Task 13: Wire format serializer (C++ → JSON string)

**Files:**
- Create: `service/include/sentinel/collector_wire.h`
- Create: `service/src/collector_wire.cpp`
- Modify: `service/CMakeLists.txt` (add `src/collector_wire.cpp` to `SERVICE_SOURCES`)

The serializer is hand-rolled — no new dependency — because the schema is
fixed and small, and the C++ side only needs to *write* JSON, never parse it.

- [ ] **Step 1: Create the header**

Create `service/include/sentinel/collector_wire.h`:

```cpp
/*
 * sentinel/collector_wire.h
 *
 * Wire format serializer for detection events sent to the collector.
 * Translates sentinel::DetectionEvent (internal C++ type) into the JSON
 * shape defined by the collector's schema v1.
 *
 * This is DELIBERATELY decoupled from detection_event_t and from the
 * driver's SENTINEL_ALERT. The internal types are optimized for fast,
 * in-process use; the wire type is optimized for stable, versioned
 * cross-host transmission. Changing one must not force a change in
 * the other.
 *
 * Output shape (schema_version = 1):
 * {
 *   "schema_version": 1,
 *   "event_id": "<uuid>",
 *   "client_id": "<from config>",
 *   "sentinel_version": "0.3.1",
 *   "timestamp": "2026-04-12T...",
 *   "source": "driver"|"service",
 *   "detection_type": "DMA_ANOMALY",
 *   "severity": "high",
 *   "confidence": 80,
 *   "summary": "...",
 *   "host": { "hostname": "...", "os_version": "...", "arch": "x64" },
 *   "context": { ... }
 * }
 */

#ifndef SENTINEL_COLLECTOR_WIRE_H
#define SENTINEL_COLLECTOR_WIRE_H

#include <sentinel/service.h>

namespace sentinel {

struct CollectorHostInfo {
    std::string hostname;
    std::string os_version;
    std::string arch;          /* "x64", "arm64" */
};

/**
 * Serialize a DetectionEvent into a JSON string matching the collector's
 * schema v1. Generates a UUIDv7 for event_id.
 *
 * @param event        The detection event to serialize.
 * @param client_id    Stable client identifier (from CollectorConfig).
 * @param host         Host info for the "host" object.
 * @param version      Sentinel service version string (e.g., "0.3.1").
 * @return JSON string, UTF-8 encoded, ready for the POST body.
 */
std::string serialize_event_json(const DetectionEvent& event,
                                  const std::string& client_id,
                                  const CollectorHostInfo& host,
                                  const std::string& version);

/**
 * Wrap one or more event JSON strings into a batch body.
 * Input: [`{"schema_version":1,...}`, `{"schema_version":1,...}`]
 * Output: `{"events":[{"schema_version":1,...},{"schema_version":1,...}]}`
 */
std::string serialize_batch(const std::vector<std::string>& event_jsons);

/**
 * Generate a UUIDv7 as a lowercase hex string with dashes.
 * Format: xxxxxxxx-xxxx-7xxx-yxxx-xxxxxxxxxxxx where y is 8,9,a,b.
 */
std::string generate_uuidv7();

/**
 * Convert AlertSource enum to the wire "detection_type" string.
 * Driver sources → "DMA_ANOMALY", "PCIE_ENUM", etc.
 * Service sources → "PROCESS_MONITOR", "SIGNATURE_SCAN", "MODULE_INTEGRITY".
 */
const char* detection_type_for_source(AlertSource src);

/**
 * Return "driver" if src is a driver-side source (0-3), "service" otherwise.
 */
const char* source_category(AlertSource src);

} /* namespace sentinel */

#endif /* SENTINEL_COLLECTOR_WIRE_H */
```

- [ ] **Step 2: Create the implementation**

Create `service/src/collector_wire.cpp`:

```cpp
/*
 * collector_wire.cpp — JSON serialization for wire format v1.
 *
 * We hand-roll JSON here (no nlohmann/json dependency) because:
 *   1. The schema is fixed and small.
 *   2. We only need to WRITE, never parse.
 *   3. Avoids adding a third-party dependency to the service build.
 *
 * Escaping follows RFC 8259 section 7: escape ", \, and control characters.
 * Non-ASCII UTF-8 is passed through unchanged (the collector is Go, which
 * handles UTF-8 natively in encoding/json).
 */

#include <sentinel/collector_wire.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <random>
#include <sstream>

namespace sentinel {

/* -------------------------------------------------------------------
 * JSON escape helper
 * ------------------------------------------------------------------- */
static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        unsigned char uc = static_cast<unsigned char>(c);
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (uc < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", uc);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

/* -------------------------------------------------------------------
 * Source → detection_type mapping
 * ------------------------------------------------------------------- */
const char* detection_type_for_source(AlertSource src) {
    switch (src) {
        case AlertSource::PCIE_ENUM:        return "PCIE_ENUM";
        case AlertSource::DMA_DETECT:       return "DMA_ANOMALY";
        case AlertSource::MEMORY:           return "MEMORY_INTEGRITY";
        case AlertSource::DEVICE_MONITOR:   return "DEVICE_MONITOR";
        case AlertSource::PROCESS_MONITOR:  return "PROCESS_MONITOR";
        case AlertSource::SIGNATURE_SCAN:   return "SIGNATURE_MATCH";
        case AlertSource::MODULE_INTEGRITY: return "MODULE_TAMPERING";
        default:                            return "UNKNOWN";
    }
}

const char* source_category(AlertSource src) {
    switch (src) {
        case AlertSource::PCIE_ENUM:
        case AlertSource::DMA_DETECT:
        case AlertSource::MEMORY:
        case AlertSource::DEVICE_MONITOR:
            return "driver";
        default:
            return "service";
    }
}

/* -------------------------------------------------------------------
 * UUIDv7 generator
 *
 * Format (RFC 9562):
 *   48 bits: unix_ts_ms
 *   4 bits:  version (0b0111)
 *   12 bits: rand_a
 *   2 bits:  variant (0b10)
 *   62 bits: rand_b
 *
 * Output: 8-4-4-4-12 hex, lowercase, with dashes.
 * ------------------------------------------------------------------- */
std::string generate_uuidv7() {
    using namespace std::chrono;
    uint64_t unix_ms = duration_cast<milliseconds>(
        system_clock::now().time_since_epoch()).count();

    /* Thread-local RNG to avoid seeding on every call */
    thread_local std::mt19937_64 rng{std::random_device{}()};
    uint64_t rand_a = rng() & 0x0FFFULL;                    /* 12 bits */
    uint64_t rand_b = rng() & 0x3FFFFFFFFFFFFFFFULL;        /* 62 bits */

    /* Assemble 128 bits into two 64-bit halves */
    uint64_t hi = (unix_ms << 16)
                | (0x7000ULL)      /* version 7 */
                | rand_a;
    uint64_t lo = (0x2ULL << 62)   /* variant 0b10 */
                | rand_b;

    char buf[40];
    std::snprintf(buf, sizeof(buf),
        "%08x-%04x-%04x-%04x-%012llx",
        static_cast<uint32_t>((hi >> 32) & 0xFFFFFFFF),
        static_cast<uint32_t>((hi >> 16) & 0xFFFF),
        static_cast<uint32_t>(hi & 0xFFFF),
        static_cast<uint32_t>((lo >> 48) & 0xFFFF),
        static_cast<unsigned long long>(lo & 0xFFFFFFFFFFFFULL));
    return std::string(buf);
}

/* -------------------------------------------------------------------
 * Event serialization
 * ------------------------------------------------------------------- */
std::string serialize_event_json(const DetectionEvent& event,
                                  const std::string& client_id,
                                  const CollectorHostInfo& host,
                                  const std::string& version) {
    int confidence_int = static_cast<int>(event.confidence * 100.0);
    if (confidence_int < 0)   confidence_int = 0;
    if (confidence_int > 100) confidence_int = 100;

    std::ostringstream os;
    os << "{"
       << "\"schema_version\":1,"
       << "\"event_id\":\"" << generate_uuidv7() << "\","
       << "\"client_id\":\"" << json_escape(client_id) << "\","
       << "\"sentinel_version\":\"" << json_escape(version) << "\","
       << "\"timestamp\":\"" << format_timestamp(event.timestamp) << "\","
       << "\"source\":\"" << source_category(event.source) << "\","
       << "\"detection_type\":\"" << detection_type_for_source(event.source) << "\","
       << "\"severity\":\"" << severity_name(event.severity) << "\","
       << "\"confidence\":" << confidence_int << ","
       << "\"summary\":\"" << json_escape(event.description) << "\","
       << "\"host\":{"
           << "\"hostname\":\"" << json_escape(host.hostname) << "\","
           << "\"os_version\":\"" << json_escape(host.os_version) << "\","
           << "\"arch\":\"" << json_escape(host.arch) << "\""
       << "},"
       << "\"context\":{"
           << "\"process_id\":" << event.process_id
       << "}"
       << "}";
    return os.str();
}

std::string serialize_batch(const std::vector<std::string>& event_jsons) {
    std::ostringstream os;
    os << "{\"events\":[";
    for (size_t i = 0; i < event_jsons.size(); ++i) {
        if (i > 0) os << ",";
        os << event_jsons[i];
    }
    os << "]}";
    return os.str();
}

} /* namespace sentinel */
```

- [ ] **Step 3: Add the new file to the service build**

In `service/CMakeLists.txt`, find the `SERVICE_SOURCES` block:

```cmake
set(SERVICE_SOURCES
    src/main.cpp
    src/driver_comm.cpp
    src/process_monitor.cpp
    src/signature_scanner.cpp
    src/module_integrity.cpp
    src/detection_engine.cpp
    src/api_server.cpp
)
```

Replace it with:

```cmake
set(SERVICE_SOURCES
    src/main.cpp
    src/driver_comm.cpp
    src/process_monitor.cpp
    src/signature_scanner.cpp
    src/module_integrity.cpp
    src/detection_engine.cpp
    src/api_server.cpp
    src/collector_wire.cpp
    src/collector_client.cpp
)
```

(The `collector_client.cpp` doesn't exist yet — Task 14 creates it. Adding it to the build list now avoids a second CMakeLists edit.)

- [ ] **Step 4: macOS syntax check**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
clang -std=c++17 -fsyntax-only -Iservice/include -Ishared/include -x c++ service/src/collector_wire.cpp
```

Expected: no output (success).

- [ ] **Step 5: Commit**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
git add service/include/sentinel/collector_wire.h service/src/collector_wire.cpp service/CMakeLists.txt
git commit -m "service: add collector wire format serializer (JSON, UUIDv7)"
```

---

### Task 14: collector_client — bounded queue and public interface

**Files:**
- Create: `service/include/sentinel/collector_client.h`
- Create: `service/src/collector_client.cpp`

This task creates the `CollectorClient` class with its queue, public
`enqueue` method, and stub worker thread. The actual HTTPS sender is added
in Task 15 — this task is about the queue shape and the lifecycle API.

- [ ] **Step 1: Create the header**

Create `service/include/sentinel/collector_client.h`:

```cpp
/*
 * sentinel/collector_client.h
 *
 * CollectorClient forwards detection events from the service to a central
 * collector over HTTPS. It runs on its own background thread so the
 * detection path is never blocked by network I/O.
 *
 * Design:
 *   - enqueue() is the single public entry point. Non-blocking, never
 *     throws. Drops oldest on overflow.
 *   - A background sender thread drains the queue and POSTs batches
 *     to the collector with exponential backoff on transient failures.
 *   - start() launches the thread. stop() signals shutdown and joins.
 *
 * Thread safety: all public methods are safe to call from any thread.
 */

#ifndef SENTINEL_COLLECTOR_CLIENT_H
#define SENTINEL_COLLECTOR_CLIENT_H

#include <sentinel/collector_config.h>
#include <sentinel/collector_wire.h>
#include <sentinel/service.h>

#include <condition_variable>
#include <deque>

namespace sentinel {

class CollectorClient {
public:
    struct Stats {
        uint64_t queue_depth        = 0;
        uint64_t events_enqueued    = 0;
        uint64_t events_sent        = 0;
        uint64_t dropped_events     = 0;
        uint64_t retries_total      = 0;
        uint64_t permanent_failures = 0;
    };

    CollectorClient();
    ~CollectorClient();

    CollectorClient(const CollectorClient&) = delete;
    CollectorClient& operator=(const CollectorClient&) = delete;

    /**
     * Start the background sender thread.
     *
     * @param config  Collector configuration. If config.enabled is false,
     *                start() is a no-op and enqueue() drops silently.
     * @param host    Host info attached to every event.
     * @param version Sentinel service version string.
     */
    void start(const CollectorConfig& config,
               const CollectorHostInfo& host,
               const std::string& version);

    /** Signal shutdown and join the background thread. Safe to call multiple times. */
    void stop();

    /**
     * Enqueue a detection event for forwarding. Non-blocking.
     * If the queue is full, the oldest event is dropped.
     * If the client is not started (config.enabled == false), drops silently.
     */
    void enqueue(const DetectionEvent& event);

    /** Copy of the current stats. Thread-safe. */
    Stats get_stats() const;

private:
    /* Background worker loop. Runs until stop_requested_ is true. */
    void worker_loop();

    /* Collect up to COLLECTOR_MAX_BATCH_SIZE events from the queue into out.
     * Returns true if at least one event was drained. */
    bool drain_batch(std::vector<DetectionEvent>& out);

    /* Wait until either the queue has >= COLLECTOR_BATCH_THRESHOLD events,
     * COLLECTOR_FLUSH_INTERVAL_MS has passed, or stop was requested. */
    void wait_for_work();

    /* Send a batch to the collector. Returns true on 202 Accepted. Added in Task 15. */
    bool send_batch(const std::vector<DetectionEvent>& events);

    /* --- state --- */
    CollectorConfig     config_;
    CollectorHostInfo   host_;
    std::string         version_;

    mutable std::mutex          mutex_;
    std::condition_variable     cv_;
    std::deque<DetectionEvent>  queue_;
    bool                        stop_requested_ = false;
    bool                        started_        = false;
    std::thread                 worker_;

    mutable std::mutex stats_mutex_;
    Stats              stats_;
};

} /* namespace sentinel */

#endif /* SENTINEL_COLLECTOR_CLIENT_H */
```

- [ ] **Step 2: Create the implementation stub (queue + lifecycle only)**

Create `service/src/collector_client.cpp`:

```cpp
/*
 * collector_client.cpp
 *
 * Queue, worker thread, and send pipeline for forwarding detections to
 * the central collector.
 *
 * Task 14: queue + lifecycle + drain logic.
 * Task 15 adds the actual HTTPS send via WinHTTP.
 * Task 16 adds the retry/backoff state machine.
 */

#include <sentinel/collector_client.h>

#include <cstdio>

namespace sentinel {

CollectorClient::CollectorClient() = default;

CollectorClient::~CollectorClient() {
    stop();
}

void CollectorClient::start(const CollectorConfig& config,
                             const CollectorHostInfo& host,
                             const std::string& version) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (started_) return;
    config_  = config;
    host_    = host;
    version_ = version;
    if (!config_.enabled) {
        std::fprintf(stderr, "collector_client: disabled by config\n");
        return;
    }
    started_        = true;
    stop_requested_ = false;
    worker_ = std::thread(&CollectorClient::worker_loop, this);
    std::fprintf(stderr, "collector_client: started, target=%s\n",
                 config_.url.c_str());
}

void CollectorClient::stop() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!started_) return;
        stop_requested_ = true;
    }
    cv_.notify_all();
    if (worker_.joinable()) worker_.join();
    std::lock_guard<std::mutex> lock(mutex_);
    started_ = false;
}

void CollectorClient::enqueue(const DetectionEvent& event) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!started_ || !config_.enabled) return;
        if (queue_.size() >= COLLECTOR_QUEUE_CAPACITY) {
            queue_.pop_front(); /* drop oldest */
            std::lock_guard<std::mutex> sl(stats_mutex_);
            stats_.dropped_events++;
        }
        queue_.push_back(event);
        std::lock_guard<std::mutex> sl(stats_mutex_);
        stats_.events_enqueued++;
        stats_.queue_depth = queue_.size();
    }
    cv_.notify_one();
}

CollectorClient::Stats CollectorClient::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

bool CollectorClient::drain_batch(std::vector<DetectionEvent>& out) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (queue_.empty()) return false;
    size_t take = queue_.size();
    if (take > COLLECTOR_MAX_BATCH_SIZE) take = COLLECTOR_MAX_BATCH_SIZE;
    out.reserve(take);
    for (size_t i = 0; i < take; ++i) {
        out.push_back(std::move(queue_.front()));
        queue_.pop_front();
    }
    {
        std::lock_guard<std::mutex> sl(stats_mutex_);
        stats_.queue_depth = queue_.size();
    }
    return true;
}

void CollectorClient::wait_for_work() {
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait_for(lock,
                 std::chrono::milliseconds(COLLECTOR_FLUSH_INTERVAL_MS),
                 [this] {
                     return stop_requested_ ||
                            queue_.size() >= COLLECTOR_BATCH_THRESHOLD;
                 });
}

void CollectorClient::worker_loop() {
    while (true) {
        wait_for_work();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stop_requested_ && queue_.empty()) break;
        }
        std::vector<DetectionEvent> batch;
        if (!drain_batch(batch) || batch.empty()) continue;
        if (send_batch(batch)) {
            std::lock_guard<std::mutex> sl(stats_mutex_);
            stats_.events_sent += batch.size();
        }
        /* On failure, Task 16 will re-enqueue or retry. For now the
         * batch is dropped — this is a STUB that Task 16 replaces. */
    }
}

/* Placeholder — Task 15 replaces this with a real WinHTTP POST. */
bool CollectorClient::send_batch(const std::vector<DetectionEvent>& events) {
    std::fprintf(stderr, "collector_client: stub send_batch, %zu events\n",
                 events.size());
    return true;
}

} /* namespace sentinel */
```

- [ ] **Step 3: macOS syntax check**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
clang -std=c++17 -fsyntax-only -Iservice/include -Ishared/include -x c++ service/src/collector_client.cpp
```

Expected: no output (success).

- [ ] **Step 4: Commit**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
git add service/include/sentinel/collector_client.h service/src/collector_client.cpp
git commit -m "service: add CollectorClient queue, lifecycle, and worker stub"
```

---

### Task 15: WinHTTP sender implementation

**Files:**
- Create: `service/include/sentinel/collector_http.h`
- Create: `service/src/collector_http_win.cpp`
- Modify: `service/src/collector_client.cpp` (delegate `send_batch` to new header)
- Modify: `service/CMakeLists.txt` (add the new source + link `winhttp`)

- [ ] **Step 1: Create the shared header**

Create `service/include/sentinel/collector_http.h`:

```cpp
/*
 * sentinel/collector_http.h
 *
 * Contract between collector_client.cpp and the platform-specific HTTP
 * sender (collector_http_win.cpp on Windows). Defining this in a shared
 * header avoids ODR problems and makes the contract explicit.
 */

#ifndef SENTINEL_COLLECTOR_HTTP_H
#define SENTINEL_COLLECTOR_HTTP_H

#include <string>

namespace sentinel {

/**
 * Result of a single POST attempt, classified so the caller can decide
 * whether to retry, drop, or fail closed.
 */
enum class SendResult {
    Accepted,        /* 2xx — drop the batch from the queue */
    RetryLater,      /* 5xx or transient network error — retain and retry */
    PermanentDrop,   /* 400, 401, 413 — drop without retry */
    CertError        /* TLS cert verification failed — fail closed */
};

/**
 * POST a JSON batch body to <url>/v1/events with the given bearer token.
 * @param http_status Out: HTTP response code (0 if no response was received).
 */
SendResult http_post_events(const std::string& url,
                             const std::string& api_key,
                             const std::string& batch_json,
                             int& http_status);

} /* namespace sentinel */

#endif /* SENTINEL_COLLECTOR_HTTP_H */
```

- [ ] **Step 2: Create the WinHTTP sender**

Create `service/src/collector_http_win.cpp`:

```cpp
/*
 * collector_http_win.cpp
 *
 * WinHTTP implementation of the collector POST.
 *
 * Compiles only on Windows (#ifdef _WIN32). On macOS, provides a stub
 * that returns false, so the file parses for static analysis.
 *
 * Strict TLS: WinHTTP is configured with WINHTTP_FLAG_SECURE and we do
 * NOT set WINHTTP_FLAG_IGNORE_* — certificate verification must succeed.
 * Cert-validation failures are reported as a distinct return code so the
 * caller can fail closed instead of retrying.
 */

#include <sentinel/collector_http.h>

namespace sentinel {

#ifdef _WIN32

#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

static std::wstring to_wstring(const std::string& s) {
    if (s.empty()) return std::wstring();
    int wlen = MultiByteToWideChar(CP_UTF8, 0, s.c_str(),
                                    static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(wlen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(),
                        static_cast<int>(s.size()), &w[0], wlen);
    return w;
}

SendResult http_post_events(const std::string& url,
                             const std::string& api_key,
                             const std::string& batch_json,
                             int& http_status) {
    http_status = 0;

    URL_COMPONENTS uc{};
    wchar_t host[256] = {};
    wchar_t path[1024] = {};
    uc.dwStructSize     = sizeof(uc);
    uc.lpszHostName     = host;
    uc.dwHostNameLength = ARRAYSIZE(host);
    uc.lpszUrlPath      = path;
    uc.dwUrlPathLength  = ARRAYSIZE(path);

    std::wstring wurl = to_wstring(url);
    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &uc)) {
        return SendResult::PermanentDrop; /* malformed URL — config bug */
    }
    bool secure = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    INTERNET_PORT port = uc.nPort ? uc.nPort : (secure ? 443 : 80);

    HINTERNET session = WinHttpOpen(L"SentinelCollectorClient/0.1",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return SendResult::RetryLater;

    HINTERNET connect = WinHttpConnect(session, host, port, 0);
    if (!connect) { WinHttpCloseHandle(session); return SendResult::RetryLater; }

    /* Build full path: /v1/events (append to uc.lpszUrlPath root). */
    std::wstring full_path = L"/v1/events";

    DWORD flags = secure ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connect, L"POST",
                                            full_path.c_str(),
                                            nullptr, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES,
                                            flags);
    if (!request) {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return SendResult::RetryLater;
    }

    std::wstring headers = L"Content-Type: application/json\r\n"
                           L"Authorization: Bearer " + to_wstring(api_key) + L"\r\n";

    BOOL sent = WinHttpSendRequest(request,
                                    headers.c_str(),
                                    (DWORD)-1, /* headers length auto */
                                    (LPVOID)batch_json.data(),
                                    (DWORD)batch_json.size(),
                                    (DWORD)batch_json.size(),
                                    0);

    SendResult result = SendResult::RetryLater;

    if (!sent) {
        DWORD err = GetLastError();
        /* Cert verification failures: fail closed. */
        if (err == ERROR_WINHTTP_SECURE_FAILURE) {
            result = SendResult::CertError;
        } else {
            result = SendResult::RetryLater;
        }
    } else if (!WinHttpReceiveResponse(request, nullptr)) {
        result = SendResult::RetryLater;
    } else {
        DWORD status = 0;
        DWORD len = sizeof(status);
        WinHttpQueryHeaders(request,
                             WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX,
                             &status, &len, WINHTTP_NO_HEADER_INDEX);
        http_status = static_cast<int>(status);

        if (status >= 200 && status < 300)      result = SendResult::Accepted;
        else if (status == 400 || status == 401 || status == 413)
                                                result = SendResult::PermanentDrop;
        else if (status >= 500 && status < 600) result = SendResult::RetryLater;
        else                                    result = SendResult::RetryLater;
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    return result;
}

#else /* !_WIN32 — stub for macOS static analysis */

SendResult http_post_events(const std::string& /*url*/,
                             const std::string& /*api_key*/,
                             const std::string& /*batch_json*/,
                             int& http_status) {
    http_status = 0;
    return SendResult::RetryLater;
}

#endif /* _WIN32 */

} /* namespace sentinel */
```

- [ ] **Step 3: Wire the real sender into `send_batch`**

In `service/src/collector_client.cpp`, first add this include near the top
of the file, alongside `#include <sentinel/collector_client.h>`:

```cpp
#include <sentinel/collector_http.h>
```

Then replace the existing `send_batch` function (the stub added in Task 14)
with the following:

Before (stub):

```cpp
/* Placeholder — Task 15 replaces this with a real WinHTTP POST. */
bool CollectorClient::send_batch(const std::vector<DetectionEvent>& events) {
    std::fprintf(stderr, "collector_client: stub send_batch, %zu events\n",
                 events.size());
    return true;
}
```

After (real):

```cpp
bool CollectorClient::send_batch(const std::vector<DetectionEvent>& events) {
    if (events.empty()) return true;

    /* Serialize each event, then wrap in a batch. */
    std::vector<std::string> jsons;
    jsons.reserve(events.size());
    for (const auto& e : events) {
        jsons.push_back(serialize_event_json(e, config_.client_id, host_, version_));
    }
    std::string body = serialize_batch(jsons);

    int http_status = 0;
    SendResult result = http_post_events(config_.url, config_.api_key, body, http_status);

    switch (result) {
        case SendResult::Accepted:
            return true;
        case SendResult::PermanentDrop:
            std::fprintf(stderr,
                "collector_client: permanent drop, status=%d, batch=%zu\n",
                http_status, events.size());
            {
                std::lock_guard<std::mutex> sl(stats_mutex_);
                stats_.permanent_failures++;
            }
            return true; /* "true" here means "do not retry" */
        case SendResult::CertError:
            std::fprintf(stderr,
                "collector_client: TLS cert verification failed, failing closed\n");
            {
                std::lock_guard<std::mutex> sl(stats_mutex_);
                stats_.permanent_failures++;
            }
            return true;
        case SendResult::RetryLater:
        default:
            std::fprintf(stderr,
                "collector_client: retry later, status=%d\n", http_status);
            return false; /* Task 16 will re-enqueue on false */
    }
}
```

- [ ] **Step 4: Update CMakeLists and link WinHTTP**

In `service/CMakeLists.txt`, update `SERVICE_SOURCES` to add
`src/collector_http_win.cpp`:

```cmake
set(SERVICE_SOURCES
    src/main.cpp
    src/driver_comm.cpp
    src/process_monitor.cpp
    src/signature_scanner.cpp
    src/module_integrity.cpp
    src/detection_engine.cpp
    src/api_server.cpp
    src/collector_wire.cpp
    src/collector_client.cpp
    src/collector_http_win.cpp
)
```

And add `winhttp` to the Windows link libraries:

```cmake
if(WIN32)
    target_link_libraries(sentinel_service PRIVATE
        ws2_32
        advapi32
        psapi
        bcrypt
        winhttp
    )
endif()
```

- [ ] **Step 5: macOS syntax check**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
clang -std=c++17 -fsyntax-only -Iservice/include -Ishared/include -x c++ service/src/collector_http_win.cpp
clang -std=c++17 -fsyntax-only -Iservice/include -Ishared/include -x c++ service/src/collector_client.cpp
```

Expected: both files parse cleanly (the `#else` stub path is used on macOS).

- [ ] **Step 6: Commit**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
git add service/include/sentinel/collector_http.h service/src/collector_http_win.cpp service/src/collector_client.cpp service/CMakeLists.txt
git commit -m "service: implement WinHTTP POST with strict TLS and result classification"
```

---

### Task 16: Retry and backoff state machine

**Files:**
- Modify: `service/src/collector_client.cpp` (retry logic in `worker_loop`)

- [ ] **Step 1: Update the worker loop to retry on failure**

In `service/src/collector_client.cpp`, replace the existing `worker_loop`
function with:

```cpp
void CollectorClient::worker_loop() {
    int backoff_ms = COLLECTOR_BACKOFF_INITIAL_MS;
    std::vector<DetectionEvent> pending; /* batch being retried */

    while (true) {
        if (pending.empty()) {
            wait_for_work();
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (stop_requested_ && queue_.empty()) break;
            }
            drain_batch(pending);
        }
        if (pending.empty()) continue;

        if (send_batch(pending)) {
            /* Success (or permanent drop — send_batch returned true). */
            {
                std::lock_guard<std::mutex> sl(stats_mutex_);
                stats_.events_sent += pending.size();
            }
            pending.clear();
            backoff_ms = COLLECTOR_BACKOFF_INITIAL_MS;
            continue;
        }

        /* Transient failure — retry with backoff. */
        {
            std::lock_guard<std::mutex> sl(stats_mutex_);
            stats_.retries_total++;
        }

        /* Check for shutdown during backoff. */
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait_for(lock, std::chrono::milliseconds(backoff_ms),
                     [this] { return stop_requested_; });
        if (stop_requested_) break;
        lock.unlock();

        backoff_ms *= 2;
        if (backoff_ms > COLLECTOR_BACKOFF_MAX_MS) {
            backoff_ms = COLLECTOR_BACKOFF_MAX_MS;
        }
    }
}
```

Note: on transient failure, `pending` is NOT drained back into the queue —
it stays in the worker thread's local `pending` vector and is retried
in-place. This is simpler than re-enqueuing and preserves batch order.

- [ ] **Step 2: macOS syntax check**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
clang -std=c++17 -fsyntax-only -Iservice/include -Ishared/include -x c++ service/src/collector_client.cpp
```

Expected: no output.

- [ ] **Step 3: Commit**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
git add service/src/collector_client.cpp
git commit -m "service: add retry/backoff state machine to collector sender"
```

---

### Task 17: API key loading from Windows credential store

**Files:**
- Create: `service/include/sentinel/credential_store.h`
- Create: `service/src/credential_store_win.cpp`
- Modify: `service/CMakeLists.txt` (add the new source)

- [ ] **Step 1: Create the header**

Create `service/include/sentinel/credential_store.h`:

```cpp
/*
 * sentinel/credential_store.h
 *
 * Thin wrapper around the Windows Credential Store (wincred.h) for
 * loading the collector API key. Keeps the secret off disk as much as
 * possible — on Windows, CredRead decrypts per-user blobs protected
 * by DPAPI.
 *
 * On non-Windows platforms (macOS editing environment), these functions
 * are stubs that return false. The service does not run outside Windows,
 * so this is only for static analysis.
 */

#ifndef SENTINEL_CREDENTIAL_STORE_H
#define SENTINEL_CREDENTIAL_STORE_H

#include <string>

namespace sentinel {

/**
 * Load an API key from the Windows credential store under the given target.
 *
 * @param target  Credential target name (e.g., "SentinelCollectorApiKey").
 * @param out_key Output: the retrieved key (UTF-8).
 * @return true on success. false if the credential does not exist or
 *         the platform does not support credential storage.
 */
bool load_credential(const std::string& target, std::string& out_key);

/**
 * Store an API key in the Windows credential store. Overwrites any
 * existing credential with the same target name.
 *
 * @return true on success.
 */
bool store_credential(const std::string& target, const std::string& key);

} /* namespace sentinel */

#endif /* SENTINEL_CREDENTIAL_STORE_H */
```

- [ ] **Step 2: Create the implementation**

Create `service/src/credential_store_win.cpp`:

```cpp
/*
 * credential_store_win.cpp
 *
 * Windows CredRead/CredWrite wrapper for the collector API key.
 */

#include <sentinel/credential_store.h>

#ifdef _WIN32
#include <windows.h>
#include <wincred.h>
#pragma comment(lib, "advapi32.lib")
#endif

namespace sentinel {

#ifdef _WIN32

static std::wstring utf8_to_wide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int wlen = MultiByteToWideChar(CP_UTF8, 0, s.c_str(),
                                    static_cast<int>(s.size()),
                                    nullptr, 0);
    std::wstring w(wlen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(),
                        static_cast<int>(s.size()), &w[0], wlen);
    return w;
}

bool load_credential(const std::string& target, std::string& out_key) {
    std::wstring wtarget = utf8_to_wide(target);
    PCREDENTIALW cred = nullptr;
    if (!CredReadW(wtarget.c_str(), CRED_TYPE_GENERIC, 0, &cred)) {
        return false;
    }
    out_key.assign(reinterpret_cast<const char*>(cred->CredentialBlob),
                   cred->CredentialBlobSize);
    CredFree(cred);
    return true;
}

bool store_credential(const std::string& target, const std::string& key) {
    std::wstring wtarget = utf8_to_wide(target);
    CREDENTIALW cred{};
    cred.Type              = CRED_TYPE_GENERIC;
    cred.TargetName        = const_cast<LPWSTR>(wtarget.c_str());
    cred.CredentialBlobSize= static_cast<DWORD>(key.size());
    cred.CredentialBlob    = reinterpret_cast<LPBYTE>(const_cast<char*>(key.data()));
    cred.Persist           = CRED_PERSIST_LOCAL_MACHINE;
    return CredWriteW(&cred, 0) != FALSE;
}

#else /* !_WIN32 — stub for macOS static analysis */

bool load_credential(const std::string& /*target*/, std::string& /*out_key*/) {
    return false;
}
bool store_credential(const std::string& /*target*/, const std::string& /*key*/) {
    return false;
}

#endif

} /* namespace sentinel */
```

- [ ] **Step 3: Add to build**

In `service/CMakeLists.txt`, add `src/credential_store_win.cpp` to
`SERVICE_SOURCES`:

```cmake
set(SERVICE_SOURCES
    src/main.cpp
    src/driver_comm.cpp
    src/process_monitor.cpp
    src/signature_scanner.cpp
    src/module_integrity.cpp
    src/detection_engine.cpp
    src/api_server.cpp
    src/collector_wire.cpp
    src/collector_client.cpp
    src/collector_http_win.cpp
    src/credential_store_win.cpp
)
```

- [ ] **Step 4: macOS syntax check**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
clang -std=c++17 -fsyntax-only -Iservice/include -Ishared/include -x c++ service/src/credential_store_win.cpp
```

Expected: no output.

- [ ] **Step 5: Commit**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
git add service/include/sentinel/credential_store.h service/src/credential_store_win.cpp service/CMakeLists.txt
git commit -m "service: add Windows credential store wrapper for collector API key"
```

---

## Phase 5 — Service integration

### Task 18: Wire CollectorClient into main.cpp

**Files:**
- Modify: `service/src/main.cpp`

The detection engine is untouched. The collector_client is attached by
wrapping the existing `AlertCallback` so it both does the current thing
and also calls `collector_client.enqueue(event)`.

- [ ] **Step 1: Read main.cpp to find the callback setup**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
grep -n "AlertCallback\|DetectionEngine\|--console\|argv" service/src/main.cpp | head -40
```

Study the output to find:
- Where `DetectionEngine` is constructed
- Where its alert callback is assigned via `start(config, callback)`
- Where command-line args are parsed
- Where service shutdown runs

These are the three edit points for this task and the next.

- [ ] **Step 2: Add includes and a file-level CollectorClient**

Near the top of `service/src/main.cpp`, after the existing includes, add:

```cpp
#include <sentinel/collector_client.h>
#include <sentinel/credential_store.h>
```

Near the file-level statics (or where the other module objects are
constructed), add a CollectorClient instance. Inside whatever namespace or
scope the other modules live in:

```cpp
static sentinel::CollectorClient g_collector_client;
```

If the existing main.cpp uses `std::unique_ptr` or constructs the other
modules on the stack inside `main`, follow the existing pattern instead.
The key is that `g_collector_client` outlives the detection engine.

- [ ] **Step 3: Build the CollectorConfig at startup**

Immediately before the detection engine is started, add:

```cpp
{
    /* Populate collector config from ServiceConfig + credential store.
     * For MVP, the URL and client_id are hardcoded defaults that the
     * operator can override via environment variables before we wire
     * them into the service config file in a later chunk. */
    sentinel::CollectorConfig cc;
    const char* url_env       = std::getenv("SENTINEL_COLLECTOR_URL");
    const char* client_id_env = std::getenv("SENTINEL_CLIENT_ID");
    cc.url       = url_env       ? url_env       : "";
    cc.client_id = client_id_env ? client_id_env : "";
    cc.enabled   = !cc.url.empty() && !cc.client_id.empty();

    if (cc.enabled) {
        if (!sentinel::load_credential(
                sentinel::COLLECTOR_CREDENTIAL_TARGET, cc.api_key)) {
            std::fprintf(stderr,
                "collector: credential not found in store (target=%s); "
                "forwarding disabled\n",
                sentinel::COLLECTOR_CREDENTIAL_TARGET);
            cc.enabled = false;
        }
    }

    sentinel::CollectorHostInfo host;
#ifdef _WIN32
    {
        char hostbuf[256] = {};
        DWORD n = sizeof(hostbuf);
        if (GetComputerNameA(hostbuf, &n)) host.hostname = hostbuf;
    }
    host.os_version = "Windows";
    host.arch       = "x64";
#else
    host.hostname   = "sentinel-dev";
    host.os_version = "Windows (stubbed)";
    host.arch       = "x64";
#endif

    g_collector_client.start(cc, host, "0.3.1");
}
```

- [ ] **Step 4: Wrap the existing alert callback**

Find the line that calls `detection_engine.start(config, callback);` (or
similar). The existing callback is whatever the file currently passes.
Wrap it:

```cpp
auto original_callback = /* whatever the existing lambda/function is */;
auto wrapped_callback = [](const sentinel::DetectionEvent& event,
                           double score) {
    /* Existing behavior: log, file write, API server visibility. */
    original_callback(event, score);
    /* New behavior: forward to collector. Non-blocking. */
    g_collector_client.enqueue(event);
};
detection_engine.start(config, wrapped_callback);
```

**IMPORTANT:** The existing main.cpp may already have a lambda inline at
the call site. In that case, edit the existing lambda and add
`g_collector_client.enqueue(event);` as the last line of its body, rather
than introducing a wrapper. Keep the change minimal and local.

- [ ] **Step 5: Stop the collector on shutdown**

At service shutdown (wherever the other modules' `stop()` is called), add
before returning from main:

```cpp
g_collector_client.stop();
```

- [ ] **Step 6: macOS syntax check**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
clang -std=c++17 -fsyntax-only -Iservice/include -Ishared/include -x c++ service/src/main.cpp
```

Expected: no output.

- [ ] **Step 7: Commit**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
git add service/src/main.cpp
git commit -m "service: wire CollectorClient into main and alert callback"
```

---

### Task 19: --inject-test-event flag

**Files:**
- Modify: `service/src/main.cpp`

- [ ] **Step 1: Add the flag parsing**

In `service/src/main.cpp`, find the existing command-line argument parsing
(search for `--console`). Add handling for `--inject-test-event` next to
it.

Near the top of `main()`, alongside existing flag checks:

```cpp
bool inject_test_event = false;
for (int i = 1; i < argc; ++i) {
    if (std::string(argv[i]) == "--inject-test-event") {
        inject_test_event = true;
    }
    /* ...existing flag handling... */
}
```

- [ ] **Step 2: Inject the event after the engine and collector start**

After both `detection_engine.start(...)` AND `g_collector_client.start(...)`
have been called (both are needed — the collector must be running to receive
the enqueue), add:

```cpp
if (inject_test_event) {
    sentinel::DetectionEvent synthetic{};
    synthetic.source      = sentinel::AlertSource::DMA_DETECT;
    synthetic.severity    = SENTINEL_SEVERITY_HIGH;
    synthetic.description = "Synthetic DMA_ANOMALY injected via --inject-test-event";
    synthetic.process_id  = 0;
    synthetic.confidence  = 0.90;
    synthetic.timestamp   = std::chrono::system_clock::now();

    detection_engine.submit_event(synthetic);
    std::fprintf(stderr,
        "main: injected synthetic DMA_ANOMALY event at startup\n");
}
```

This uses `submit_event` so the synthetic event flows through the real
detection engine path (scoring, callback), which in turn calls the wrapped
callback from Task 18, which calls `g_collector_client.enqueue(...)`. This
exercises the whole chain end-to-end.

- [ ] **Step 3: macOS syntax check**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
clang -std=c++17 -fsyntax-only -Iservice/include -Ishared/include -x c++ service/src/main.cpp
```

Expected: no output.

- [ ] **Step 4: Commit**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
git add service/src/main.cpp
git commit -m "service: add --inject-test-event flag for smoke testing"
```

---

## Phase 6 — Windows VM build + C++ unit tests

### Task 20: Build and smoke-test the service in the Windows VM

This is the first time the C++ code from Phases 4–5 actually compiles. Batch
all previous changes into one VM roundtrip.

- [ ] **Step 1: Configure and build in the Windows VM**

Inside the Windows VM, open a Developer Command Prompt and run:

```bash
cd C:\path\to\sentinel
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release --target sentinel_service
```

Expected: `sentinel_service.exe` in `build\bin\Release\`.

If build errors appear, the most likely culprits are:
- `collector_http_win.cpp` — may need `#include <winhttp.h>` BEFORE `<windows.h>` on some WDK configurations
- `credential_store_win.cpp` — may need `#include <wincred.h>` explicit
- Link error for `winhttp` or `advapi32` — verify CMakeLists link lines from Tasks 15 and 17
- Missing header: ensure `service/include/sentinel/` is in the include path (it already is)

Fix compile errors iteratively until the target builds clean.

- [ ] **Step 2: Store a dev API key in the credential store**

In the VM, PowerShell (admin):

```powershell
cmdkey /generic:SentinelCollectorApiKey /user:sentinel /pass:<paste-the-key-from-task-10>
```

Use the exact 64-char key the collector's `admin add-client` printed.

- [ ] **Step 3: Run the service with environment variables and the inject flag**

With the collector still NOT running:

```cmd
set SENTINEL_COLLECTOR_URL=https://host.docker.internal:18443
set SENTINEL_CLIENT_ID=trading-desk-01
build\bin\Release\sentinel_service.exe --console --inject-test-event
```

Expected behavior (collector down, so transient failure + backoff):

- Stderr shows `collector_client: started, target=https://...`
- Stderr shows `main: injected synthetic DMA_ANOMALY event at startup`
- Stderr shows `collector_client: retry later, status=0` then the backoff grows

Stop with Ctrl+C. Expected: clean shutdown, `collector_client` thread joins.

This proves the C++ side builds and runs but does NOT prove the round-trip
works — that's Task 22 (end-to-end smoke test).

- [ ] **Step 4: Commit any compile fixes from Step 1**

If you needed to adjust any source files to get the Windows build working:

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
git add <whatever changed>
git commit -m "service: fixes to build collector pieces under MSVC"
```

If no fixes were needed, skip this commit.

---

### Task 21: C++ unit tests with GoogleTest

**Files:**
- Modify: `service/CMakeLists.txt` (add optional test target)
- Create: `service/test/CMakeLists.txt`
- Create: `service/test/test_collector_queue.cpp`
- Create: `service/test/test_collector_wire.cpp`

- [ ] **Step 1: Add a test target to the service CMake**

At the bottom of `service/CMakeLists.txt`, add:

```cmake
# --- Unit tests (optional) ---
option(SENTINEL_SERVICE_TESTS "Build service unit tests" OFF)
if(SENTINEL_SERVICE_TESTS)
    add_subdirectory(test)
endif()
```

- [ ] **Step 2: Create the test subproject CMakeLists**

Create `service/test/CMakeLists.txt`:

```cmake
# service/test/CMakeLists.txt
#
# GoogleTest-based unit tests for the service. Fetches GoogleTest at
# configure time so no system-wide install is required. Only the parts
# of the service that are meaningfully testable in isolation are built
# here — specifically the collector queue and wire format serializer.

cmake_minimum_required(VERSION 3.20)

include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
)
FetchContent_MakeAvailable(googletest)

add_executable(sentinel_service_tests
    test_collector_queue.cpp
    test_collector_wire.cpp
    # Include the translation units under test directly. This avoids
    # needing to produce a static library from the service.
    ${CMAKE_SOURCE_DIR}/service/src/collector_client.cpp
    ${CMAKE_SOURCE_DIR}/service/src/collector_wire.cpp
)

target_include_directories(sentinel_service_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/service/include
    ${CMAKE_SOURCE_DIR}/shared/include
)

target_link_libraries(sentinel_service_tests PRIVATE
    GTest::gtest_main
)

if(WIN32)
    # Stub — tests don't actually POST, but collector_client.cpp references
    # the http_post_events forward declaration which is defined in
    # collector_http_win.cpp. Provide a fake implementation in the test
    # binary instead of pulling in winhttp.
    target_compile_definitions(sentinel_service_tests PRIVATE
        SENTINEL_TEST_FAKE_HTTP=1
    )
endif()

include(GoogleTest)
gtest_discover_tests(sentinel_service_tests)
```

- [ ] **Step 3: Write queue tests with a fake sender**

Create `service/test/test_collector_queue.cpp`:

```cpp
/*
 * Unit tests for CollectorClient queue behavior.
 *
 * We link directly against collector_client.cpp and provide a fake
 * http_post_events below so tests don't touch the network. The fake
 * uses the real SendResult enum from <sentinel/collector_http.h>.
 */

#include <sentinel/collector_http.h>

// Fake http_post_events for unit tests. Tests set g_fake_result to control
// what the next POST attempt returns.
namespace sentinel {
static SendResult g_fake_result = SendResult::Accepted;
SendResult http_post_events(const std::string&, const std::string&,
                             const std::string&, int& http_status) {
    http_status = (g_fake_result == SendResult::Accepted)      ? 202 :
                  (g_fake_result == SendResult::PermanentDrop) ? 400 :
                  (g_fake_result == SendResult::CertError)     ? 0   : 503;
    return g_fake_result;
}
} // namespace sentinel

#include <gtest/gtest.h>
#include <sentinel/collector_client.h>

using namespace sentinel;

static DetectionEvent make_event(int id) {
    DetectionEvent e{};
    e.source      = AlertSource::DMA_DETECT;
    e.severity    = SENTINEL_SEVERITY_HIGH;
    e.description = "test-" + std::to_string(id);
    e.process_id  = static_cast<uint32_t>(id);
    e.confidence  = 0.8;
    e.timestamp   = std::chrono::system_clock::now();
    return e;
}

static CollectorConfig make_config() {
    CollectorConfig c;
    c.enabled   = true;
    c.url       = "https://localhost:1";
    c.client_id = "test";
    c.api_key   = "k";
    return c;
}

TEST(CollectorQueue, DisabledEnqueueIsNoOp) {
    CollectorClient cc;
    CollectorConfig disabled = make_config();
    disabled.enabled = false;
    cc.start(disabled, {"h","o","x64"}, "test");
    cc.enqueue(make_event(1));
    auto s = cc.get_stats();
    EXPECT_EQ(s.events_enqueued, 0u);
    cc.stop();
}

TEST(CollectorQueue, EnqueueIncrementsCounter) {
    g_fake_result = SendResult::Accepted;
    CollectorClient cc;
    cc.start(make_config(), {"h","o","x64"}, "test");
    for (int i = 0; i < 5; ++i) cc.enqueue(make_event(i));

    /* Give the worker a moment to drain. */
    for (int i = 0; i < 50; ++i) {
        if (cc.get_stats().events_sent >= 5) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    auto s = cc.get_stats();
    EXPECT_GE(s.events_enqueued, 5u);
    EXPECT_EQ(s.dropped_events, 0u);
    cc.stop();
}

TEST(CollectorQueue, OverflowDropsOldest) {
    g_fake_result = SendResult::RetryLater; /* keep queue full */
    CollectorClient cc;
    cc.start(make_config(), {"h","o","x64"}, "test");

    /* Fill beyond capacity. */
    for (std::size_t i = 0; i < COLLECTOR_QUEUE_CAPACITY + 50; ++i) {
        cc.enqueue(make_event(static_cast<int>(i)));
    }
    auto s = cc.get_stats();
    EXPECT_GE(s.dropped_events, 50u);
    cc.stop();
}

TEST(CollectorQueue, PermanentDropIncrementsPermanentFailures) {
    g_fake_result = SendResult::PermanentDrop;
    CollectorClient cc;
    cc.start(make_config(), {"h","o","x64"}, "test");
    cc.enqueue(make_event(1));

    for (int i = 0; i < 50; ++i) {
        if (cc.get_stats().permanent_failures > 0) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    auto s = cc.get_stats();
    EXPECT_GE(s.permanent_failures, 1u);
    cc.stop();
}
```

- [ ] **Step 4: Write wire format tests**

Create `service/test/test_collector_wire.cpp`:

```cpp
/*
 * Unit tests for the wire format serializer.
 */

#include <gtest/gtest.h>
#include <sentinel/collector_wire.h>

using namespace sentinel;

static DetectionEvent sample_event() {
    DetectionEvent e{};
    e.source      = AlertSource::DMA_DETECT;
    e.severity    = SENTINEL_SEVERITY_HIGH;
    e.description = "Unknown PCIe device";
    e.process_id  = 1234;
    e.confidence  = 0.87;
    e.timestamp   = std::chrono::system_clock::from_time_t(1712931807); /* 2024-04-12 */
    return e;
}

TEST(Wire, UUIDv7Shape) {
    std::string id = generate_uuidv7();
    ASSERT_EQ(id.size(), 36u);
    EXPECT_EQ(id[8],  '-');
    EXPECT_EQ(id[13], '-');
    EXPECT_EQ(id[14], '7'); /* version nibble */
    EXPECT_EQ(id[18], '-');
    EXPECT_EQ(id[23], '-');
}

TEST(Wire, UUIDv7Unique) {
    auto a = generate_uuidv7();
    auto b = generate_uuidv7();
    EXPECT_NE(a, b);
}

TEST(Wire, SerializeEventContainsExpectedFields) {
    std::string j = serialize_event_json(
        sample_event(), "acme-07", {"h","Win11","x64"}, "0.3.1");

    EXPECT_NE(j.find("\"schema_version\":1"), std::string::npos);
    EXPECT_NE(j.find("\"client_id\":\"acme-07\""), std::string::npos);
    EXPECT_NE(j.find("\"sentinel_version\":\"0.3.1\""), std::string::npos);
    EXPECT_NE(j.find("\"source\":\"driver\""), std::string::npos);
    EXPECT_NE(j.find("\"detection_type\":\"DMA_ANOMALY\""), std::string::npos);
    EXPECT_NE(j.find("\"severity\":\"high\""), std::string::npos);
    EXPECT_NE(j.find("\"confidence\":87"), std::string::npos);
    EXPECT_NE(j.find("\"summary\":\"Unknown PCIe device\""), std::string::npos);
    EXPECT_NE(j.find("\"hostname\":\"h\""), std::string::npos);
}

TEST(Wire, SerializeEscapesQuotes) {
    DetectionEvent e = sample_event();
    e.description = R"(evil"injection\n)";
    std::string j = serialize_event_json(e, "c", {"h","o","x64"}, "1");
    EXPECT_NE(j.find("evil\\\"injection\\\\n"), std::string::npos);
}

TEST(Wire, SerializeBatchWrapsEvents) {
    std::vector<std::string> events = {
        R"({"schema_version":1,"a":1})",
        R"({"schema_version":1,"b":2})"
    };
    std::string batch = serialize_batch(events);
    EXPECT_EQ(batch,
        R"({"events":[{"schema_version":1,"a":1},{"schema_version":1,"b":2}]})");
}
```

- [ ] **Step 5: Build and run the tests in the VM**

In the Windows VM:

```cmd
cd C:\path\to\sentinel
cmake -B build -G "Visual Studio 17 2022" -A x64 -DSENTINEL_SERVICE_TESTS=ON
cmake --build build --config Release --target sentinel_service_tests
ctest --test-dir build --output-on-failure -C Release
```

Expected: all tests PASS. If GoogleTest fetch fails due to corporate
network, run `git clone https://github.com/google/googletest.git`
manually and point `FetchContent_Declare` at the local path.

- [ ] **Step 6: Commit**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
git add service/test/ service/CMakeLists.txt
git commit -m "service: add GoogleTest unit tests for collector queue and wire format"
```

---

## Phase 7 — End-to-end smoke test

### Task 22: Manual end-to-end smoke test

This is the test that proves the whole chain works. No code; it's a runbook.

- [ ] **Step 1: Generate a client key and start the collector on macOS**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel/collector

# Initial config
cat > /tmp/collector-smoke.toml <<'EOF'
[server]
listen = "0.0.0.0:18443"

[storage]
sqlite_path = "/tmp/collector-smoke.db"

[clients]
EOF

./collector admin add-client smoke-vm-01 --config /tmp/collector-smoke.toml
```

Copy the printed 64-hex API key. You'll need it for the VM.

Start the collector:

```bash
./collector serve --config /tmp/collector-smoke.toml
```

Expected: listening on `0.0.0.0:18443` with plaintext (no TLS for the
smoke test — this is the one acceptable place to skip TLS because the
traffic is already on a host-only network).

- [ ] **Step 2: Verify from macOS the collector is reachable**

In another terminal:

```bash
curl -s http://127.0.0.1:18443/v1/healthz
```

Expected: `{"status":"ok","version":"0.1.0"}`

- [ ] **Step 3: Store the API key in the VM's credential store**

In the Windows VM, PowerShell (admin):

```powershell
cmdkey /generic:SentinelCollectorApiKey /user:sentinel /pass:<paste-64-hex-key-from-step-1>
```

- [ ] **Step 4: Run the service in the VM with inject flag**

Find the macOS host IP as seen from the VM (this depends on your VM
configuration — VMware "NAT" commonly exposes the host at `192.168.x.1`,
VirtualBox `10.0.2.2`, Parallels `10.211.55.2`, Hyper-V varies). From the
VM, verify:

```cmd
curl http://<HOST-IP>:18443/v1/healthz
```

Expected: the same healthz JSON. If this fails, fix networking before
continuing — the C++ side will also fail.

Then run the service:

```cmd
cd C:\path\to\sentinel
set SENTINEL_COLLECTOR_URL=http://<HOST-IP>:18443
set SENTINEL_CLIENT_ID=smoke-vm-01
build\bin\Release\sentinel_service.exe --console --inject-test-event
```

(Use `http://` not `https://` for the smoke test because we skipped TLS
in Step 1. In a real pilot you would use `https://` with a real cert.)

Expected in stderr:
- `collector_client: started, target=http://<HOST-IP>:18443`
- `main: injected synthetic DMA_ANOMALY event at startup`
- After a few seconds: something like `ingest: accepted` in the collector's
  stdout on macOS, and no retries in the service's stderr.

Let it run for 10 seconds then Ctrl+C to stop.

- [ ] **Step 5: Verify the event landed in the collector DB**

On macOS:

```bash
curl -s -H "Authorization: Bearer <same-64-hex-key>" \
  http://127.0.0.1:18443/v1/events | python3 -m json.tool
```

Expected: one event with `detection_type: "DMA_ANOMALY"`, `client_id:
"smoke-vm-01"`, `severity: "high"`, `summary: "Synthetic DMA_ANOMALY
injected via --inject-test-event"`.

- [ ] **Step 6: Verify idempotency (re-run)**

Stop the service with Ctrl+C. Re-run with the same command. Inject fires
again but with a fresh UUIDv7, so the collector sees two distinct events.

```bash
curl -s -H "Authorization: Bearer <key>" \
  http://127.0.0.1:18443/v1/events | python3 -c "import sys,json;print(len(json.load(sys.stdin)['events']))"
```

Expected: `2` (each run produced one new event). If you see `1`, check
that UUIDv7 generation is not stuck at a constant.

- [ ] **Step 7: Commit the smoke test runbook to `docs/`**

Create `docs/smoke-test-collector.md` containing the above steps 1–6 as a
human-readable runbook. This is not a source change — it's documentation
for future runs.

```markdown
# Collector smoke test runbook

...paste the steps from this task as a standalone doc...
```

Then:

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel
git add docs/smoke-test-collector.md
git commit -m "docs: add collector smoke test runbook"
```

---

## Phase 8 — Wrap up

### Task 23: Verify all done criteria from the spec

Walk through section 6 of `docs/superpowers/specs/2026-04-12-detection-collector-design.md` and verify each item:

- [ ] `collector` binary exists at `collector/cmd/collector/` and builds with `go build ./...` on macOS
- [ ] `collector admin add-client <name>` creates an API key and persists it
- [ ] Collector serves `/v1/events` (POST+GET), `/v1/events/{id}` (GET), `/v1/healthz` (GET)
- [ ] All Layer 1 and Layer 2 tests pass (run `go test ./...` in collector dir)
- [ ] Sentinel service has a new `collector_client` module, enabled via config, that forwards detections asynchronously
- [ ] Service has `--inject-test-event` flag
- [ ] Layer 4 smoke test passes manually (Task 22)
- [ ] Existing localhost dashboard still works (start it via `cd dashboard && npm run dev` and confirm nothing regressed)
- [ ] Both sides emit the structured log fields from spec §4.6

For any item that fails, open a fresh task, fix it, and re-run the check.

- [ ] **Step 1: Run the full Go test suite**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel/collector
go test ./...
```

Expected: all PASS, no SKIP, no FAIL.

- [ ] **Step 2: Check dashboard is unaffected**

```bash
cd /Users/arjunmyanger/Documents/Dev/sentinel/dashboard
npm run dev
```

Expected: dashboard serves on `http://localhost:3000` and renders without errors (mock data is fine; the service does not need to be running).

Stop with Ctrl+C.

- [ ] **Step 3: Final commit if any lingering fixups**

If the verification surfaced small fixes, commit them with descriptive messages. Otherwise this task is just a checkbox walk.

---

## Notes for future chunks

After this plan is done, the next most valuable chunks (each its own spec
and plan) are:

1. **Operator console rework** — the localhost dashboard reads from the collector instead of from the local service.
2. **Evidence bundles** — attach signed artifacts (process snapshots, driver telemetry) to detections.
3. **Self-protection pass** — driver anti-unload, service watchdog, Sentinel binary integrity.
4. **DMA detection depth** — the "escape valve" motivation chunk that makes the product genuinely differentiated.
5. **Installer and signing path** — MSI, test-signing, EV cert.

This plan is designed so each of those builds on the collector as the source of truth without further architectural rework.
