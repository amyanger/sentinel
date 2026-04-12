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

//go:embed 0001_init.sql
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
