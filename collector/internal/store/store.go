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
