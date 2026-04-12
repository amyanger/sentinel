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
