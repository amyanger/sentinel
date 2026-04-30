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
)

// Handler serves both list and get-by-id routes. It inspects the URL path to
// decide which operation to run. Routing is kept in main.go; this handler
// takes everything under "/v1/events".
type Handler struct {
	store store.Store
	keys  *auth.AdminStore
}

func New(s store.Store, ks *auth.AdminStore) *Handler {
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
	if e.Context == nil {
		e.Context = map[string]any{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(e)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
