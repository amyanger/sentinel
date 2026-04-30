// Package httpapi holds HTTP middleware shared across the collector's routes.
package httpapi

import "net/http"

// WithCORS returns a handler that adds CORS headers for requests whose Origin
// is in allowedOrigins, and short-circuits OPTIONS preflight with 204.
// Non-CORS requests (no Origin header) and disallowed origins pass through to
// inner unchanged — the browser then enforces the missing-header policy.
func WithCORS(allowedOrigins []string, inner http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		allowed[o] = struct{}{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			if _, ok := allowed[origin]; ok {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				w.Header().Set("Access-Control-Max-Age", "600")
			}
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		inner.ServeHTTP(w, r)
	})
}
