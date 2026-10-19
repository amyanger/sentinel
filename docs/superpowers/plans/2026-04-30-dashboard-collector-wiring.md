# Dashboard ↔ Collector Wiring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a fleet-wide "Collector" view to the dashboard that reads detection events from the collector, gated by a new admin API key class distinct from the existing client (ingest) keys.

**Architecture:** The collector currently uses a single `KeyStore` for both POST `/v1/events` (ingest) and GET `/v1/events[/{id}]` (query). We split these — clients keep ingest auth, a new `AdminStore` gates GET endpoints. Admin keys live in the TOML config under `[admins]` parallel to `[clients]`, registered via a new `admin add-admin <name>` subcommand. The dashboard gains a "Collector" view that talks to a configurable collector URL with a bearer key the operator pastes into a settings modal (key persisted in `localStorage`). CORS headers are added so a browser at `localhost:3000` can hit the collector.

**Tech Stack:** Go 1.22 (collector), `BurntSushi/toml`, `crypto/subtle`, vanilla HTML/CSS/JS (dashboard, no build step).

**XSS note:** The collector returns fields populated from user-controlled sources (hostname, summary, client_id). All dashboard rendering of collector data MUST use `textContent` / `createElement`, not `innerHTML` with interpolation. Task 9's code follows this rule strictly.

---

## File Structure

**Collector (Go):**
- Modify: `collector/internal/auth/keys.go` — add `AdminStore` type alongside `KeyStore`
- Create: `collector/internal/auth/admin_test.go` — unit tests for admin key store
- Modify: `collector/internal/config/config.go` — add `Admins map[string]string` field and `Server.AllowedOrigins []string`
- Modify: `collector/internal/config/config_test.go` — extend tests to cover `[admins]`
- Modify: `collector/internal/query/handler.go` — accept `*auth.AdminStore` instead of `*auth.KeyStore`
- Modify: `collector/internal/query/handler_test.go` — update tests to use admin store; add cross-class rejection test
- Create: `collector/internal/httpapi/cors.go` — small CORS middleware
- Create: `collector/internal/httpapi/cors_test.go` — middleware tests
- Modify: `collector/cmd/collector/serve.go` — load admin keys, wire admin store to query, wire CORS, route OPTIONS
- Create: `collector/cmd/collector/admin_admin.go` — `add-admin` subcommand
- Modify: `collector/cmd/collector/admin.go` — dispatch `add-admin` to new handler
- Create: `collector/cmd/collector/admin_admin_test.go` — unit test for the new subcommand
- Modify: `collector/e2e/e2e_test.go` — extend to cover GET requires admin key, POST with admin key rejected, GET with client key rejected
- Modify: `collector/testdata/config_valid.toml` — add an `[admins]` example

**Dashboard (HTML/CSS/JS, no build):**
- Modify: `dashboard/index.html` — add a `Collector` nav item, a `view-collector` container, and a settings modal template, script tag for `collector.js`
- Modify: `dashboard/css/style.css` — styles for the new view, settings modal, and event table
- Create: `dashboard/js/collector.js` — fetch wrapper for the collector
- Modify: `dashboard/js/app.js` — render the collector view, settings modal handlers, list refresh, detail drawer (XSS-safe)

**Docs:**
- Modify: `docs/smoke-test-collector.md` — addendum: register an admin key and load the dashboard against the smoke collector
- Create: `dashboard/README.md` — short note on configuring the dashboard against a collector

---

## Task 1: Collector — extend `Config` with `[admins]`

**Files:**
- Modify: `collector/internal/config/config.go`
- Modify: `collector/internal/config/config_test.go`
- Modify: `collector/testdata/config_valid.toml`

- [ ] **Step 1: Write the failing test**

Add to `collector/internal/config/config_test.go` (new tests, do not delete existing):

```go
func TestLoad_ParsesAdmins(t *testing.T) {
	cfg, err := Load("../../testdata/config_valid.toml")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if got, ok := cfg.Admins["dashboard-dev"]; !ok || got == "" {
		t.Fatalf("expected admin 'dashboard-dev' present with non-empty key, got %q (ok=%v)", got, ok)
	}
}

func TestLoad_AdminsDefaultsToEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "no-admins.toml")
	body := `
[server]
listen = "127.0.0.1:0"

[storage]
sqlite_path = "/tmp/x.db"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Admins == nil {
		t.Fatal("expected Admins to be a non-nil empty map after Load")
	}
	if len(cfg.Admins) != 0 {
		t.Fatalf("expected empty Admins, got %d entries", len(cfg.Admins))
	}
}
```

If `os` and `path/filepath` aren't already imported in this test file, add them.

- [ ] **Step 2: Run test to verify it fails**

```bash
cd ~/Documents/Dev/sentinel/collector
go test ./internal/config/ -run TestLoad_ParsesAdmins -v
```

Expected: FAIL — either `cfg.Admins` is undefined (compile error) or the field doesn't exist.

- [ ] **Step 3: Add `Admins` field, `AllowedOrigins`, and update fixture**

Modify `collector/internal/config/config.go`:

```go
// Config is the top-level collector configuration.
type Config struct {
	Server struct {
		Listen         string   `toml:"listen"`
		TLSCert        string   `toml:"tls_cert"`
		TLSKey         string   `toml:"tls_key"`
		AllowedOrigins []string `toml:"allowed_origins"`
	} `toml:"server"`

	Storage struct {
		SQLitePath string `toml:"sqlite_path"`
	} `toml:"storage"`

	// Clients maps client_name -> api_key. Authenticates POST /v1/events (ingest).
	Clients map[string]string `toml:"clients"`

	// Admins maps admin_name -> api_key. Authenticates GET /v1/events[/{id}] (query).
	// Admin keys grant fleet-wide read access; treat them more carefully than client keys.
	Admins map[string]string `toml:"admins"`
}
```

In `Load`, after the existing `Clients` nil-init, add:

```go
	if cfg.Admins == nil {
		cfg.Admins = make(map[string]string)
	}
```

Append to `collector/testdata/config_valid.toml`:

```toml

[admins]
dashboard-dev = "0000000000000000000000000000000000000000000000000000000000000001"
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/config/ -v
```

Expected: PASS for all `TestLoad_*` cases. Existing tests must still pass.

- [ ] **Step 5: Commit**

```bash
git add collector/internal/config/config.go collector/internal/config/config_test.go collector/testdata/config_valid.toml
git commit -m "collector: add [admins] section and CORS origins to config"
```

---

## Task 2: Collector — add `AdminStore` type

**Decision:** A new `AdminStore` type duplicates ~10 lines of `KeyStore`. Accepted because the type-level distinction prevents accidentally passing the wrong store to a handler — a single shared type with a string discriminator would lose that protection. If a third key class ever appears, factor.

**Files:**
- Modify: `collector/internal/auth/keys.go`
- Create: `collector/internal/auth/admin_test.go`

- [ ] **Step 1: Write the failing test**

Create `collector/internal/auth/admin_test.go`:

```go
package auth

import "testing"

func TestAdminStore_AddAndVerify(t *testing.T) {
	as := NewAdminStore()
	as.Add("ops-laptop", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	name, ok := as.Verify("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if !ok {
		t.Fatal("expected Verify to succeed for registered admin key")
	}
	if name != "ops-laptop" {
		t.Fatalf("expected admin name 'ops-laptop', got %q", name)
	}
}

func TestAdminStore_VerifyRejectsUnknown(t *testing.T) {
	as := NewAdminStore()
	as.Add("ops-laptop", "aaaa")
	if _, ok := as.Verify("bbbb"); ok {
		t.Fatal("expected Verify to reject unknown key")
	}
}

func TestAdminStore_VerifyRejectsEmpty(t *testing.T) {
	as := NewAdminStore()
	if _, ok := as.Verify(""); ok {
		t.Fatal("expected Verify to reject empty key")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/auth/ -run TestAdminStore -v
```

Expected: FAIL — `AdminStore` undefined.

- [ ] **Step 3: Add `AdminStore` to `keys.go`**

Append to `collector/internal/auth/keys.go`:

```go
// AdminStore maps admin names to their API keys. Thread-safe.
// Admin keys grant fleet-wide read access on /v1/events[/{id}] and are
// distinct from client keys to prevent accidental privilege escalation
// from a leaked endpoint credential.
type AdminStore struct {
	mu   sync.RWMutex
	keys map[string]string // key -> admin name
}

func NewAdminStore() *AdminStore {
	return &AdminStore{keys: make(map[string]string)}
}

// Add registers an API key for an admin name.
func (as *AdminStore) Add(adminName, apiKey string) {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.keys[apiKey] = adminName
}

// Verify checks whether apiKey matches any registered admin key.
// Returns the associated admin name and true on success.
func (as *AdminStore) Verify(apiKey string) (string, bool) {
	if apiKey == "" {
		return "", false
	}
	as.mu.RLock()
	defer as.mu.RUnlock()
	for storedKey, name := range as.keys {
		if subtle.ConstantTimeCompare([]byte(storedKey), []byte(apiKey)) == 1 {
			return name, true
		}
	}
	return "", false
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/auth/ -v
```

Expected: PASS for all `TestAdminStore_*` cases. Existing `TestKeyStore_*` tests must still pass.

- [ ] **Step 5: Commit**

```bash
git add collector/internal/auth/keys.go collector/internal/auth/admin_test.go
git commit -m "collector: add AdminStore type for fleet-read auth"
```

---

## Task 3: Collector — switch query handler to admin auth

**Files:**
- Modify: `collector/internal/query/handler.go`
- Modify: `collector/internal/query/handler_test.go`

- [ ] **Step 1: Read existing query test setup**

Before changing the test, read `collector/internal/query/handler_test.go` end-to-end. Note the helper that constructs the store and the pattern for the existing successful-list and 401-on-bad-key tests. The new test below uses placeholders (`newTestStore`, etc.) — replace them with whatever the file actually uses.

- [ ] **Step 2: Update existing test for new constructor signature**

In `collector/internal/query/handler_test.go`, find every `auth.NewKeyStore()` and replace with `auth.NewAdminStore()`; every `*auth.KeyStore` field/parameter type with `*auth.AdminStore`. The `query.New(s, store)` call sites do not change shape — only the variable type does.

Add this new test at the end of the file (adapt helper names to whatever the file already uses):

```go
func TestQuery_RejectsClientKeyForGET(t *testing.T) {
	s := newTestStore(t) // use whatever helper exists in this file
	adminKS := auth.NewAdminStore()
	// Note: we deliberately register no admin; the request below presents what
	// would be a valid *client* key, which must NOT pass admin auth.

	h := query.New(s, adminKS)

	req := httptest.NewRequest(http.MethodGet, "/v1/events", nil)
	req.Header.Set("Authorization", "Bearer client-key-not-an-admin")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
go test ./internal/query/ -v
```

Expected: compile error (`query.New` still takes `*KeyStore`, you're passing `*AdminStore`).

- [ ] **Step 4: Update the query handler signature**

Modify `collector/internal/query/handler.go`:

```go
type Handler struct {
	store store.Store
	keys  *auth.AdminStore
}

func New(s store.Store, ks *auth.AdminStore) *Handler {
	return &Handler{store: s, keys: ks}
}
```

The bearer parse, path routing, list, and getByID logic do not change — `Verify` has the same signature on both stores.

- [ ] **Step 5: Run tests to verify they pass**

```bash
go test ./internal/query/ -v
```

Expected: PASS, including the new `TestQuery_RejectsClientKeyForGET`.

- [ ] **Step 6: Commit**

```bash
git add collector/internal/query/handler.go collector/internal/query/handler_test.go
git commit -m "collector: gate query handler with admin auth"
```

---

## Task 4: Collector — add CORS middleware

**Files:**
- Create: `collector/internal/httpapi/cors.go`
- Create: `collector/internal/httpapi/cors_test.go`

- [ ] **Step 1: Write the failing test**

Create `collector/internal/httpapi/cors_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/httpapi/ -v
```

Expected: FAIL — `WithCORS` undefined.

- [ ] **Step 3: Implement `WithCORS`**

Create `collector/internal/httpapi/cors.go`:

```go
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/httpapi/ -v
```

Expected: PASS for all three tests.

- [ ] **Step 5: Commit**

```bash
git add collector/internal/httpapi/cors.go collector/internal/httpapi/cors_test.go
git commit -m "collector: add CORS middleware"
```

---

## Task 5: Collector — wire admin store and CORS into `serve`

**Files:**
- Modify: `collector/cmd/collector/serve.go`
- Modify: `collector/e2e/e2e_test.go`

- [ ] **Step 1: Read the existing e2e test helper**

Open `collector/e2e/e2e_test.go` and identify the helper that builds a running server (something like `startTestServer(t)`). Note: (a) the helper's exact name; (b) what TOML config or struct it builds; (c) what client key/name it registers; (d) how tests reach the server URL. The new test below references `startTestServer` — replace it with the actual name. If the helper builds the config in code, you'll add an admin entry inline; if it writes a TOML, add an `[admins]` section.

- [ ] **Step 2: Write the failing integration test**

Append to `collector/e2e/e2e_test.go`:

```go
func TestE2E_AuthClassesAreSeparate(t *testing.T) {
	srv, teardown := startTestServer(t) // adapt to actual helper name
	defer teardown()
	// Helper must register: client "smoke" with key "client-secret"
	// AND admin "ops" with key "admin-secret". Update helper in Step 4.

	// 1) GET with client key → 401
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/events", nil)
	req.Header.Set("Authorization", "Bearer client-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("client key on GET should 401, got %d", resp.StatusCode)
	}

	// 2) GET with admin key → 200
	req2, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/events", nil)
	req2.Header.Set("Authorization", "Bearer admin-secret")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("admin key on GET should 200, got %d", resp2.StatusCode)
	}

	// 3) POST with admin key → 401
	req3, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/events", bytes.NewReader([]byte("{}")))
	req3.Header.Set("Authorization", "Bearer admin-secret")
	req3.Header.Set("Content-Type", "application/json")
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusUnauthorized {
		t.Fatalf("admin key on POST should 401, got %d", resp3.StatusCode)
	}
}
```

If `bytes` isn't already imported in this file, add it.

- [ ] **Step 3: Run the test to verify it fails**

```bash
go test ./e2e/ -run TestE2E_AuthClassesAreSeparate -v
```

Expected: FAIL — helper doesn't register an admin yet, or GET succeeds with the client key.

- [ ] **Step 4: Update `serve.go` to load admin keys and wire CORS**

Modify `collector/cmd/collector/serve.go`. Add to imports:

```go
	"sentinel/collector/internal/httpapi"
```

After the existing client `KeyStore` block (around lines 50-54), add:

```go
	as := auth.NewAdminStore()
	for name, key := range cfg.Admins {
		as.Add(name, key)
	}
	slog.Info("admin keys loaded", "count", len(cfg.Admins))
```

Replace the existing handler registration:

```go
	mux.Handle("/v1/events", ingestOrQuery(s, ks, as))
	mux.Handle("/v1/events/", query.New(s, as))
	mux.HandleFunc("/v1/healthz", handleHealthz)
```

Update `ingestOrQuery`:

```go
func ingestOrQuery(s store.Store, ks *auth.KeyStore, as *auth.AdminStore) http.Handler {
	ingestH := ingest.New(s, ks)
	queryH := query.New(s, as)
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
```

Wrap the mux with CORS in the `Handler:` line of `&http.Server{...}`:

```go
	srv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           httpapi.WithCORS(cfg.Server.AllowedOrigins, mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
```

Update the e2e helper (`startTestServer` or equivalent) so it registers admin "ops" with key "admin-secret" alongside whatever client it already registers. Use the same mechanism the helper currently uses for clients.

- [ ] **Step 5: Run all tests**

```bash
go test ./... -v
```

Expected: PASS, including `TestE2E_AuthClassesAreSeparate` and the existing e2e suite.

- [ ] **Step 6: Commit**

```bash
git add collector/cmd/collector/serve.go collector/e2e/e2e_test.go
git commit -m "collector: wire admin store and CORS into serve"
```

---

## Task 6: Collector — `admin add-admin` subcommand

**Files:**
- Create: `collector/cmd/collector/admin_admin.go`
- Modify: `collector/cmd/collector/admin.go`
- Create: `collector/cmd/collector/admin_admin_test.go`

- [ ] **Step 1: Write the failing test**

Create `collector/cmd/collector/admin_admin_test.go`:

```go
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sentinel/collector/internal/config"
)

func TestRunAdminAddAdmin_WritesKeyToConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "c.toml")
	body := `
[server]
listen = "127.0.0.1:0"

[storage]
sqlite_path = "/tmp/x.db"
`
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := runAdminAddAdmin([]string{"dashboard-dev", "--config", cfgPath}); err != nil {
		t.Fatalf("runAdminAddAdmin: %v", err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := cfg.Admins["dashboard-dev"]
	if !ok {
		t.Fatal("expected admin 'dashboard-dev' to be registered")
	}
	if len(key) != 64 {
		t.Fatalf("expected 64-hex-char key, got %d chars: %q", len(key), key)
	}
	if !looksHex(key) {
		t.Fatalf("key should be hex, got %q", key)
	}
}

func TestRunAdminAddAdmin_RejectsDuplicate(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "c.toml")
	body := `
[server]
listen = "127.0.0.1:0"

[storage]
sqlite_path = "/tmp/x.db"

[admins]
ops = "deadbeef"
`
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runAdminAddAdmin([]string{"ops", "--config", cfgPath})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected duplicate error, got %v", err)
	}
}

func looksHex(s string) bool {
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
			// ok
		default:
			return false
		}
	}
	return true
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./cmd/collector/ -run TestRunAdminAddAdmin -v
```

Expected: FAIL — `runAdminAddAdmin` undefined.

- [ ] **Step 3: Implement `add-admin` and dispatch**

Create `collector/cmd/collector/admin_admin.go`:

```go
package main

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"sentinel/collector/internal/config"
)

func runAdminAddAdmin(args []string) error {
	// Same arg-shuffling as add-client so flag order is flexible.
	var positional []string
	var flagArgs []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			flagArgs = append(flagArgs, args[i])
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") &&
				!strings.Contains(args[i], "=") {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		} else {
			positional = append(positional, args[i])
		}
	}

	fs := flag.NewFlagSet("admin add-admin", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "path to collector TOML config")
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if len(positional) < 1 {
		return errors.New("admin name required")
	}
	adminName := positional[0]
	if strings.ContainsAny(adminName, " \t\n") {
		return errors.New("admin name cannot contain whitespace")
	}
	if *cfgPath == "" {
		return errors.New("--config is required")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if _, exists := cfg.Admins[adminName]; exists {
		return fmt.Errorf("admin %q already exists", adminName)
	}

	key, err := generateAPIKey() // existing helper from admin.go
	if err != nil {
		return err
	}
	if cfg.Admins == nil {
		cfg.Admins = make(map[string]string)
	}
	cfg.Admins[adminName] = key

	if err := writeConfig(*cfgPath, cfg); err != nil {
		return err
	}
	fmt.Println("admin added:", adminName)
	fmt.Println("api key:    ", key)
	fmt.Println("(store this key wherever the dashboard is configured; it cannot be recovered)")
	return nil
}
```

Modify `collector/cmd/collector/admin.go`. Replace `runAdmin`:

```go
func runAdmin(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: collector admin <add-client|add-admin> <name> --config <path>")
	}
	switch args[0] {
	case "add-client":
		return runAdminAddClient(args[1:])
	case "add-admin":
		return runAdminAddAdmin(args[1:])
	default:
		return fmt.Errorf("unknown admin subcommand %q", args[0])
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./cmd/collector/ -v
```

Expected: PASS for both new tests; existing `add-client` tests must still pass.

- [ ] **Step 5: Commit**

```bash
git add collector/cmd/collector/admin.go collector/cmd/collector/admin_admin.go collector/cmd/collector/admin_admin_test.go
git commit -m "collector: add admin add-admin subcommand"
```

---

## Task 7: Dashboard — collector API module

**Files:**
- Create: `dashboard/js/collector.js`

- [ ] **Step 1: Implement the module**

Mirrors the structure of `dashboard/js/api.js` (IIFE, exposed as a global) but talks to the collector with a configurable base URL and bearer token, both in `localStorage`.

Create `dashboard/js/collector.js`:

```js
/**
 * Sentinel Dashboard — Collector API module.
 *
 * Talks to the collector's read endpoints using a bearer token. Both base URL
 * and token are user-configurable and persisted in localStorage:
 *   sentinel.collector.url, sentinel.collector.key
 */

const Collector = (() => {
  const URL_KEY = 'sentinel.collector.url';
  const TOKEN_KEY = 'sentinel.collector.key';

  function getConfig() {
    return {
      url: localStorage.getItem(URL_KEY) || '',
      key: localStorage.getItem(TOKEN_KEY) || '',
    };
  }

  function setConfig({ url, key }) {
    if (typeof url === 'string') localStorage.setItem(URL_KEY, url.trim());
    if (typeof key === 'string') localStorage.setItem(TOKEN_KEY, key.trim());
  }

  function isConfigured() {
    const { url, key } = getConfig();
    return url !== '' && key !== '';
  }

  async function _fetch(path) {
    const { url, key } = getConfig();
    if (!url || !key) {
      throw new Error('Collector not configured. Open Settings to set URL and API key.');
    }
    const resp = await fetch(`${url}${path}`, {
      headers: {
        'Authorization': `Bearer ${key}`,
        'Accept': 'application/json',
      },
    });
    if (resp.status === 401) {
      throw new Error('Unauthorized — admin API key is invalid.');
    }
    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
    }
    return await resp.json();
  }

  async function listEvents(limit = 50) {
    return _fetch(`/v1/events?limit=${encodeURIComponent(limit)}`);
  }

  async function getEvent(id) {
    return _fetch(`/v1/events/${encodeURIComponent(id)}`);
  }

  async function ping() {
    // /v1/healthz is unauthenticated, so use it to test connectivity
    // without burning the configured admin key.
    const { url } = getConfig();
    if (!url) throw new Error('Collector URL not set.');
    const resp = await fetch(`${url}/v1/healthz`);
    if (!resp.ok) throw new Error(`Collector unreachable (HTTP ${resp.status}).`);
    return await resp.json();
  }

  return { getConfig, setConfig, isConfigured, listEvents, getEvent, ping };
})();
```

- [ ] **Step 2: Manually verify the module loads**

Add a temporary `<script src="js/collector.js"></script>` line right before `<script src="js/api.js">` in `index.html` (you'll do this properly in Task 8 but a quick sanity check now keeps wiring honest).

```bash
cd ~/Documents/Dev/sentinel/dashboard
npm run dev
```

Open Safari to `http://localhost:3000`. Open the JS console:

```js
Collector.isConfigured()
Collector.setConfig({ url: 'http://localhost:18443', key: 'abc' })
Collector.isConfigured()
Collector.getConfig()
localStorage.removeItem('sentinel.collector.url')
localStorage.removeItem('sentinel.collector.key')
```

Expected: false → true → `{ url: '...', key: 'abc' }`. If `Collector` is undefined, the script tag wasn't added.

- [ ] **Step 3: Commit**

Remove the temporary script tag (Task 8 adds it properly).

```bash
git add dashboard/js/collector.js
git commit -m "dashboard: add collector API module"
```

---

## Task 8: Dashboard — collector view markup and styles

**Files:**
- Modify: `dashboard/index.html`
- Modify: `dashboard/css/style.css`

- [ ] **Step 1: Add the nav item, view container, modal, and script tag**

In `dashboard/index.html`, add to the sidebar nav (after the "Logs" item):

```html
        <div class="nav-item" data-view="collector">
          <span class="nav-item__icon">&#x2728;</span> Collector
        </div>
```

Add a new view container in the `<div class="content">` block (after `view-logs`):

```html
        <div id="view-collector" class="view"></div>
```

Add the settings modal markup before `</body>`:

```html
  <!-- Collector settings modal -->
  <div class="modal" id="collector-settings-modal" hidden>
    <div class="modal__backdrop" data-close="collector-settings-modal"></div>
    <div class="modal__panel">
      <header class="modal__header">
        <h2>Collector Settings</h2>
        <button class="btn btn--sm" data-close="collector-settings-modal">&times;</button>
      </header>
      <div class="modal__body">
        <label class="form-row">
          <span>Collector URL</span>
          <input type="text" id="collector-url-input" placeholder="http://localhost:18443" />
        </label>
        <label class="form-row">
          <span>Admin API key</span>
          <input type="password" id="collector-key-input" placeholder="64-hex-char admin key" />
        </label>
        <p class="form-help" id="collector-test-result"></p>
      </div>
      <footer class="modal__footer">
        <button class="btn" id="collector-test-btn">Test connection</button>
        <button class="btn btn--primary" id="collector-save-btn">Save</button>
      </footer>
    </div>
  </div>
```

Add the script tag near the bottom (before `app.js`):

```html
  <script src="js/collector.js"></script>
```

- [ ] **Step 2: Add styles**

Append to `dashboard/css/style.css`:

```css
/* Collector view */
.collector-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
  gap: 12px;
}

.event-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
.event-table th,
.event-table td {
  padding: 8px 10px;
  border-bottom: 1px solid var(--border, #2a2a2a);
  text-align: left;
}
.event-table tbody tr {
  cursor: pointer;
}
.event-table tbody tr:hover {
  background: var(--hover, rgba(255,255,255,0.04));
}

.event-detail {
  margin-top: 16px;
  padding: 12px;
  background: var(--surface-2, #1a1a1a);
  border-radius: 6px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
}

/* Modal */
.modal[hidden] { display: none; }
.modal {
  position: fixed; inset: 0;
  display: flex; align-items: center; justify-content: center;
  z-index: 100;
}
.modal__backdrop {
  position: absolute; inset: 0;
  background: rgba(0,0,0,0.6);
}
.modal__panel {
  position: relative;
  width: min(480px, 90vw);
  background: var(--surface, #181818);
  border: 1px solid var(--border, #2a2a2a);
  border-radius: 8px;
  display: flex; flex-direction: column;
}
.modal__header,
.modal__footer {
  padding: 12px 16px;
  display: flex; align-items: center; justify-content: space-between;
}
.modal__header h2 { margin: 0; font-size: 15px; }
.modal__body { padding: 0 16px 8px; }
.modal__footer { gap: 8px; justify-content: flex-end; }

.form-row { display: flex; flex-direction: column; gap: 4px; margin: 12px 0; }
.form-row span { font-size: 12px; color: var(--text-muted, #888); }
.form-row input {
  padding: 6px 10px; font-size: 13px;
  background: var(--input-bg, #0e0e0e);
  border: 1px solid var(--border, #2a2a2a);
  color: var(--text, #fff);
  border-radius: 4px;
  font-family: 'JetBrains Mono', monospace;
}
.form-help { font-size: 12px; color: var(--text-muted, #888); margin: 8px 0 0; }
.form-help--ok { color: #00d4aa; }
.form-help--err { color: #ff6b6b; }
```

If `style.css` already defines theme variables like `--border`, `--surface-2`, etc., the fallback values will be ignored.

- [ ] **Step 3: Visually verify**

```bash
npm run dev
```

Open Safari to `http://localhost:3000`. Click the Collector nav item — view switches (empty for now). In the JS console:

```js
document.getElementById('collector-settings-modal').hidden = false
```

Modal should appear with two inputs and a Save button. `hidden = true` hides it.

- [ ] **Step 4: Commit**

```bash
git add dashboard/index.html dashboard/css/style.css
git commit -m "dashboard: add collector view markup and styles"
```

---

## Task 9: Dashboard — render events and detail in `app.js` (XSS-safe)

**Files:**
- Modify: `dashboard/js/app.js`

> **Critical:** Collector responses contain user-controlled fields (`hostname`, `summary`, `client_id`, etc.). Never insert them with `innerHTML` or template-literal interpolation into HTML strings. Use `createElement` + `textContent`. The code below follows this rule.

- [ ] **Step 1: Read the existing `app.js` structure**

```bash
cat dashboard/js/app.js
```

Identify (a) the function that handles nav clicks (look for `data-view` references), (b) the pattern for view rendering (likely a `renderViewX()` per view), (c) any toast/notify helper. Match these patterns exactly when integrating the new code.

- [ ] **Step 2: Add the renderer and modal handlers**

Add the following functions to `app.js`, placed near the other `renderViewX` functions. Then wire `renderViewCollector` into the existing nav-click dispatcher (add a `case 'collector':` or matching pattern — match what's already there).

```js
function renderViewCollector() {
  const root = document.getElementById('view-collector');
  // Always rebuild — clearing children is safe; child contents are built below.
  while (root.firstChild) root.removeChild(root.firstChild);

  if (!Collector.isConfigured()) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    const p = document.createElement('p');
    p.textContent = 'Collector is not configured.';
    const btn = document.createElement('button');
    btn.className = 'btn btn--primary';
    btn.textContent = 'Configure';
    btn.onclick = openCollectorSettings;
    empty.appendChild(p);
    empty.appendChild(btn);
    root.appendChild(empty);
    return;
  }

  // Toolbar
  const toolbar = document.createElement('div');
  toolbar.className = 'collector-toolbar';
  const label = document.createElement('span');
  label.textContent = 'Recent events';
  const buttons = document.createElement('div');
  const refreshBtn = document.createElement('button');
  refreshBtn.className = 'btn btn--sm';
  refreshBtn.textContent = 'Refresh';
  refreshBtn.onclick = loadCollectorEvents;
  const settingsBtn = document.createElement('button');
  settingsBtn.className = 'btn btn--sm';
  settingsBtn.textContent = 'Settings';
  settingsBtn.onclick = openCollectorSettings;
  buttons.appendChild(refreshBtn);
  buttons.appendChild(settingsBtn);
  toolbar.appendChild(label);
  toolbar.appendChild(buttons);
  root.appendChild(toolbar);

  // Table skeleton
  const table = document.createElement('table');
  table.className = 'event-table';
  const thead = document.createElement('thead');
  const headRow = document.createElement('tr');
  for (const heading of ['Time', 'Client', 'Type', 'Severity', 'Confidence']) {
    const th = document.createElement('th');
    th.textContent = heading;
    headRow.appendChild(th);
  }
  thead.appendChild(headRow);
  const tbody = document.createElement('tbody');
  tbody.id = 'collector-events-body';
  const loadingRow = document.createElement('tr');
  const loadingCell = document.createElement('td');
  loadingCell.colSpan = 5;
  loadingCell.textContent = 'Loading…';
  loadingRow.appendChild(loadingCell);
  tbody.appendChild(loadingRow);
  table.appendChild(thead);
  table.appendChild(tbody);
  root.appendChild(table);

  // Detail pane
  const detail = document.createElement('pre');
  detail.className = 'event-detail';
  detail.id = 'collector-event-detail';
  detail.hidden = true;
  root.appendChild(detail);

  loadCollectorEvents();
}

async function loadCollectorEvents() {
  const tbody = document.getElementById('collector-events-body');
  if (!tbody) return;
  while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

  let events;
  try {
    const result = await Collector.listEvents(50);
    events = result.events;
  } catch (err) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 5;
    td.textContent = `Failed to load: ${err.message}`;
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  if (!events.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 5;
    td.textContent = 'No events yet.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  for (const e of events) {
    const tr = document.createElement('tr');
    tr.dataset.eventId = e.event_id;
    tr.onclick = () => showCollectorEvent(e.event_id);
    for (const field of [e.timestamp, e.client_id, e.detection_type, e.severity, String(e.confidence)]) {
      const td = document.createElement('td');
      td.textContent = field == null ? '' : String(field);
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
}

async function showCollectorEvent(id) {
  const detail = document.getElementById('collector-event-detail');
  detail.hidden = false;
  detail.textContent = 'Loading…';
  try {
    const e = await Collector.getEvent(id);
    detail.textContent = JSON.stringify(e, null, 2); // textContent — safe
  } catch (err) {
    detail.textContent = `Failed to load event: ${err.message}`;
  }
}

function openCollectorSettings() {
  const modal = document.getElementById('collector-settings-modal');
  const { url, key } = Collector.getConfig();
  document.getElementById('collector-url-input').value = url;
  document.getElementById('collector-key-input').value = key;
  const result = document.getElementById('collector-test-result');
  result.textContent = '';
  result.className = 'form-help';
  modal.hidden = false;
}

function closeCollectorSettings() {
  document.getElementById('collector-settings-modal').hidden = true;
}

document.addEventListener('click', (ev) => {
  const closeId = ev.target.dataset && ev.target.dataset.close;
  if (closeId === 'collector-settings-modal') closeCollectorSettings();
});

document.getElementById('collector-test-btn').addEventListener('click', async () => {
  Collector.setConfig({
    url: document.getElementById('collector-url-input').value,
    key: document.getElementById('collector-key-input').value,
  });
  const result = document.getElementById('collector-test-result');
  try {
    const r = await Collector.ping();
    result.textContent = `OK — collector v${r.version}`;
    result.className = 'form-help form-help--ok';
  } catch (err) {
    result.textContent = err.message;
    result.className = 'form-help form-help--err';
  }
});

document.getElementById('collector-save-btn').addEventListener('click', () => {
  Collector.setConfig({
    url: document.getElementById('collector-url-input').value,
    key: document.getElementById('collector-key-input').value,
  });
  closeCollectorSettings();
  renderViewCollector();
});
```

- [ ] **Step 3: Manually verify the full flow**

Terminal 1:

```bash
cd ~/Documents/Dev/sentinel/collector
go build ./cmd/collector

cat > /tmp/dash-dev.toml <<'EOF'
[server]
listen = "127.0.0.1:18443"
allowed_origins = ["http://localhost:3000"]

[storage]
sqlite_path = "/tmp/dash-dev.db"
EOF

./collector admin add-client smoke-vm-01 --config /tmp/dash-dev.toml
./collector admin add-admin dashboard-dev --config /tmp/dash-dev.toml
# Note both keys.

./collector serve --config /tmp/dash-dev.toml
```

Terminal 2 — inject one event using the client key:

```bash
curl -X POST -H "Authorization: Bearer <CLIENT-KEY>" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: $(uuidgen)" \
  -d '{
    "schema_version": 1,
    "event_id": "01900000-0000-7000-8000-000000000001",
    "client_id": "smoke-vm-01",
    "sentinel_version": "0.3.1",
    "timestamp": "2026-04-30T20:00:00Z",
    "source": "driver",
    "detection_type": "DMA_ANOMALY",
    "severity": "high",
    "confidence": 90,
    "summary": "Manual test injection",
    "host": { "hostname": "macbook", "os_version": "macOS", "arch": "arm64" },
    "context": { "process_id": 0 }
  }' \
  http://localhost:18443/v1/events
```

Terminal 3:

```bash
cd ~/Documents/Dev/sentinel/dashboard
npm run dev
```

Open Safari to `http://localhost:3000`. Click **Collector** → **Configure** → enter `http://localhost:18443` and the admin key → click **Test connection** (should print `OK — collector v0.1.0`) → click **Save**. The events table should show one row. Click the row — JSON detail appears below.

**XSS smoke test:** in Terminal 2, inject a second event with a malicious-looking `summary`:

```bash
curl -X POST -H "Authorization: Bearer <CLIENT-KEY>" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: $(uuidgen)" \
  -d '{
    "schema_version": 1,
    "event_id": "01900000-0000-7000-8000-000000000002",
    "client_id": "<script>alert(1)</script>",
    "sentinel_version": "0.3.1",
    "timestamp": "2026-04-30T20:01:00Z",
    "source": "driver",
    "detection_type": "DMA_ANOMALY",
    "severity": "high",
    "confidence": 90,
    "summary": "<img src=x onerror=alert(2)>",
    "host": { "hostname": "x", "os_version": "x", "arch": "x" },
    "context": { "process_id": 0 }
  }' \
  http://localhost:18443/v1/events
```

Reload the dashboard. The malicious strings should appear as **literal text** in the table cells — not interpreted as HTML, no alert popups. If you see a popup or the strings render as HTML, the rendering code regressed to `innerHTML` somewhere. Find it and switch to `textContent`.

Cleanup:

```bash
rm -f /tmp/dash-dev.toml /tmp/dash-dev.db /tmp/dash-dev.db-*
```

- [ ] **Step 4: Commit**

```bash
git add dashboard/js/app.js
git commit -m "dashboard: render collector events and detail (XSS-safe)"
```

---

## Task 10: Docs — README and smoke test addendum

**Files:**
- Create: `dashboard/README.md`
- Modify: `docs/smoke-test-collector.md`

- [ ] **Step 1: Write the dashboard README**

Create `dashboard/README.md`:

````markdown
# Sentinel Dashboard

Static HTML/CSS/JS — no build step. Serves on `http://localhost:3000`.

```bash
npm run dev
```

## Views

- **Status, Devices, Alerts, Config, Logs** — talk to the Sentinel service's local REST API at `http://localhost:8088`. Render mock data when the service isn't running.
- **Collector** — talks to a remote (or local) detection collector. URL and admin API key are configured via the in-app settings modal and persisted in `localStorage`.

## Configuring the Collector view

1. Run a collector (see `collector/README.md`).
2. Register an admin key:
   ```bash
   ./collector admin add-admin dashboard-dev --config <path>
   ```
3. Make sure the collector's TOML config has the dashboard origin allowed for CORS:
   ```toml
   [server]
   allowed_origins = ["http://localhost:3000"]
   ```
4. In the dashboard, click **Collector** → **Configure**. Paste the URL and admin key. **Test connection** uses the unauthenticated `/v1/healthz` to verify reachability without burning the admin key.

## Security notes

- The admin key sits in `localStorage`. Acceptable for a developer laptop, not for a shared kiosk. For production, a server-side proxy holding the key is required.
- The collector view is read-only. All collector data is rendered with `textContent` to defend against XSS via malicious `client_id` / `summary` / etc.
````

- [ ] **Step 2: Add the smoke-test addendum**

Append to `docs/smoke-test-collector.md`:

````markdown

## Step 8 — Optional: load the dashboard against the smoke collector

Useful to eyeball the same data the curl in Step 6 returns.

On macOS:

```bash
./collector admin add-admin dashboard-dev --config /tmp/collector-smoke.toml
# Note the printed admin key.
```

Edit `/tmp/collector-smoke.toml` and add to the `[server]` table:

```toml
allowed_origins = ["http://localhost:3000"]
```

Restart the collector. Then:

```bash
cd ~/Documents/Dev/sentinel/dashboard
npm run dev
```

Open Safari → `http://localhost:3000` → **Collector** → **Configure** → paste `http://127.0.0.1:18443` and the admin key. The event injected from the VM in Step 5 should appear in the table.
````

- [ ] **Step 3: Commit**

```bash
git add dashboard/README.md docs/smoke-test-collector.md
git commit -m "docs: dashboard README and collector view smoke-test addendum"
```

---

## Self-Review Notes

- **Spec coverage:** Auth split (Tasks 1–3, 5), CORS (Task 4), admin CLI (Task 6), dashboard module (Task 7), markup/styles (Task 8), wiring/render (Task 9), docs (Task 10). All covered.
- **Type consistency:** `AdminStore` (Task 2) is the type used in `query.New` (Task 3), `serve.go` (Task 5), and the e2e test (Task 5). `Collector` global (Task 7) is referenced in `app.js` (Task 9) and `index.html` script tag (Task 8).
- **XSS:** Task 9 uses `createElement` + `textContent` exclusively for collector data and includes a smoke test with a hostile payload to verify.
- **Risk:** Task 9 makes assumptions about `app.js` structure that weren't fully verified at plan-writing time. Step 1 of Task 9 explicitly mandates reading the file before changing it; the engineer should match the existing pattern rather than copy-paste blindly.
- **Out of scope deliberately:** server-side dashboard proxy (admin key in `localStorage` is acceptable for the dev iteration), client-id filter on the events view, pagination beyond `?limit=`, audit logging on admin reads.
