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

// startCollector boots an httptest collector wired with separate client and
// admin key stores. Returns (server, store, clientKey, adminKey) so tests use
// the right credential class for each route: clientKey for POST /v1/events,
// adminKey for GET /v1/events[/{id}].
func startCollector(t *testing.T) (*httptest.Server, *store.SQLiteStore, string, string) {
	t.Helper()
	s, err := store.OpenSQLite(filepath.Join(t.TempDir(), "e2e.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	const clientKey = "e2e-key"
	const adminKey = "e2e-admin-key"

	ks := auth.NewKeyStore()
	ks.Add("e2e", clientKey)

	as := auth.NewAdminStore()
	as.Add("e2e-admin", adminKey)

	ingestH := ingest.New(s, ks)
	queryH := query.New(s, as)

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
	return srv, s, clientKey, adminKey
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
	srv, _, clientKey, adminKey := startCollector(t)

	// Send 50 events
	events := make([]wire.Event, 50)
	for i := range events {
		events[i] = syntheticEvent(fmt.Sprintf("e2e-%03d", i))
	}
	resp := postBatch(t, srv.URL, clientKey, events)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST: got %d, want 202; body=%s", resp.StatusCode, body)
	}

	// List them back
	req, _ := http.NewRequest("GET", srv.URL+"/v1/events?limit=100", nil)
	req.Header.Set("Authorization", "Bearer "+adminKey)
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
	getReq.Header.Set("Authorization", "Bearer "+adminKey)
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
	srv, _, clientKey, adminKey := startCollector(t)
	events := []wire.Event{syntheticEvent("dup")}

	for i := 0; i < 3; i++ {
		resp := postBatch(t, srv.URL, clientKey, events)
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("retry %d: got %d", i, resp.StatusCode)
		}
	}

	// Only one should exist.
	req, _ := http.NewRequest("GET", srv.URL+"/v1/events", nil)
	req.Header.Set("Authorization", "Bearer "+adminKey)
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
	srv, _, _, _ := startCollector(t)
	resp := postBatch(t, srv.URL, "not-the-right-key", []wire.Event{syntheticEvent("e1")})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", resp.StatusCode)
	}
}

func TestE2E_Fault_BadSchema(t *testing.T) {
	srv, _, clientKey, _ := startCollector(t)
	bad := syntheticEvent("bad")
	bad.Severity = "apocalyptic"
	resp := postBatch(t, srv.URL, clientKey, []wire.Event{bad})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("got %d, want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("severity")) {
		t.Errorf("400 body should name the failing field, got %s", body)
	}
}

// TestE2E_AuthClassesAreSeparate verifies that client keys cannot read events
// and admin keys cannot ingest. This guards the security boundary that
// motivated splitting KeyStore from AdminStore: a leaked client credential on
// a fielded agent must not grant fleet-wide read access.
func TestE2E_AuthClassesAreSeparate(t *testing.T) {
	srv, _, clientKey, adminKey := startCollector(t)

	// 1) GET with client key → 401
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/events", nil)
	req.Header.Set("Authorization", "Bearer "+clientKey)
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
	req2.Header.Set("Authorization", "Bearer "+adminKey)
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
	req3.Header.Set("Authorization", "Bearer "+adminKey)
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

// TestE2E_Fault_ServerDown verifies client-side behavior is out of scope for
// Go e2e tests — the client lives in C++. We do instead test the "server
// returns 503 when the store errors" path via a broken store in a unit test.
// See store/sqlite_test.go for store-level failures.
