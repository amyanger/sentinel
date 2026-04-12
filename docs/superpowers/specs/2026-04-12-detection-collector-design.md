# Detection Collector — Design Spec

**Status:** Draft, pending user approval
**Date:** 2026-04-12
**Chunk:** First of several toward making Sentinel company-ready
**Author:** Design brainstormed collaboratively

---

## 1. Context and goal

Sentinel today is a single-machine tool. The driver, service, and dashboard all run on one box, and detections never leave that box. To be usable by companies — whether game studios layering Sentinel on top of existing anticheat, or non-game enterprises deploying it on internal fleets — detections must flow from many endpoints to a central place where an operator can see them.

This spec covers the **Detection Collector**: the smallest piece of infrastructure that turns Sentinel from a single-machine tool into a fleet product. It is the first of several chunks on the road to a company-deployable product.

### Goals

- Sentinel clients can forward detection events to a central service over an authenticated network connection.
- The collector durably stores events and exposes a read API for later use by an operator console.
- The detection path in the service is never blocked or slowed by collector availability.
- The collector runs as a single binary on the customer's own network, with no cloud dependencies and no data leaving the customer's perimeter.
- The architecture makes the next chunks (operator console rework, evidence bundles, self-protection) cheap to add.

### Non-goals for this chunk

- Operator console rework (still uses the existing localhost dashboard)
- Mutual TLS, client certificates, or key rotation (API keys only)
- Evidence bundles, memory snapshots, or large binary artifacts (events only)
- Multi-tenancy or per-customer isolation (single-tenant)
- SaaS hosting, cloud deployment, or anything Sentinel operates itself
- Client auto-update or fleet management
- High availability, rate limiting, or backpressure beyond HTTP 503 + retry
- Encryption at rest beyond what the customer's filesystem provides
- Driver changes of any kind

---

## 2. Architecture

### 2.1 Language choice

**The collector is written in Go.** Rationale:

- Single static binary deployment — the customer runs one file with no runtime dependencies. Enterprise IT will actively prefer this over anything that needs a Python runtime, a JVM, or a DLL bundle.
- Most of the collector can be built and tested on macOS. The existing C++ service requires Windows VM roundtrips for every change; the collector does not. This materially accelerates solo iteration.
- Go's standard library is exceptionally strong for exactly this workload (HTTP server, TLS, JSON, SQL). Expected line count is 60–70% of the equivalent C++ implementation, with fewer memory-safety footguns.

Rust would be defensible; it is rejected here only because learning Rust while building a product is too much to stack on a solo builder. C++ is rejected because a C++ HTTP/TLS/SQL backend costs significantly more time per feature than Go, and that cost compounds for the life of the project.

This adds a third language to the project (C for the driver, C++ for the service, Go for the collector). The one-time cost of introducing Go is smaller than the recurring cost of building backend infrastructure in C++.

### 2.2 Repo layout

A new top-level `collector/` component:

```
sentinel/
  collector/                         NEW
    cmd/collector/main.go            Entry point, config load, server lifecycle
    internal/
      ingest/                        POST /v1/events handler
      query/                         GET /v1/events, GET /v1/events/{id}
      store/                         Storage interface + SQLite implementation
      auth/                          API key validation, constant-time compare
      config/                        Config file parsing
      wire/                          Event schema types, JSON marshal/unmarshal
    schema/                          SQL migration files (0001_init.sql, ...)
    testdata/                        Fixtures for integration tests
    README.md
```

Design principle: five small internal packages, each with one clear responsibility. The `store` package is the important seam — an interface today with a SQLite implementation, so a later Postgres implementation can be added without touching any other package.

Modified existing component — `service/`:

```
service/
  src/
    collector_client.cpp             NEW — forwards events to collector
    collector_client.h               NEW
    detection_engine.cpp             MODIFIED — calls collector_client on detection
    main.cpp                         MODIFIED — constructs collector_client at startup
  include/sentinel/
    collector_config.h               NEW — config struct definitions and compile-time defaults (queue capacity, retry policy). Runtime values (collector URL, API key) come from the existing service config file and the Windows credential store, not from this header.
```

Design principle: the `collector_client` is a single new module with its own thread and its own bounded queue. The detection engine's only interaction with it is `enqueue(event)` — fire-and-forget, non-blocking, never throws.

### 2.3 Deployment shape

For a pilot deployment:

- The customer runs the `collector` binary on a server they own, on their own network.
- Configuration file and SQLite database live on the local filesystem next to the binary.
- TLS: self-signed certificate for development; the customer provides a real certificate for pilot. The collector does not mint certificates.
- Each Sentinel client is configured with `collector_url` and `api_key`. The API key lives in the Windows credential store on the client side, not in a plain config file.
- No cloud, no SaaS, no infrastructure operated by us. The customer owns the entire data path.

This deployment model sidesteps most compliance and trust conversations for pilot deployments: no data leaves the customer's perimeter, no uptime obligation on us, no hosting costs, and "nothing leaves our network" is a phrase enterprise security reviewers respond well to.

---

## 3. Data flow

### 3.1 Happy path, end-to-end

1. Driver reports a finding to the service via IOCTL.
2. Detection engine in the service processes the finding, applies confidence scoring, and produces an internal `detection_event_t` struct.
3. Detection engine calls `collector_client.enqueue(event)` and returns to its normal work immediately.
4. `collector_client` translates the internal struct into the wire format (JSON) and pushes it onto its in-memory send queue.
5. A background sender thread inside `collector_client` pulls events from the queue, assembles a batch, and POSTs to `https://<collector>/v1/events` over HTTPS.
6. The collector's `ingest` handler validates the API key, validates the JSON against `schema_version`, and hands the batch to `store`.
7. `store` inserts the events into SQLite in a single transaction. `event_id` is the primary key, so duplicates are idempotently ignored.
8. The collector returns `202 Accepted` with the list of accepted event IDs.
9. The sender thread drops the successfully-sent batch from its queue.

If any step from 5 onward fails, the events remain in the queue and are retried per the error-handling policy in section 4.

### 3.2 API surface (v1)

Four endpoints, no cleverness:

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/events` | Ingest a batch of detection events (client → collector) |
| `GET` | `/v1/events` | List recent events, paginated (console → collector) |
| `GET` | `/v1/events/{id}` | Fetch one event by ID |
| `GET` | `/v1/healthz` | Liveness check, no auth |

All endpoints except `/v1/healthz` require an `Authorization: Bearer <api-key>` header. Comparison is constant-time on the collector side. API keys are per-client and created by a `collector admin add-client <name>` subcommand of the collector binary itself.

Pagination on `GET /v1/events`: cursor-based, keyed on `(client_ts, event_id)` descending. Page size default 50, max 200.

### 3.3 Wire format (schema version 1)

Event JSON shape:

```json
{
  "schema_version": 1,
  "event_id": "018f4a2c-7e10-7b1a-9c5d-1f2e3a4b5c6d",
  "client_id": "acme-trading-desk-07",
  "sentinel_version": "0.3.1",
  "timestamp": "2026-04-12T14:03:27.412Z",
  "source": "driver",
  "detection_type": "DMA_ANOMALY",
  "severity": "high",
  "confidence": 87,
  "summary": "Unknown PCIe device enumerated BAR0 with unusual access pattern",
  "host": {
    "hostname": "TRADING-07",
    "os_version": "Windows 11 23H2",
    "arch": "x64"
  },
  "context": {
    "pcie_vendor_id": "0x10ee",
    "pcie_device_id": "0x7024",
    "bus": "03:00.0",
    "first_seen_ms_uptime": 142318
  }
}
```

Design decisions embedded in this shape:

- **`event_id` is a UUIDv7**, client-generated. Globally unique, sortable by time, makes idempotency and pagination trivial.
- **`client_id` is set from client config**, not derived from hostname. The customer controls naming.
- **`timestamp` is from the client**, but the collector also records its own `received_at` internally to audit drift. Neither clock is trusted alone.
- **`context` is a free-form object**. Different detection types carry different fields (DMA carries PCIe info, signature match carries process name and signature ID, etc.). The wire schema does not attempt to enumerate every context shape — each detection type gets a bag.
- **`schema_version` at the top level** allows a future v2 to ship without breaking v1 clients. The collector dispatches on this field before parsing anything else.
- **The wire format is deliberately decoupled from `detection_event_t`**. The internal struct is optimized for the kernel↔service IOCTL boundary and must not leak onto the network, because changing it later would otherwise force a coordinated client/collector upgrade.

Batch shape: `{"events": [ ...events... ]}`. Maximum 100 events per batch, maximum 1 MB raw payload size.

### 3.4 Storage schema (SQLite)

One table, one index to start:

```sql
CREATE TABLE events (
  event_id       TEXT PRIMARY KEY,
  client_id      TEXT NOT NULL,
  received_at    TEXT NOT NULL,         -- ISO-8601, collector's clock
  client_ts      TEXT NOT NULL,         -- ISO-8601, from the event
  detection_type TEXT NOT NULL,
  severity       TEXT NOT NULL,
  confidence     INTEGER NOT NULL,
  source         TEXT NOT NULL,
  summary        TEXT NOT NULL,
  raw_json       TEXT NOT NULL          -- full event payload
);

CREATE INDEX idx_events_client_ts ON events(client_id, client_ts DESC);
```

Design decisions:

- **Unpacked columns + `raw_json`**: the few fields we always query on live as real columns for speed and indexability; the full payload stays in `raw_json` so that future queries (and the console) can reach into `context.*` without a schema migration. This is a well-aged pattern in event-storage backends.
- **SQLite in WAL mode with `PRAGMA synchronous=NORMAL`**: durable enough for MVP, much faster than `FULL`, and WAL allows concurrent reads when the console joins later.
- **`event_id` as primary key** gives free idempotency on retries via `INSERT OR IGNORE`.

---

## 4. Error handling and retry semantics

Guiding principles: never lose a detection silently, never block the detection path on network I/O, and never retry a hopeless request.

### 4.1 Client-side: collector unreachable or unhappy

| Situation | Client behavior |
|---|---|
| TCP refused, DNS fail, transient handshake failure (I/O error, timeout) | Queue batch, retry with backoff |
| TLS certificate verification failure (untrusted CA, expired cert, hostname mismatch) | Fail closed, drop batch, log loudly. No plaintext fallback, ever. This is a config/security problem, not a transient problem, so retrying is wrong. |
| Collector returns `5xx` | Queue batch, retry with backoff |
| Collector returns `202 Accepted` | Drop batch from queue, success |
| Collector returns `400` (schema error) | Log loudly, drop batch, do NOT retry — programmer bug |
| Collector returns `401` (bad API key) | Log loudly, drop batch, do NOT retry — config bug; detection engine keeps running |
| Collector returns `413` (batch too large) | Split batch in half, retry each half separately |

Backoff policy: exponential with jitter — 1s, 2s, 4s, 8s, 16s, capped at 30s. No hard retry count limit for MVP; queue pressure is the runaway control.

### 4.2 Client-side: queue pressure

The send queue is a bounded in-memory ring buffer. Default capacity 10,000 events, defined as a compile-time constant in `collector_config.h`. Not runtime-tunable in the MVP — if 10,000 is the wrong number in practice, we rebuild. When full:

- Drop the **oldest** event (recent telemetry is more actionable than stale telemetry).
- Increment a `dropped_events_total` counter.
- Emit a local warning log at most once per minute to avoid log spam.

**Explicitly not in MVP:** on-disk spool so events survive service restarts. This is important eventually but is its own sub-project (crash safety, file format, garbage collection). For MVP, a service restart loses whatever was in the queue, and that is acceptable.

### 4.3 Client-side: batching behavior

- Send trigger: whenever the queue has at least 10 events, OR 5 seconds have passed since the last send attempt, whichever comes first.
- Maximum batch size: 100 events per request.
- One send in flight at a time per client. No parallel sends for MVP — simpler, and the collector is not the bottleneck.

### 4.4 Collector-side: request handling

| HTTP code | When |
|---|---|
| `202 Accepted` | Batch validated and committed to SQLite |
| `400 Bad Request` | Malformed JSON, missing required field, unknown `schema_version`. Response body names the failing field. |
| `401 Unauthorized` | Missing or invalid bearer token |
| `413 Payload Too Large` | Batch > 100 events or > 1 MB raw |
| `503 Service Unavailable` | SQLite busy or disk write failed; client should retry |
| `500 Internal Server Error` | Unexpected; log with stack trace, client retries |

**Design decision: all-or-nothing batches.** If any event in a batch fails schema validation, the whole batch is rejected with `400`. A `207 Multi-Status` partial-acceptance design exists but complicates both sides without real benefit — schema errors are deterministic, and fixing one fixes them all.

**Idempotency:** duplicate `event_id`s get `INSERT OR IGNORE`'d silently and the batch still returns `202`. Clients can retry safely without fear of double-counting.

### 4.5 Collector-side: SQLite under pressure

- WAL mode ensures readers never block writers.
- On `SQLITE_BUSY`, retry up to 3 times internally with small backoff before returning `503`.
- On disk exhaustion, writes start returning `503`, the client queues, and the operator sees log spam. We do not try to be clever — disk exhaustion is an ops problem.

### 4.6 Observability (minimum viable)

Both sides log structured JSON to stderr (`slog` on the Go side, the existing log facility on the C++ side).

Always-logged fields:

- **Client**: `queue_depth`, `last_send_status`, `retries_this_batch`, `dropped_events_total`.
- **Collector**: `events_received_total`, `events_rejected_total` (with reason), `sqlite_errors_total`, `request_duration_ms`.

No Prometheus endpoint, tracing, or metrics backend in MVP. Structured logs are enough at this stage.

### 4.7 Explicit out-of-scope for this chunk

- On-disk spool for restart survival
- Per-client rate limiting
- Authentication rotation / key expiry
- Multi-region or HA collector
- Backpressure signaling beyond HTTP 503 + retry
- Encryption at rest in SQLite
- Audit log of who accessed what

Every one of these is a legitimate concern for production. None is blocking for the first demo.

---

## 5. Testing strategy

Four layers, fastest to slowest. Goal: prove the round-trip works without needing customers, and keep fast-feedback tests on macOS so iteration is not gated on the Windows VM.

### 5.1 Layer 1 — Collector unit tests (Go, on macOS)

Standard `testing` package, no framework, no mocks. Coverage targets:

- `ingest` handler: valid batch → 202; missing auth → 401; bad schema version → 400; oversized batch → 413; duplicate `event_id` → 202 (idempotent); malformed JSON → 400.
- `store`: insert a batch, read it back, verify unique constraint, verify transaction rollback on injected error.
- `auth`: constant-time compare correctness, missing header, malformed header, valid key.
- `wire`: JSON marshal/unmarshal round-trip, schema version dispatch.

Sub-second runtime. This is the bulk of the feedback loop.

### 5.2 Layer 2 — Collector integration test (Go, in-process, on macOS)

One test stands up the full collector — real HTTP server on `127.0.0.1:0`, real SQLite in a temp file, real TLS with a self-signed cert generated at test start — and exercises it end-to-end:

1. Generate a synthetic batch of 50 events covering 3 detection types.
2. POST to `/v1/events`, expect `202`.
3. Retry the same batch, expect `202` with zero new rows in SQLite.
4. GET `/v1/events`, expect 50 rows back, newest-first, pagination works.
5. GET `/v1/events/{id}` for one event, expect it back with `context` intact.

Fault-injection scenarios bolted onto this layer:

- Collector returns 503 → client retries; events land.
- Collector returns 401 → client drops batch and does NOT retry; detection engine keeps running.
- Collector TCP-refused → client queues; when collector comes back, events flush.
- Duplicate `event_id` submitted twice → second is a no-op; row count unchanged.

### 5.3 Layer 3 — Client-side tests (C++, in Windows VM)

Surgical: test what breaks in the real world, skip what is better covered elsewhere.

- `collector_client` queue behavior: enqueue, dequeue, drop-oldest when full, `dropped_events_total` increments.
- Wire format translation: feed a synthetic `detection_event_t` through the translator and compare the JSON output byte-for-byte against a fixture file in `service/test/fixtures/`.
- Retry/backoff logic: an injectable fake HTTP sender returning configurable status codes, verifying the state machine (retry on 5xx, drop on 4xx, backoff grows).

Not tested at this layer: real network I/O, real TLS, real threading interactions. Those belong to Layer 4.

Test framework: whichever exists in `service/` today. If none, add GoogleTest via CMake; no bespoke harness.

### 5.4 Layer 4 — End-to-end smoke test (manual, run at chunk boundaries)

One scripted scenario, run by hand before any commit that touches client↔collector:

1. Start the collector with test config (self-signed cert, temp DB).
2. Start the Sentinel service in the Windows VM with `--console`, pointed at the collector.
3. Trigger a synthetic detection via a new `--inject-test-event` flag on the service, which enqueues a fake `detection_event_t` at startup. (This flag is added as part of this chunk; it costs almost nothing and unlocks smoke testing forever.)
4. Verify the event appears in the collector via `GET /v1/events`.

Slow and manual, so run only at chunk boundaries, not on every save.

### 5.5 Out of scope for this chunk's testing

- Load, throughput, or soak testing
- Chaos or OS-level network partition testing
- UI/console tests (console does not exist yet)
- Real driver fault injection (this chunk does not touch the driver)
- Cross-version compatibility (no v2 exists yet)

---

## 6. What "done" looks like for this chunk

All of the following are true:

1. A `collector` binary exists at `sentinel/collector/cmd/collector/` and builds with `go build ./...` on macOS.
2. `collector admin add-client <name>` creates an API key and persists it.
3. The collector serves `/v1/events` (POST and GET), `/v1/events/{id}` (GET), and `/v1/healthz` (GET) over HTTPS with a self-signed cert.
4. All Layer 1 and Layer 2 tests pass, including fault injection.
5. The Sentinel service has a new `collector_client` module, enabled via config, that forwards detection events asynchronously to a configured collector.
6. The service has a `--inject-test-event` flag that enqueues a synthetic detection at startup.
7. The Layer 4 smoke test passes manually: a service in the Windows VM with `--inject-test-event` causes an event to appear in the collector's database on macOS.
8. The existing localhost dashboard still works and is unaffected.
9. Both sides emit the structured log fields listed in section 4.6.

When all nine are true, this chunk is done and we move on to the next — most likely the operator console rework (Chunk 2), which reads from the collector instead of from the local service.

---

## 7. What comes after this chunk (for context, not this spec)

Rough ordering. Each is its own spec and its own implementation plan; none are locked in yet.

1. **Operator console rework** — dashboard reads from collector, multi-client view, basic auth.
2. **Evidence bundles** — detections carry signed artifacts (process snapshots, driver telemetry), stored centrally.
3. **Self-protection pass** — driver anti-unload, service watchdog, Sentinel binary integrity checks.
4. **DMA detection depth pass** — the first "escape valve" motivation chunk after the scaffolding is in place.
5. **Installer and deployment** — proper MSI, service registration, uninstaller, update path.
6. **Driver signing path** — test-sign → proper cert → eventual WHQL attestation (very long road).

Each future chunk assumes the collector exists and is the source of truth for fleet-level detection state. Everything about this chunk is designed to make those future chunks cheap.
