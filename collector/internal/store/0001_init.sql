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
