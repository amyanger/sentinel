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
