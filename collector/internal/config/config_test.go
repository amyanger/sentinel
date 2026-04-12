package config

import "testing"

func TestLoad_Valid(t *testing.T) {
	cfg, err := Load("../../testdata/config_valid.toml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Server.Listen != "127.0.0.1:8443" {
		t.Errorf("listen: got %q", cfg.Server.Listen)
	}
	if cfg.Storage.SQLitePath != "events.db" {
		t.Errorf("sqlite_path: got %q", cfg.Storage.SQLitePath)
	}
	if len(cfg.Clients) != 2 {
		t.Errorf("clients: got %d, want 2", len(cfg.Clients))
	}
	if cfg.Clients["acme-07"] != "s3cret-key-for-acme" {
		t.Errorf("acme-07 key mismatch")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load("nonexistent.toml")
	if err == nil {
		t.Errorf("expected error for missing file")
	}
}

func TestValidate_RequiresListen(t *testing.T) {
	cfg := &Config{}
	cfg.Storage.SQLitePath = "x"
	if err := cfg.Validate(); err == nil {
		t.Errorf("expected error for missing server.listen")
	}
}
