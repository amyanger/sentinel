package config

import (
	"os"
	"path/filepath"
	"testing"
)

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
