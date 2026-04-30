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
