// Package config loads collector configuration from TOML.
package config

import (
	"errors"
	"fmt"

	"github.com/BurntSushi/toml"
)

// Config is the top-level collector configuration.
type Config struct {
	Server struct {
		Listen         string   `toml:"listen"`          // host:port for HTTPS
		TLSCert        string   `toml:"tls_cert"`        // path to PEM cert
		TLSKey         string   `toml:"tls_key"`         // path to PEM key
		AllowedOrigins []string `toml:"allowed_origins"` // CORS allow-list for dashboard origins
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

// Load reads a TOML file and parses it into a Config.
func Load(path string) (*Config, error) {
	var cfg Config
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, fmt.Errorf("load config %s: %w", path, err)
	}
	if cfg.Clients == nil {
		cfg.Clients = make(map[string]string)
	}
	if cfg.Admins == nil {
		cfg.Admins = make(map[string]string)
	}
	return &cfg, nil
}

// Validate checks required fields.
func (c *Config) Validate() error {
	if c.Server.Listen == "" {
		return errors.New("server.listen is required")
	}
	if c.Storage.SQLitePath == "" {
		return errors.New("storage.sqlite_path is required")
	}
	return nil
}
