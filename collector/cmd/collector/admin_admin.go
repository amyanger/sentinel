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
