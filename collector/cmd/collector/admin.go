package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"

	"sentinel/collector/internal/config"
)

func runAdmin(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: collector admin add-client <name> --config <path>")
	}
	switch args[0] {
	case "add-client":
		return runAdminAddClient(args[1:])
	default:
		return fmt.Errorf("unknown admin subcommand %q", args[0])
	}
}

func runAdminAddClient(args []string) error {
	// Separate positional args from flags so that both orderings work:
	//   add-client <name> --config <path>
	//   add-client --config <path> <name>
	var positional []string
	var flagArgs []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			flagArgs = append(flagArgs, args[i])
			// Consume the next token as the flag value if the flag uses
			// separate-value form (e.g. "--config path" vs "--config=path").
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") &&
				!strings.Contains(args[i], "=") {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		} else {
			positional = append(positional, args[i])
		}
	}

	fs := flag.NewFlagSet("admin add-client", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "path to collector TOML config")
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if len(positional) < 1 {
		return errors.New("client name required")
	}
	clientName := positional[0]
	if strings.ContainsAny(clientName, " \t\n") {
		return errors.New("client name cannot contain whitespace")
	}
	if *cfgPath == "" {
		return errors.New("--config is required")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if _, exists := cfg.Clients[clientName]; exists {
		return fmt.Errorf("client %q already exists", clientName)
	}

	key, err := generateAPIKey()
	if err != nil {
		return err
	}
	if cfg.Clients == nil {
		cfg.Clients = make(map[string]string)
	}
	cfg.Clients[clientName] = key

	if err := writeConfig(*cfgPath, cfg); err != nil {
		return err
	}
	fmt.Println("client added:", clientName)
	fmt.Println("api key:     ", key)
	fmt.Println("(store this key on the client side; it cannot be recovered)")
	return nil
}

// generateAPIKey returns 32 random bytes hex-encoded (64 characters).
func generateAPIKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// writeConfig writes the config back to path. TOML marshaling preserves the
// structure but will not preserve comments from the original file — that's
// acceptable for MVP.
func writeConfig(path string, cfg *config.Config) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := toml.NewEncoder(f)
	return enc.Encode(cfg)
}
