package main

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// defaultSocketPath is the default Unix domain socket path created by the
// audisp-af_unix plugin.
const defaultSocketPath = "/var/run/audispd_events"

// Config holds all configuration settings for the tuzik daemon.
type Config struct {
	SocketPath    string   `yaml:"socket_path"`
	AuditKey      string   `yaml:"audit_key"`
	WatchPaths    []string `yaml:"watch_paths"`
	IgnorePaths   []string `yaml:"ignore_paths"`
	Filenames     []string `yaml:"filenames"`
	Extensions    []string `yaml:"extensions"`
	Action        string   `yaml:"action"`
	QuarantineDir string   `yaml:"quarantine_dir"`
	DryRun        bool     `yaml:"dry_run"`
	AllowSymlinks bool     `yaml:"allow_symlinks"`
}

// LoadConfig reads and parses a YAML config file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %q: %w", path, err)
	}
	cfg := Config{}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %q: %w", path, err)
	}
	// Apply default for socket_path.
	if cfg.SocketPath == "" {
		cfg.SocketPath = defaultSocketPath
	}
	// Normalise extensions: ensure they start with '.'
	for i, ext := range cfg.Extensions {
		if ext != "" && !strings.HasPrefix(ext, ".") {
			cfg.Extensions[i] = "." + ext
		}
	}
	return &cfg, nil
}

// Validate ensures all required fields are present and consistent.
func (c *Config) Validate() error {
	if c.AuditKey == "" {
		return fmt.Errorf("audit_key is required")
	}
	if len(c.WatchPaths) == 0 {
		return fmt.Errorf("watch_paths must not be empty")
	}
	if c.Action != "delete" && c.Action != "quarantine" {
		return fmt.Errorf("action must be \"delete\" or \"quarantine\", got %q", c.Action)
	}
	if c.Action == "quarantine" && c.QuarantineDir == "" {
		return fmt.Errorf("quarantine_dir is required when action=quarantine")
	}
	return nil
}
