package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/magenx/tuzik/version"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("tuzik %s\n", version.Version)
		os.Exit(0)
	}

	var (
		configFile    = flag.String("config", "/etc/tuzik/config.yaml", "path to YAML configuration file")
		socketPath    = flag.String("socket", "", "override socket_path from config (audisp-af_unix socket)")
		auditKey      = flag.String("audit-key", "", "override audit_key from config")
		action        = flag.String("action", "", "override action from config (delete|quarantine)")
		quarantineDir = flag.String("quarantine-dir", "", "override quarantine_dir from config")
		dryRun        = flag.Bool("dry-run", false, "override dry_run from config")
		allowSymlinks = flag.Bool("allow-symlinks", false, "override allow_symlinks from config")
	)
	flag.Parse()

	cfg, err := LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("[tuzik] failed to load config: %v", err)
	}

	// Apply CLI flag overrides.
	if *socketPath != "" {
		cfg.SocketPath = *socketPath
	}
	if *auditKey != "" {
		cfg.AuditKey = *auditKey
	}
	if *action != "" {
		cfg.Action = *action
	}
	if *quarantineDir != "" {
		cfg.QuarantineDir = *quarantineDir
	}
	if *dryRun {
		cfg.DryRun = true
	}
	if *allowSymlinks {
		cfg.AllowSymlinks = true
	}

	if err := cfg.Validate(); err != nil {
		log.Fatalf("[tuzik] invalid configuration: %v", err)
	}

	// Connect to the audisp-af_unix socket.  This requires no special kernel
	// capabilities — any process that can read the socket can receive events.
	listener, err := NewSocketListener(cfg.SocketPath)
	if err != nil {
		log.Fatalf("[tuzik] %v", err)
	}
	defer listener.Close()

	log.Printf("[tuzik] listening on audisp socket %s (key=%s, action=%s)",
		cfg.SocketPath, cfg.AuditKey, cfg.Action)

	if cfg.DryRun {
		log.Println("[tuzik] dry-run mode enabled; no files will be modified")
	}

	// Set up signal handling for graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	doneCh := make(chan struct{})

	go func() {
		sig := <-sigCh
		log.Printf("[tuzik] received signal %s, shutting down…", sig)
		// Close the socket first so that ReadEvent unblocks immediately.
		listener.Close()
		close(doneCh)
	}()

	// Read audit events in a goroutine so shutdown signals are respected.
	eventCh := make(chan AuditEvent, 256)
	readErrCh := make(chan error, 1)

	go func() {
		for {
			ev, err := listener.ReadEvent()
			if err != nil {
				if err != io.EOF {
					readErrCh <- err
				}
				return
			}
			select {
			case eventCh <- ev:
			case <-doneCh:
				return
			}
		}
	}()

	handler := NewEventHandler(cfg)
	log.Println("[tuzik] daemon started")

	for {
		select {
		case ev := <-eventCh:
			handler.Process(ev.Type, ev.Text)
		case err := <-readErrCh:
			log.Printf("[tuzik] fatal read error: %v", err)
			return
		case <-doneCh:
			log.Println("[tuzik] daemon stopped")
			return
		}
	}
}
