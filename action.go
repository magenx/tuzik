package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// FileContext carries the process metadata associated with the audit event
// that triggered the action.  Its fields are used to stamp quarantined filenames.
type FileContext struct {
	Comm string    // process command name (comm field from SYSCALL record)
	UID  string    // UID of the process that created/wrote the file
	Time time.Time // timestamp for the quarantine stamp; zero means time.Now()
}

// FileAction executes the configured action (delete or quarantine) on a file.
type FileAction struct {
	cfg *Config
}

// NewFileAction creates a FileAction backed by the supplied Config.
func NewFileAction(cfg *Config) *FileAction {
	return &FileAction{cfg: cfg}
}

// Execute performs the configured action on the file at path.
// ctx carries process metadata used when quarantining; a nil ctx is treated
// as an empty context (comm "unknown", uid "0").
func (a *FileAction) Execute(path string, ctx *FileContext) error {
	// Resolve the path to an absolute, cleaned form.
	// filepath.Abs already calls filepath.Clean internally.
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolving path %q: %w", path, err)
	}

	// Stat the file without following symlinks.
	info, err := os.Lstat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[tuzik] file already gone: %s", absPath)
			return nil
		}
		return fmt.Errorf("stat %q: %w", absPath, err)
	}

	// Optionally skip symlinks.
	if info.Mode()&os.ModeSymlink != 0 && !a.cfg.AllowSymlinks {
		log.Printf("[tuzik] skipping symlink: %s", absPath)
		return nil
	}

	switch a.cfg.Action {
	case "delete":
		return a.deleteFile(absPath)
	case "quarantine":
		return a.quarantineFile(absPath, ctx)
	default:
		return fmt.Errorf("unknown action %q", a.cfg.Action)
	}
}

// deleteFile removes the file at absPath.
func (a *FileAction) deleteFile(absPath string) error {
	if a.cfg.DryRun {
		log.Printf("[tuzik] dry-run: would delete %s", absPath)
		return nil
	}
	log.Printf("[tuzik] deleting %s", absPath)
	if err := os.Remove(absPath); err != nil {
		return fmt.Errorf("delete %q: %w", absPath, err)
	}
	return nil
}

// quarantineFile moves the file at absPath into the configured quarantine
// directory with a stamped filename:
//
//	<base>.<YYYYMMDDhhmm>.<comm>.<uid>
//
// For example: file.php.202603120916.php-fpm83.1001
func (a *FileAction) quarantineFile(absPath string, ctx *FileContext) error {
	if err := os.MkdirAll(a.cfg.QuarantineDir, 0o750); err != nil {
		return fmt.Errorf("creating quarantine dir %q: %w", a.cfg.QuarantineDir, err)
	}

	comm, uid := "unknown", "0"
	if ctx != nil {
		if ctx.Comm != "" {
			comm = ctx.Comm
		}
		if ctx.UID != "" {
			uid = ctx.UID
		}
	}
	// Sanitize audit-supplied values before embedding them in a filename.
	// This prevents path traversal if a crafted comm or uid contains '/' or '..'
	comm = sanitizeComponent(comm)
	uid = sanitizeComponent(uid)

	ts := time.Now()
	if ctx != nil && !ctx.Time.IsZero() {
		ts = ctx.Time
	}

	base := filepath.Base(absPath)
	stamp := fmt.Sprintf("%s.%s.%s", ts.Format("200601021504"), comm, uid)
	destName := base + "." + stamp
	destPath := filepath.Join(a.cfg.QuarantineDir, destName)

	// Avoid overwriting an existing entry (extremely rare with a timestamp stamp).
	if _, err := os.Lstat(destPath); err == nil {
		destPath = uniquePath(a.cfg.QuarantineDir, destName)
	}

	if a.cfg.DryRun {
		log.Printf("[tuzik] dry-run: would quarantine %s -> %s", absPath, destPath)
		return nil
	}
	log.Printf("[tuzik] quarantining %s -> %s", absPath, destPath)
	if err := os.Rename(absPath, destPath); err != nil {
		return fmt.Errorf("quarantine %q -> %q: %w", absPath, destPath, err)
	}
	return nil
}

// uniquePath generates a path that does not yet exist by appending an
// incrementing numeric suffix to the base name.
func uniquePath(dir, base string) string {
	for i := 1; ; i++ {
		candidate := filepath.Join(dir, fmt.Sprintf("%s.%d", base, i))
		if _, err := os.Lstat(candidate); os.IsNotExist(err) {
			return candidate
		}
	}
}

// sanitizeComponent replaces any character in s that is not an ASCII
// alphanumeric, hyphen, underscore, or dot with an underscore.  This prevents
// audit-supplied strings (comm, uid) from introducing path separators or other
// dangerous characters when they are embedded into quarantine filenames.
func sanitizeComponent(s string) string {
	if s == "" {
		return "_"
	}
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			out[i] = c
		} else {
			out[i] = '_'
		}
	}
	return string(out)
}
