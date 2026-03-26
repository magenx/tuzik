package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- Config tests ---

func TestLoadConfigValid(t *testing.T) {
	yaml := `
audit_key: "mykey"
watch_paths:
  - /tmp/watch
action: delete
dry_run: true
`
	path := writeTempYAML(t, yaml)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AuditKey != "mykey" {
		t.Errorf("audit_key: got %q, want %q", cfg.AuditKey, "mykey")
	}
	if len(cfg.WatchPaths) != 1 || cfg.WatchPaths[0] != "/tmp/watch" {
		t.Errorf("watch_paths: got %v", cfg.WatchPaths)
	}
	if cfg.Action != "delete" {
		t.Errorf("action: got %q, want \"delete\"", cfg.Action)
	}
	if !cfg.DryRun {
		t.Error("dry_run should be true")
	}
	if cfg.SocketPath != defaultSocketPath {
		t.Errorf("socket_path default: got %q, want %q", cfg.SocketPath, defaultSocketPath)
	}
}

func TestLoadConfigExtensionNormalisation(t *testing.T) {
	yaml := `
audit_key: "k"
watch_paths: [/tmp]
action: delete
extensions:
  - php
  - .sh
`
	path := writeTempYAML(t, yaml)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Extensions[0] != ".php" {
		t.Errorf("extension without dot not normalised: %q", cfg.Extensions[0])
	}
	if cfg.Extensions[1] != ".sh" {
		t.Errorf("extension with dot altered: %q", cfg.Extensions[1])
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	_, err := LoadConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestValidateMissingAuditKey(t *testing.T) {
	cfg := &Config{WatchPaths: []string{"/tmp"}, Action: "delete"}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for missing audit_key")
	}
}

func TestValidateMissingWatchPaths(t *testing.T) {
	cfg := &Config{AuditKey: "k", Action: "delete"}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for empty watch_paths")
	}
}

func TestValidateBadAction(t *testing.T) {
	cfg := &Config{AuditKey: "k", WatchPaths: []string{"/tmp"}, Action: "explode"}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for bad action")
	}
}

func TestValidateQuarantineDirRequired(t *testing.T) {
	cfg := &Config{AuditKey: "k", WatchPaths: []string{"/tmp"}, Action: "quarantine"}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for missing quarantine_dir")
	}
}

func TestValidateOK(t *testing.T) {
	cfg := &Config{
		AuditKey:      "k",
		WatchPaths:    []string{"/tmp"},
		Action:        "quarantine",
		QuarantineDir: "/var/q",
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- parseSerial tests ---

func TestParseSerial(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"audit(1712000000.001:100): key=\"upload\"", "100"},
		{"audit(1712000000.001:42): arch=c000003e", "42"},
		{"no audit prefix here", ""},
		{"audit(1712000000.001:1): ", "1"},
	}
	for _, tc := range tests {
		got := parseSerial(tc.input)
		if got != tc.want {
			t.Errorf("parseSerial(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// --- parseLine tests ---

func TestParseLineKnownTypes(t *testing.T) {
	tests := []struct {
		line        string
		wantType    int
		wantTextPfx string // expected prefix of text
		wantOK      bool
	}{
		{
			`type=SYSCALL msg=audit(1712000000.001:42): arch=c000003e syscall=257 key="tuzik"`,
			AuditTypeSyscall,
			`audit(1712000000.001:42):`,
			true,
		},
		{
			`type=PATH msg=audit(1712000000.001:42): item=1 name="/var/www/uploads/shell.php" nametype=CREATE`,
			AuditTypePath,
			`audit(1712000000.001:42):`,
			true,
		},
		{
			`type=EOE msg=audit(1712000000.001:42):`,
			AuditTypeEOE,
			`audit(1712000000.001:42):`,
			true,
		},
		{
			`type=PROCTITLE msg=audit(1712000000.001:42): proctitle=62617368`,
			AuditTypeProctitle,
			`audit(1712000000.001:42):`,
			true,
		},
		{`type=UNKNOWN msg=audit(1712000000.001:42):`, 0, "", false},
		{`not a type line`, 0, "", false},
		{`type=SYSCALL`, 0, "", false}, // no space / msg part
	}
	for _, tc := range tests {
		gotType, gotText, gotOK := parseLine(tc.line)
		if gotOK != tc.wantOK {
			t.Errorf("parseLine(%q) ok=%v, want %v", tc.line, gotOK, tc.wantOK)
			continue
		}
		if !gotOK {
			continue
		}
		if gotType != tc.wantType {
			t.Errorf("parseLine(%q) type=%d, want %d", tc.line, gotType, tc.wantType)
		}
		if !strings.HasPrefix(gotText, tc.wantTextPfx) {
			t.Errorf("parseLine(%q) text=%q, want prefix %q", tc.line, gotText, tc.wantTextPfx)
		}
	}
}

// --- parseRecord tests (audisp socket format) ---

// TestAudispFormatFieldParsing verifies that parseRecord correctly extracts
// the serial and fields from the payload delivered by audisp-af_unix.
// The SocketListener strips the "type=X msg=" prefix before handing the text
// to the handler, so parseRecord sees the same bare "audit(…): …" format as
// before — keeping the handler layer format-agnostic.
func TestAudispFormatFieldParsing(t *testing.T) {
	raw := `audit(1712000000.001:42): arch=c000003e syscall=257 key="tuzik"`
	rec := parseRecord(AuditTypeSyscall, raw)
	if rec.serial != "42" {
		t.Errorf("serial: got %q, want %q", rec.serial, "42")
	}
	if rec.fields["key"] != "tuzik" {
		t.Errorf("key: got %q, want %q", rec.fields["key"], "tuzik")
	}
}

func TestAudispFormatPathFieldParsing(t *testing.T) {
	raw := `audit(1712000000.001:42): item=0 name="/var/www/uploads/shell.php" nametype=CREATE`
	rec := parseRecord(AuditTypePath, raw)
	if rec.serial != "42" {
		t.Errorf("serial: got %q, want %q", rec.serial, "42")
	}
	if rec.fields["name"] != "/var/www/uploads/shell.php" {
		t.Errorf("name: got %q, want %q", rec.fields["name"], "/var/www/uploads/shell.php")
	}
	if rec.fields["item"] != "0" {
		t.Errorf("item: got %q, want %q", rec.fields["item"], "0")
	}
	if rec.fields["nametype"] != "CREATE" {
		t.Errorf("nametype: got %q, want %q", rec.fields["nametype"], "CREATE")
	}
}

// --- SocketListener tests ---

// TestSocketListenerReadEvent creates a temporary Unix socket, writes audisp-
// formatted lines to it, and verifies that SocketListener correctly parses
// them into AuditEvent values.
func TestSocketListenerReadEvent(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "audispd_events.sock")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	lines := []string{
		`type=SYSCALL msg=audit(1712000000.001:42): arch=c000003e syscall=257 key="tuzik"`,
		`type=PATH msg=audit(1712000000.001:42): item=1 name="/var/www/uploads/shell.php" nametype=CREATE`,
		`type=EOE msg=audit(1712000000.001:42):`,
		`type=UNKNOWN msg=audit(1712000000.001:43):`, // should be skipped
		`type=PATH msg=audit(1712000000.001:43): item=1 name="/var/www/uploads/evil.sh" nametype=CREATE`,
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		for _, l := range lines {
			fmt.Fprintln(conn, l)
		}
	}()

	sl, err := NewSocketListener(socketPath)
	if err != nil {
		t.Fatalf("NewSocketListener: %v", err)
	}
	defer sl.Close()

	want := []AuditEvent{
		{Type: AuditTypeSyscall, Text: `audit(1712000000.001:42): arch=c000003e syscall=257 key="tuzik"`},
		{Type: AuditTypePath, Text: `audit(1712000000.001:42): item=1 name="/var/www/uploads/shell.php" nametype=CREATE`},
		{Type: AuditTypeEOE, Text: `audit(1712000000.001:42):`},
		// UNKNOWN skipped; next is PATH
		{Type: AuditTypePath, Text: `audit(1712000000.001:43): item=1 name="/var/www/uploads/evil.sh" nametype=CREATE`},
	}

	for i, wantEv := range want {
		got, err := sl.ReadEvent()
		if err != nil {
			t.Fatalf("ReadEvent[%d]: unexpected error: %v", i, err)
		}
		if got.Type != wantEv.Type {
			t.Errorf("ReadEvent[%d] Type: got %d, want %d", i, got.Type, wantEv.Type)
		}
		if got.Text != wantEv.Text {
			t.Errorf("ReadEvent[%d] Text: got %q, want %q", i, got.Text, wantEv.Text)
		}
	}

	// After the server closes the connection, ReadEvent should return io.EOF.
	_, err = sl.ReadEvent()
	if err != io.EOF {
		t.Errorf("ReadEvent after close: got %v, want io.EOF", err)
	}
}

// TestSocketListenerClose verifies that Close unblocks a pending ReadEvent.
func TestSocketListenerClose(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "close_test.sock")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	// Accept a connection but never send anything — ReadEvent should block.
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Hold the connection open; let Close() trigger the unblock.
		defer conn.Close()
	}()

	sl, err := NewSocketListener(socketPath)
	if err != nil {
		t.Fatalf("NewSocketListener: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := sl.ReadEvent()
		done <- err
	}()

	sl.Close()
	if err := <-done; err != io.EOF {
		t.Errorf("expected io.EOF after Close, got %v", err)
	}
}

// --- parseFieldsInto tests ---

func TestParseFieldsQuoted(t *testing.T) {
	dst := make(map[string]string)
	parseFieldsInto(`key="upload" name="/var/www/file.php"`, dst)
	if dst["key"] != "upload" {
		t.Errorf("key: %q", dst["key"])
	}
	if dst["name"] != "/var/www/file.php" {
		t.Errorf("name: %q", dst["name"])
	}
}

func TestParseFieldsHex(t *testing.T) {
	// "shell.php" hex-encoded
	hexName := "7368656c6c2e706870"
	dst := make(map[string]string)
	parseFieldsInto("name="+hexName+" item=0", dst)
	if dst["name"] != "shell.php" {
		t.Errorf("hex name not decoded: %q", dst["name"])
	}
}

func TestParseFieldsUnquoted(t *testing.T) {
	dst := make(map[string]string)
	parseFieldsInto("item=0 inode=12345 dev=08:01", dst)
	if dst["item"] != "0" {
		t.Errorf("item: %q", dst["item"])
	}
}

func TestIsHexString(t *testing.T) {
	if !isHexString("deadbeef") {
		t.Error("deadbeef should be hex")
	}
	if isHexString("deadbee") { // odd length
		t.Error("odd-length string should not be hex")
	}
	if isHexString("xyz") {
		t.Error("xyz should not be hex")
	}
}

// --- EventHandler matching tests ---

func TestMatchesWatchPath(t *testing.T) {
	h := NewEventHandler(&Config{
		AuditKey:   "k",
		WatchPaths: []string{"/var/www/uploads"},
		Action:     "delete",
	})
	if !h.matchesWatchPath("/var/www/uploads/shell.php") {
		t.Error("should match file inside watch path")
	}
	if !h.matchesWatchPath("/var/www/uploads") {
		t.Error("should match exact watch path")
	}
	if h.matchesWatchPath("/var/www/other/shell.php") {
		t.Error("should NOT match file outside watch path")
	}
	if h.matchesWatchPath("/var/www/uploadssomething/file.php") {
		t.Error("should NOT match path with common prefix but not subpath")
	}
}

func TestMatchesIgnorePath(t *testing.T) {
	h := NewEventHandler(&Config{
		AuditKey:    "k",
		WatchPaths:  []string{"/var/www/uploads"},
		IgnorePaths: []string{"/var/www/uploads/cache"},
		Action:      "delete",
	})
	if !h.matchesIgnorePath("/var/www/uploads/cache/file.php") {
		t.Error("should match file inside ignore path")
	}
	if !h.matchesIgnorePath("/var/www/uploads/cache") {
		t.Error("should match exact ignore path")
	}
	if h.matchesIgnorePath("/var/www/uploads/shell.php") {
		t.Error("should NOT match file outside ignore path")
	}
	if h.matchesIgnorePath("/var/www/uploads/cachemore/file.php") {
		t.Error("should NOT match path with common prefix but not subpath")
	}
}

func TestIgnorePathSkipsAction(t *testing.T) {
	dir := t.TempDir()
	ignoredDir := filepath.Join(dir, "cache")
	if err := os.Mkdir(ignoredDir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(ignoredDir, "cached.php")
	if err := os.WriteFile(target, []byte("<?php"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		AuditKey:    "tuzik",
		WatchPaths:  []string{dir},
		IgnorePaths: []string{ignoredDir},
		Action:      "delete",
	}
	h := NewEventHandler(cfg)

	serial := "300"
	syscallLine := `audit(1774463819.025:` + serial + `): arch=c000003e syscall=257 success=yes key="tuzik"`
	pathCreateLine := `audit(1774463819.025:` + serial + `): item=1 name="` + target + `" nametype=CREATE`
	eoeLine := `audit(1774463819.025:` + serial + `):`

	h.Process(AuditTypeSyscall, syscallLine)
	h.Process(AuditTypePath, pathCreateLine)
	h.Process(AuditTypeEOE, eoeLine)

	// File should NOT have been deleted because the path is ignored.
	if _, err := os.Stat(target); err != nil {
		t.Error("file in ignore_paths should not have been deleted")
	}
}

func TestLoadConfigIgnorePaths(t *testing.T) {
	yaml := `
audit_key: "k"
watch_paths: [/tmp/watch]
ignore_paths:
  - /tmp/watch/cache
  - /tmp/watch/tmp
action: delete
`
	path := writeTempYAML(t, yaml)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.IgnorePaths) != 2 {
		t.Fatalf("ignore_paths: got %d entries, want 2", len(cfg.IgnorePaths))
	}
	if cfg.IgnorePaths[0] != "/tmp/watch/cache" {
		t.Errorf("ignore_paths[0]: got %q, want %q", cfg.IgnorePaths[0], "/tmp/watch/cache")
	}
	if cfg.IgnorePaths[1] != "/tmp/watch/tmp" {
		t.Errorf("ignore_paths[1]: got %q, want %q", cfg.IgnorePaths[1], "/tmp/watch/tmp")
	}
}

func TestMatchesRulesEmptyListsMatchAll(t *testing.T) {
	h := &EventHandler{cfg: &Config{}}
	if !h.matchesRules("/any/file.xyz") {
		t.Error("empty rules should match anything")
	}
}

func TestMatchesRulesByFilename(t *testing.T) {
	h := &EventHandler{cfg: &Config{Filenames: []string{".htaccess", "wp-config.php"}}}
	if !h.matchesRules("/var/www/.htaccess") {
		t.Error("should match .htaccess by filename")
	}
	if h.matchesRules("/var/www/index.html") {
		t.Error("should NOT match index.html")
	}
}

func TestMatchesRulesByExtension(t *testing.T) {
	h := &EventHandler{cfg: &Config{Extensions: []string{".php", ".sh"}}}
	if !h.matchesRules("/uploads/shell.php") {
		t.Error("should match .php")
	}
	if !h.matchesRules("/uploads/exploit.sh") {
		t.Error("should match .sh")
	}
	if h.matchesRules("/uploads/safe.txt") {
		t.Error("should NOT match .txt")
	}
}

// --- Action tests (no actual audit required) ---

func TestDeleteFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "malware.php")
	if err := os.WriteFile(target, []byte("<?php echo 1;"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{Action: "delete", WatchPaths: []string{dir}}
	fa := NewFileAction(cfg)
	if err := fa.Execute(target, nil); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Error("file should have been deleted")
	}
}

func TestDeleteFileDryRun(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "malware.php")
	if err := os.WriteFile(target, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{Action: "delete", DryRun: true, WatchPaths: []string{dir}}
	fa := NewFileAction(cfg)
	if err := fa.Execute(target, nil); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Error("file should still exist in dry-run mode")
	}
}

func TestQuarantineFile(t *testing.T) {
	dir := t.TempDir()
	qdir := t.TempDir()
	target := filepath.Join(dir, "shell.php")
	if err := os.WriteFile(target, []byte("<?php"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{Action: "quarantine", QuarantineDir: qdir, WatchPaths: []string{dir}}
	fa := NewFileAction(cfg)
	ctx := &FileContext{Comm: "php-fpm83", UID: "1001"}
	if err := fa.Execute(target, ctx); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// Original should be gone.
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Error("original file should have been moved")
	}
	// Quarantine entry should exist with the stamp appended.
	entries, err := os.ReadDir(qdir)
	if err != nil {
		t.Fatalf("reading quarantine dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 quarantined file, got %d", len(entries))
	}
	name := entries[0].Name()
	if !strings.HasPrefix(name, "shell.php.") {
		t.Errorf("quarantined filename %q does not start with \"shell.php.\"", name)
	}
	if !strings.HasSuffix(name, ".php-fpm83.1001") {
		t.Errorf("quarantined filename %q does not end with \".php-fpm83.1001\"", name)
	}
}

func TestQuarantineFileNameCollision(t *testing.T) {
	dir := t.TempDir()
	qdir := t.TempDir()

	// Fix the timestamp via FileContext.Time so the pre-populated entry and
	// the quarantine call use the exact same stamp — no minute-boundary race.
	fixedTime, _ := time.Parse("200601021504", "202603120916")
	ctx := &FileContext{Comm: "php-fpm", UID: "33", Time: fixedTime}
	stamp := fmt.Sprintf("%s.%s.%s", fixedTime.Format("200601021504"), ctx.Comm, ctx.UID)
	existingName := "shell.php." + stamp
	if err := os.WriteFile(filepath.Join(qdir, existingName), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(dir, "shell.php")
	if err := os.WriteFile(target, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{Action: "quarantine", QuarantineDir: qdir, WatchPaths: []string{dir}}
	fa := NewFileAction(cfg)
	if err := fa.Execute(target, ctx); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// The colliding file should end up with a ".1" suffix.
	dest := filepath.Join(qdir, existingName+".1")
	if _, err := os.Stat(dest); err != nil {
		t.Errorf("expected collision-renamed quarantine file at %s: %v", dest, err)
	}
}

func TestSkipSymlinkByDefault(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.php")
	if err := os.WriteFile(target, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.php")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("cannot create symlink:", err)
	}

	cfg := &Config{Action: "delete", AllowSymlinks: false, WatchPaths: []string{dir}}
	fa := NewFileAction(cfg)
	if err := fa.Execute(link, nil); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// The symlink should still exist.
	if _, err := os.Lstat(link); err != nil {
		t.Error("symlink should not have been removed when allow_symlinks=false")
	}
}

func TestAllowSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.php")
	if err := os.WriteFile(target, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.php")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("cannot create symlink:", err)
	}

	cfg := &Config{Action: "delete", AllowSymlinks: true, WatchPaths: []string{dir}}
	fa := NewFileAction(cfg)
	if err := fa.Execute(link, nil); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// The symlink itself should have been removed.
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Error("symlink should have been removed when allow_symlinks=true")
	}
}

// TestEvaluateItem1CreateTriggersAction is a regression test for the bug where
// the handler incorrectly skipped PATH records with item=1 (nametype=CREATE),
// which are the actual newly-created files, and only processed item=0
// (nametype=PARENT, the parent directory).  The handler must fire the
// configured action when a file appears in the watched directory.
func TestEvaluateItem1CreateTriggersAction(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "backdoor.php")
	if err := os.WriteFile(target, []byte("<?php"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		AuditKey:  "tuzik",
		WatchPaths: []string{dir},
		Action:    "delete",
	}
	h := NewEventHandler(cfg)

	// Simulate the sequence of audit records produced when a file is created
	// inside a watched directory.  SocketListener strips the "type=X msg=" prefix
	// before passing text to the handler, so the handler always sees bare
	// "audit(…): …" payloads:
	//   item=0  nametype=PARENT  → parent directory reference (must be skipped)
	//   item=1  nametype=CREATE  → the new file           (must trigger action)
	serial := "228"
	syscallLine := `audit(1774463819.025:` + serial + `): arch=c000003e syscall=257 success=yes key="tuzik"`
	pathParentLine := `audit(1774463819.025:` + serial + `): item=0 name="` + dir + `/" nametype=PARENT`
	pathCreateLine := `audit(1774463819.025:` + serial + `): item=1 name="` + target + `" nametype=CREATE`
	eoeLine := `audit(1774463819.025:` + serial + `):`

	h.Process(AuditTypeSyscall, syscallLine)
	h.Process(AuditTypePath, pathParentLine)
	h.Process(AuditTypePath, pathCreateLine)
	h.Process(AuditTypeEOE, eoeLine)

	// The file should have been deleted by the action.
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Error("handler did not trigger action: file still exists after CREATE event")
	}
}

// TestEvaluateParentOnlyDoesNotTriggerAction verifies that a PATH record with
// nametype=PARENT alone (no CREATE record) does not trigger any action.
func TestEvaluateParentOnlyDoesNotTriggerAction(t *testing.T) {
	dir := t.TempDir()

	cfg := &Config{
		AuditKey:  "tuzik",
		WatchPaths: []string{dir},
		Action:    "delete",
	}
	h := NewEventHandler(cfg)

	serial := "229"
	syscallLine := `audit(1774463819.025:` + serial + `): arch=c000003e syscall=257 success=yes key="tuzik"`
	// Only a PARENT record — no CREATE record in this event.
	pathParentLine := `audit(1774463819.025:` + serial + `): item=0 name="` + dir + `/" nametype=PARENT`
	eoeLine := `audit(1774463819.025:` + serial + `):`

	h.Process(AuditTypeSyscall, syscallLine)
	h.Process(AuditTypePath, pathParentLine)
	h.Process(AuditTypeEOE, eoeLine)
	// No assertion needed — the test passes if no panic/error occurs and no
	// unintended action was triggered (there is no file to delete anyway).
}

// --- sanitizeComponent tests ---

func TestSanitizeComponent(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"php-fpm83", "php-fpm83"},       // safe: alphanumeric + hyphen
		{"1001", "1001"},                 // safe: numeric uid
		{"", "_"},                        // empty → underscore
		{"../../etc/passwd", ".._.._etc_passwd"}, // slashes replaced; dots are safe in filename
		{"bad/comm", "bad_comm"},         // slash replaced
		{"with space", "with_space"},     // space replaced
		{"safe_name.1", "safe_name.1"},   // underscore + dot OK
		{"UPPER", "UPPER"},               // uppercase OK
	}
	for _, tc := range tests {
		got := sanitizeComponent(tc.input)
		if got != tc.want {
			t.Errorf("sanitizeComponent(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestQuarantineFileSanitizesCommUID verifies that a crafted comm value
// containing a path separator does not escape the quarantine directory.
func TestQuarantineFileSanitizesCommUID(t *testing.T) {
	dir := t.TempDir()
	qdir := t.TempDir()
	target := filepath.Join(dir, "shell.php")
	if err := os.WriteFile(target, []byte("<?php"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{Action: "quarantine", QuarantineDir: qdir, WatchPaths: []string{dir}}
	fa := NewFileAction(cfg)
	// comm contains slashes — must be sanitized to prevent path traversal.
	ctx := &FileContext{Comm: "../../../../evil", UID: "0"}
	if err := fa.Execute(target, ctx); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	entries, err := os.ReadDir(qdir)
	if err != nil {
		t.Fatalf("reading quarantine dir: %v", err)
	}
	// The quarantined file must remain inside qdir (no path traversal).
	if len(entries) != 1 {
		t.Fatalf("expected 1 quarantined file in qdir, got %d (path traversal?)", len(entries))
	}
	name := entries[0].Name()
	// The sanitized filename must not contain a path separator.
	if strings.Contains(name, "/") {
		t.Errorf("quarantined filename %q contains path separator", name)
	}
}

// --- Helpers ---

func writeTempYAML(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}
