# tuzik
<img width="122" height="122" alt="tuzik" src="https://github.com/user-attachments/assets/c336567f-08f6-4d10-90b0-a4854addacdc" />

A little daemon doggy shepherd that watches over your backyard and protects you from intruders. 
  
Go daemon for Linux that reads audit events from the **audisp-af_unix** Unix domain socket
and automatically **deletes** or **quarantines** (moves) files that match a set of
configurable rules as soon as they appear.

This is the same transport used by SIEM systems: `audispd` dispatches fully-formatted
audit records over the socket so tuzik requires no direct kernel access and no special
capabilities beyond read permission on the socket.

Why I adopted Tuzik  

Most security tools wait for the post-mortem. By then, the damage is done.
I wanted something different. Something that acts instantly. That’s why I brought Tuzik into my stack.
Tuzik isn’t your average guard dog. He’s built on a philosophy of immutable loyalty and real-time action:
- Immutable & Lockdown System – Tuzik is loyal only to his master. No exceptions.
- Strict Configuration-Based Logic – You tell him who, what, and where. He handles the rest.
- Kernel Audit Events – The moment something changes, Tuzik listens. He makes event-based decisions to instantly quarantine, delete, or restore files.
- Zero Tolerance for Tampering – You won’t even execute a modified file. That’s how fast the kernel audit event is processed.
- No More "Post-Mortem" Panic – No waiting 5 hours for a security scan while customer data is already being exfiltrated. Tuzik acts now.
- Ignore the Noise – He doesn’t care about hashes, heuristics, or training patterns. He simply executes the policy: “Just do it.”

## Requirements

| Dependency | Version |
|---|---|
| Go | 1.26 |
| auditd + audispd | any (Ubuntu/Debian: `apt install auditd`) |

No CGO or C library dependencies — tuzik is a pure Go binary.

## Build

```bash
make build       # produces ./tuzik
make install     # installs to /usr/local/sbin and /etc/tuzik/
```

## auditd / audispd setup

### 1 — Enable the `af_unix` dispatcher plugin

The `audisp-af_unix` plugin ships with `audispd` (part of the `auditd` package on most
distributions).  Enable it by editing its configuration file:

```
# /etc/audit/plugins.d/af_unix.conf   (path may vary by distro)
active = yes
direction = out
path = /sbin/audisp-af_unix
type = always
args = 0640 /var/run/audispd_events
format = string
```

The `args` field sets the socket permissions and path.  Reload audispd to apply:

```bash
service auditd restart   # or: kill -HUP $(pidof auditd)
```

After restarting you should see `/var/run/audispd_events` appear.

### 2 — Add audit watch rules

Create watch rules in `/etc/audit/rules.d/tuzik.rules`:

```
# Watch the upload directory for write / attribute-change events.
-w /var/www/uploads -p wa -k tuzik
```

Reload the rules:

```bash
augenrules --load   # or: service auditd reload
```

## Configuration

Copy `config.yaml` to `/etc/tuzik/config.yaml` and edit it:

```yaml
# tuzik configuration

# Path to the audisp-af_unix Unix domain socket created by the audispd plugin.
# Default: /var/run/audispd_events
socket_path: /var/run/audispd_events

# Audit key used to identify relevant events.
# Must match the -k value used in your auditd rules.
audit_key: "tuzik"

# Paths to watch for file-creation / write events.
# tuzik reacts to PATH records in audit events whose key matches audit_key
# and whose file path falls under one of these paths.
watch_paths:
  - /home/magento/public_html/pub/media/
  - /home/magento/public_html/pub/static/

# Optional: paths to exclude from monitoring even if they fall under watch_paths.
# Leave empty to process all paths under watch_paths.
ignore_paths: []

# Optional: only act on files with these exact names (basename match).
# Leave empty to match all filenames.
filenames: []

# Optional: only act on files with these extensions.
# A leading '.' is added automatically if omitted.
# Leave empty to match all extensions.
extensions:
  - .php

# Action to perform when a matching file is detected.
# Supported values: delete | quarantine
action: quarantine

# Required when action=quarantine: directory where suspicious files are moved.
quarantine_dir: /var/quarantine

# When true, log what would happen but do not modify any files.
dry_run: false

# When false (default), symlinks found in watched directories are ignored.
# Set to true to process symlinks as regular files.
allow_symlinks: false
```

### CLI flags (override config)

```
-config           path to YAML config file (default: config.yaml)
-socket           override socket_path (audisp-af_unix socket)
-audit-key        override audit_key
-action           override action (delete|quarantine)
-quarantine-dir   override quarantine_dir
-dry-run          enable dry-run mode
-allow-symlinks   enable symlink processing
```

## Usage

tuzik connects to the `audisp-af_unix` socket; the process must be able to read that
socket (permissions set in `af_unix.conf`).  Typically run as **root**:

```bash
sudo ./tuzik -config /etc/tuzik/config.yaml
```

On startup it:
1. Connects to the audisp-af_unix Unix domain socket.
2. Reads `type=X msg=audit(…): …` lines dispatched by audispd; when a complete event
   group (SYSCALL + PATH + EOE) contains the configured `audit_key` **and** a PATH record
   whose file matches the configured rules, it executes the configured action.
3. On `SIGTERM` / `SIGINT`, closes the socket and exits cleanly.

## systemd

### Install and start

After running `make install`, the unit file is placed at `/lib/systemd/system/tuzik.service`.
Enable and start the service:

```bash
systemctl daemon-reload
systemctl enable --now tuzik
systemctl status tuzik
```

Check logs with:

```bash
journalctl -u tuzik -f
```

### Adjusting `ReadWritePaths`

The unit file ships with example paths that match the defaults in `config.yaml`:

```ini
ReadWritePaths=/home/magento/public_html/pub/media
ReadWritePaths=/home/magento/public_html/pub/static
ReadWritePaths=/var/tuzik/quarantine
```

These must cover every directory listed under `watch_paths` **and** `quarantine_dir` in
`/etc/tuzik/config.yaml`.  If you change those config values, create a drop-in override
to add or replace the paths, then reload systemd:

```bash
systemctl edit tuzik   # opens a drop-in override file in $EDITOR
```

To replace all `ReadWritePaths`, reset the list first then set the new values:

```ini
[Service]
ReadWritePaths=
ReadWritePaths=/your/watch/path1
ReadWritePaths=/your/watch/path2
ReadWritePaths=/your/quarantine/dir
```

After saving the drop-in:

```bash
systemctl daemon-reload
systemctl restart tuzik
```

## Tests

```bash
make test
```

Unit tests cover config loading, line parsing, field parsing, socket reading,
path matching, and file actions (delete / quarantine / dry-run / symlink handling)
without requiring auditd or root privileges.

## Architecture

| File | Purpose |
|---|---|
| `main.go` | Entry point, CLI flags, daemon loop, signal handling |
| `config.go` | YAML config loading and validation |
| `audit.go` | `SocketListener` — reads `type=X msg=…` lines from the audisp-af_unix socket |
| `handler.go` | Audit event parsing, grouping by serial, match evaluation |
| `action.go` | File delete / quarantine implementation |
| `tuzik_test.go` | Unit tests |
