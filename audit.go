package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

const (
	// Audit record types (from linux/audit.h).
	AuditTypeSyscall   = 1300
	AuditTypePath      = 1302
	AuditTypeEOE       = 1320
	AuditTypeProctitle = 1327
)

// auditTypeNames maps the string type names used by audisp-af_unix to the
// corresponding integer record-type constants.
var auditTypeNames = map[string]int{
	"SYSCALL":   AuditTypeSyscall,
	"PATH":      AuditTypePath,
	"EOE":       AuditTypeEOE,
	"PROCTITLE": AuditTypeProctitle,
}

// AuditEvent holds an audit record received from the audisp socket.
type AuditEvent struct {
	Type int
	Text string
}

// SocketListener reads audit events from the audisp-af_unix Unix domain socket.
// This is the same transport used by SIEM systems: audisp dispatches enriched,
// fully-formatted records so tuzik requires no direct kernel access.
type SocketListener struct {
	conn   net.Conn
	reader *bufio.Reader
}

// NewSocketListener connects to the audisp-af_unix socket at socketPath.
func NewSocketListener(socketPath string) (*SocketListener, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("connecting to audisp socket %q: %w", socketPath, err)
	}
	return &SocketListener{
		conn:   conn,
		reader: bufio.NewReader(conn),
	}, nil
}

// Close closes the underlying socket connection.
// Calling Close unblocks any in-progress ReadEvent call.
func (l *SocketListener) Close() {
	l.conn.Close()
}

// ReadEvent returns the next relevant audit event from the socket.
// Lines from audisp-af_unix have the format:
//
//	type=SYSCALL msg=audit(1234567890.001:42): arch=c000003e …
//
// ReadEvent strips the "type=X msg=" prefix and returns only the payload that
// parseRecord expects, keeping the handler layer format-agnostic.
// Returns (AuditEvent{}, io.EOF) when the connection is closed.
func (l *SocketListener) ReadEvent() (AuditEvent, error) {
	for {
		line, err := l.reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return AuditEvent{}, io.EOF
			}
			// Treat a closed connection as clean EOF so the caller can shut down.
			if isClosedConnError(err) {
				return AuditEvent{}, io.EOF
			}
			return AuditEvent{}, fmt.Errorf("reading from audisp socket: %w", err)
		}

		line = strings.TrimRight(line, "\r\n")
		msgType, text, ok := parseLine(line)
		if !ok {
			continue // unrecognized record type — skip
		}
		return AuditEvent{Type: msgType, Text: text}, nil
	}
}

// parseLine parses one line from audisp-af_unix.
// Expected format: "type=TYPE msg=audit(…): …"
// Returns the integer record type, the text after "type=TYPE msg=", and true.
// Returns (0, "", false) for unrecognized or malformed lines.
func parseLine(line string) (int, string, bool) {
	if !strings.HasPrefix(line, "type=") {
		return 0, "", false
	}
	rest := line[5:] // after "type="
	spaceIdx := strings.IndexByte(rest, ' ')
	if spaceIdx < 0 {
		return 0, "", false
	}
	typeName := rest[:spaceIdx]
	msgType, ok := auditTypeNames[typeName]
	if !ok {
		return 0, "", false
	}
	text := rest[spaceIdx+1:] // everything after "TYPENAME "
	// Strip the "msg=" prefix that audisp prepends.
	if strings.HasPrefix(text, "msg=") {
		text = text[4:]
	}
	return msgType, text, true
}

// isClosedConnError reports whether err indicates a closed network connection.
func isClosedConnError(err error) bool {
	return errors.Is(err, net.ErrClosed)
}
