package main

import (
	"encoding/hex"
	"log"
	"path/filepath"
	"strings"
)

// eventRecord stores the fields parsed from a single raw audit record.
type eventRecord struct {
	msgType int
	serial  string
	fields  map[string]string
}

// eventGroup accumulates all records belonging to the same audit event serial.
type eventGroup struct {
	serial  string
	records []eventRecord
}

// EventHandler processes a stream of raw audit netlink messages and triggers
// file actions when a complete event group matches the configured criteria.
type EventHandler struct {
	cfg         *Config
	groups      map[string]*eventGroup // keyed by serial
	action      *FileAction
	watchPaths  []string // pre-cleaned watch paths
	ignorePaths []string // pre-cleaned ignore paths
}

// NewEventHandler creates an EventHandler for the given config.
func NewEventHandler(cfg *Config) *EventHandler {
	cleanedWatch := make([]string, len(cfg.WatchPaths))
	for i, d := range cfg.WatchPaths {
		cleanedWatch[i] = filepath.Clean(d)
	}
	cleanedIgnore := make([]string, len(cfg.IgnorePaths))
	for i, d := range cfg.IgnorePaths {
		cleanedIgnore[i] = filepath.Clean(d)
	}
	return &EventHandler{
		cfg:         cfg,
		groups:      make(map[string]*eventGroup),
		action:      NewFileAction(cfg),
		watchPaths:  cleanedWatch,
		ignorePaths: cleanedIgnore,
	}
}

// Process receives a single audit event (type + raw text) and handles it.
func (h *EventHandler) Process(msgType int, text string) {
	switch msgType {
	case AuditTypeEOE:
		// End of event: finalise the group identified by this serial.
		serial := parseSerial(text)
		if g, ok := h.groups[serial]; ok {
			h.evaluate(g)
			delete(h.groups, serial)
		}
		return
	case AuditTypeSyscall, AuditTypePath, AuditTypeProctitle:
		// fall through
	default:
		// Ignore unrelated record types.
		return
	}

	rec := parseRecord(msgType, text)
	if rec.serial == "" {
		return
	}

	g, ok := h.groups[rec.serial]
	if !ok {
		g = &eventGroup{serial: rec.serial}
		h.groups[rec.serial] = g
	}
	g.records = append(g.records, rec)
}

// evaluate inspects a completed event group and triggers an action if it
// matches the configured audit key and file criteria.
func (h *EventHandler) evaluate(g *eventGroup) {
	// 1. Check that at least one record carries the configured audit key;
	//    also collect process metadata (comm, uid) from SYSCALL records.
	hasKey := false
	ctx := &FileContext{}
	for _, r := range g.records {
		if k, ok := r.fields["key"]; ok && k == h.cfg.AuditKey {
			hasKey = true
		}
		if r.msgType == AuditTypeSyscall {
			// Take the first non-empty values encountered.
			if ctx.Comm == "" {
				ctx.Comm = r.fields["comm"]
			}
			if ctx.UID == "" {
				ctx.UID = r.fields["uid"]
			}
		}
	}
	if !hasKey {
		return
	}

	// 2. Look for PATH records whose name matches our criteria.
	for _, r := range g.records {
		if r.msgType != AuditTypePath {
			continue
		}
		name, ok := r.fields["name"]
		if !ok || name == "" {
			continue
		}
		// Skip parent-directory reference entries and deletion entries.
		if nt, ok := r.fields["nametype"]; ok && (nt == "PARENT" || nt == "DELETE") {
			continue
		}

		if !h.matchesWatchPath(name) {
			continue
		}
		if h.matchesIgnorePath(name) {
			continue
		}
		if !h.matchesRules(name) {
			continue
		}

		log.Printf("[tuzik] match: %s (key=%s)", name, h.cfg.AuditKey)
		if err := h.action.Execute(name, ctx); err != nil {
			log.Printf("[tuzik] action error for %s: %v", name, err)
		}
	}
}

// matchesWatchPath returns true when name is located under one of the
// configured watch paths.
func (h *EventHandler) matchesWatchPath(name string) bool {
	cleanName := filepath.Clean(name)
	for _, cleanPath := range h.watchPaths {
		// Accept both exact match and prefix/sub-path match.
		if cleanName == cleanPath {
			return true
		}
		if strings.HasPrefix(cleanName, cleanPath+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// matchesIgnorePath returns true when name is located under one of the
// configured ignore paths.
func (h *EventHandler) matchesIgnorePath(name string) bool {
	cleanName := filepath.Clean(name)
	for _, cleanPath := range h.ignorePaths {
		if cleanName == cleanPath {
			return true
		}
		if strings.HasPrefix(cleanName, cleanPath+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// matchesRules returns true when the filename satisfies the configured
// filename or extension rules.  If both lists are empty, all files match.
func (h *EventHandler) matchesRules(name string) bool {
	if len(h.cfg.Filenames) == 0 && len(h.cfg.Extensions) == 0 {
		return true
	}
	base := filepath.Base(name)
	for _, fn := range h.cfg.Filenames {
		if base == fn {
			return true
		}
	}
	ext := filepath.Ext(base)
	for _, e := range h.cfg.Extensions {
		if ext == e {
			return true
		}
	}
	return false
}

// parseSerial extracts the audit event serial number from the raw record
// text.  The format is: "audit(1234567890.001:SERIAL): ..."
func parseSerial(text string) string {
	start := strings.Index(text, "audit(")
	if start == -1 {
		return ""
	}
	rest := text[start+6:]
	end := strings.Index(rest, ")")
	if end == -1 {
		return ""
	}
	pair := rest[:end] // e.g. "1234567890.001:42"
	colon := strings.LastIndex(pair, ":")
	if colon == -1 {
		return pair
	}
	return pair[colon+1:]
}

// parseRecord builds an eventRecord from a raw audit netlink text payload.
func parseRecord(msgType int, text string) eventRecord {
	rec := eventRecord{
		msgType: msgType,
		fields:  make(map[string]string),
	}
	rec.serial = parseSerial(text)

	// Strip the "audit(ts:serial): " prefix before parsing fields.
	if idx := strings.Index(text, "): "); idx >= 0 {
		text = text[idx+3:]
	}

	parseFieldsInto(text, rec.fields)
	return rec
}

// parseFieldsInto parses space-separated key=value and key="value" pairs from
// src and stores them in dst.  Hex-encoded values (without quotes) are decoded
// when they are valid hex strings longer than 2 characters.
func parseFieldsInto(src string, dst map[string]string) {
	for len(src) > 0 {
		src = strings.TrimLeft(src, " \t")
		if src == "" {
			break
		}

		// Find the key.
		eqIdx := strings.IndexByte(src, '=')
		if eqIdx <= 0 {
			break
		}
		key := src[:eqIdx]
		src = src[eqIdx+1:]

		// Find the value.
		var val string
		if len(src) > 0 && src[0] == '"' {
			// Quoted value: scan for closing quote.
			src = src[1:]
			end := strings.IndexByte(src, '"')
			if end < 0 {
				// Malformed: take the rest.
				val = src
				src = ""
			} else {
				val = src[:end]
				src = src[end+1:]
			}
		} else {
			// Unquoted value: ends at next space.
			end := strings.IndexByte(src, ' ')
			if end < 0 {
				val = src
				src = ""
			} else {
				val = src[:end]
				src = src[end:]
			}
			// Attempt hex decoding for values that look like hex strings.
			if len(val) > 2 && isHexString(val) {
				if decoded, err := hex.DecodeString(val); err == nil {
					val = string(decoded)
				}
			}
		}

		dst[key] = val
	}
}

// isHexString returns true when s consists entirely of hexadecimal digits and
// has even length.
func isHexString(s string) bool {
	if len(s)%2 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
