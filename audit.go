package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"iter"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Caps for what one audit line keeps: a heredoc in a command line or a pasted file as the reason must not make
// lines that readers choke on.
const (
	auditMaxReason = 1000
	auditMaxArg    = 2000
)

// Audit appends one JSON line per event (asked, approved, denied, expired, granted, ...). No secret values.
type Audit struct {
	mu   sync.Mutex
	path string
}

func (a *Audit) Log(r *Request, event, by, detail string) {
	if a == nil || a.path == "" {
		return
	}
	caller := make([]string, len(r.Caller))
	for i, c := range r.Caller {
		caller[i] = clip(c, auditMaxArg)
	}
	line, _ := json.Marshal(map[string]any{
		"time": time.Now().Format(time.RFC3339), "id": r.ID, "event": event, "kind": r.Kind, "refs": r.Refs,
		"ttl": r.TTL.String(), "reason": clip(r.Reason, auditMaxReason), "caller": caller, "cwd": r.Cwd, "by": by,
		"project": r.Asker.Project, "root": r.Asker.Root,
		"detail": clip(detail, auditMaxArg),
	})
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(a.path), 0o700); err != nil {
		log.Printf("audit: %v", err)
		return
	}
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("audit: %v", err)
		return
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		log.Printf("audit: %v", err)
	}
}

// auditLines yields the log's lines, however long (a too-long line must not end the reading, as with
// bufio.Scanner's limit).
func auditLines(r io.Reader) iter.Seq[[]byte] {
	return func(yield func([]byte) bool) {
		br := bufio.NewReaderSize(r, 64<<10)
		for {
			line, err := br.ReadBytes('\n')
			if line = bytes.TrimRight(line, "\r\n"); len(line) > 0 && !yield(line) {
				return
			}
			if err != nil {
				if err != io.EOF {
					log.Printf("audit log: %v", err)
				}
				return
			}
		}
	}
}
