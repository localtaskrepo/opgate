package main

import (
	"io"
	"net/http"
	"sync"
	"time"
)

// maxStreams caps open event streams (one per visible opgate tab; pages close theirs while hidden).
const maxStreams = 32

// changes tells open pages that something they show may have changed: a request came or was decided, a key or
// grant was used, something was revoked or loaded. Pages then ask for their own state (/overview/state,
// /r/{id}/state, /u/{tag}/state); the stream itself carries nothing.
type changes struct {
	mu   sync.Mutex
	subs map[chan struct{}]struct{}
}

// subscribe returns a channel that gets a value after changes (several changes in a row may arrive as one).
func (c *changes) subscribe() (chan struct{}, func(), bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.subs) >= maxStreams {
		return nil, nil, false
	}
	if c.subs == nil {
		c.subs = map[chan struct{}]struct{}{}
	}
	ch := make(chan struct{}, 1)
	c.subs[ch] = struct{}{}
	return ch, func() {
		c.mu.Lock()
		delete(c.subs, ch)
		c.mu.Unlock()
	}, true
}

func (c *changes) publish() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for ch := range c.subs {
		select {
		case ch <- struct{}{}:
		default: // a change is already waiting for this page
		}
	}
}

// serveEvents is GET /events: server-sent events, "change" after each change and a comment every 25 s so proxies
// and browsers keep the connection (the reverse proxy must pass text/event-stream through unbuffered).
func (b *Broker) serveEvents(w http.ResponseWriter, req *http.Request) {
	ch, stop, ok := b.changes.subscribe()
	if !ok {
		http.Error(w, "too many open pages", http.StatusServiceUnavailable)
		return
	}
	defer stop()
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	send := func(s string) bool {
		if rc.SetWriteDeadline(time.Now().Add(10*time.Second)) != nil { // without it a stuck page would hold this handler
			return false
		}
		if _, err := io.WriteString(w, s); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	if !send("retry: 5000\n\n") {
		return
	}
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-req.Context().Done():
			return
		case <-ch:
			if !send("event: change\ndata:\n\n") {
				return
			}
		case <-ping.C:
			if !send(": ping\n\n") {
				return
			}
		}
	}
}

// ended is a decided request's outcome, kept for an hour so a page still showing it can tell what happened.
type ended struct {
	Status string
	By     string
	At     time.Time
}

const endedFor = time.Hour

// requestState is GET /r/{id}/state: "pending", the outcome (approved, denied, expired, error) with the passkey
// that approved it, or "gone". Enrollments are only reachable with their key, so they count as gone here.
func (b *Broker) requestState(id string) map[string]string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if r := b.pending[id]; r != nil {
		if r.Kind == KindEnroll {
			return map[string]string{"status": "gone"}
		}
		return map[string]string{"status": "pending"}
	}
	if e, ok := b.ended[id]; ok {
		return map[string]string{"status": e.Status, "by": e.By}
	}
	return map[string]string{"status": "gone"}
}

// rememberLocked keeps a decided request's outcome (b.mu held) and forgets those older than endedFor.
func (b *Broker) rememberLocked(r *Request, res Result) {
	if r.Kind == KindEnroll {
		return
	}
	now := b.now()
	for id, e := range b.ended {
		if now.Sub(e.At) > endedFor {
			delete(b.ended, id)
		}
	}
	by := res.By
	if res.Status != "approved" || by == "grant" {
		by = ""
	}
	b.ended[r.ID] = ended{Status: res.Status, By: by, At: now}
}
