package main

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// stream opens /events and returns a channel that gets one value per "change" event.
func (e *env) stream() <-chan struct{} {
	ctx, cancel := context.WithCancel(context.Background())
	e.t.Cleanup(cancel)
	req, _ := http.NewRequestWithContext(ctx, "GET", e.srv.URL+"/events", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { resp.Body.Close() }) // also ends the reader below
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		e.t.Fatalf("events content type %q", ct)
	}
	out := make(chan struct{}, 16)
	ready := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(resp.Body)
		first := true
		for sc.Scan() {
			if first { // the stream's opening line: subscribed from here on
				first = false
				close(ready)
			}
			if sc.Text() == "event: change" {
				out <- struct{}{}
			}
		}
	}()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		e.t.Fatal("events stream sent nothing")
	}
	return out
}

func wantChange(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("no change event after %s", what)
	}
	for len(ch) > 0 { // several changes at once may arrive as several events
		<-ch
	}
}

func (e *env) state(path string) map[string]any {
	code, body := e.getPage(path)
	if code != 200 {
		e.t.Fatalf("%s: %d %s", path, code, body)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		e.t.Fatalf("%s: %v (%s)", path, err, body)
	}
	return m
}

// Open pages hear about a new request and its decision at once, and the request page can tell the outcome.
func TestPagesHearAboutRequests(t *testing.T) {
	e := newEnv(t)
	ch := e.stream()
	r := e.ask(cfReq)
	wantChange(t, ch, "a new request")
	if s := e.state("/r/" + r.ID + "/state"); s["status"] != "pending" {
		t.Errorf("pending request state %v", s)
	}
	if code, _ := e.post("/r/"+r.ID+"/deny", nil); code != 200 {
		t.Fatalf("deny: %d", code)
	}
	wantChange(t, ch, "a denial")
	if s := e.state("/r/" + r.ID + "/state"); s["status"] != "denied" {
		t.Errorf("denied request state %v", s)
	}
	// a page that still shows the request learns it is gone instead of showing "Denied" for a click that did nothing
	if code, _ := e.post("/r/"+r.ID+"/deny", nil); code != http.StatusConflict {
		t.Errorf("deny of a decided request: %d", code)
	}
	if s := e.state("/r/nosuch/state"); s["status"] != "gone" {
		t.Errorf("unknown request state %v", s)
	}
}

// The approval names the passkey that decided, so another page can say where it was approved.
func TestRequestStateNamesThePasskey(t *testing.T) {
	e := newEnv(t)
	a := newAuthenticator("approve.example")
	e.enroll(a)
	r := e.ask(cfReq)
	if code, body := e.approve(a, r, "0s", 0x05); code != 200 {
		t.Fatalf("approve: %d %s", code, body)
	}
	if s := e.state("/r/" + r.ID + "/state"); s["status"] != "approved" || s["by"] != "test" {
		t.Errorf("approved request state %v", s)
	}
}

// Enrollments stay behind their key: their state is not told.
func TestEnrollStateIsHidden(t *testing.T) {
	e := newEnv(t)
	r, err := e.b.Submit(RequestIn{Kind: KindEnroll, Name: "phone"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s := e.state("/r/" + r.ID + "/state"); s["status"] != "gone" {
		t.Errorf("enrollment state %v", s)
	}
}

// Activity pages hear about new uses and revokes and can compare counts.
func TestPagesHearAboutActivity(t *testing.T) {
	e := newEnv(t)
	ch := e.stream()
	act := e.b.recordUse("k", Activity{Kind: "key", Title: "Server key"}, Use{Time: time.Now(), Command: "ssh router uptime"})
	wantChange(t, ch, "a key use")
	if s := e.state("/u/" + act.Tag + "/state"); s["count"] != float64(1) || s["revoked"] != false {
		t.Errorf("activity state %v", s)
	}
	if _, _, err := e.b.Revoke(act.Tag, false); err != nil {
		t.Fatal(err)
	}
	wantChange(t, ch, "a revoke")
	if s := e.state("/u/" + act.Tag + "/state"); s["revoked"] != true {
		t.Errorf("revoked activity state %v", s)
	}
	if s := e.state("/u/nosuch/state"); s["found"] != false {
		t.Errorf("unknown activity state %v", s)
	}
}

// The stream has a cap, so a page left open in many tabs (or a client in a loop) can't pile up connections.
func TestEventStreamsAreCapped(t *testing.T) {
	e := newEnv(t)
	for range maxStreams {
		e.stream()
	}
	resp, err := http.Get(e.srv.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("stream over the cap: %d", resp.StatusCode)
	}
}

// The pages use the stream: the overview, request and activity pages all start it.
func TestPagesListen(t *testing.T) {
	e := newEnv(t)
	_, js := e.getPage("/app.js")
	if !strings.Contains(js, "new EventSource('/events')") {
		t.Error("app.js doesn't open the event stream")
	}
}
