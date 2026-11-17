package main

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

// launchd stops the service with SIGTERM on every upgrade; exiting non-zero then shows as a failed last run
func TestServeUntilStopsCleanlyOnSignal(t *testing.T) {
	sig := make(chan os.Signal, 1)
	sig <- syscall.SIGTERM
	if err := serveUntil(make(chan error), sig); err != nil {
		t.Fatalf("SIGTERM: got %v, want nil", err)
	}
}

func TestServeUntilReturnsServerError(t *testing.T) {
	errc := make(chan error, 1)
	want := errors.New("listen: address in use")
	errc <- want
	if err := serveUntil(errc, make(chan os.Signal)); !errors.Is(err, want) {
		t.Fatalf("got %v, want %v", err, want)
	}
}
