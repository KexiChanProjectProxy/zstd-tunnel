package transport

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestGuardDeadlineAndRelease(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	var releases atomic.Int32
	g := newGuard(a, func(*guard) { releases.Add(1) })
	defer g.fail()
	g.mu.Lock()
	until := g.until
	phase := g.phase
	g.mu.Unlock()
	if phase.After(until) {
		t.Fatal("phase exceeds registration limit")
	}
	g.next()
	g.mu.Lock()
	phase = g.phase
	g.mu.Unlock()
	if phase.After(until) {
		t.Fatal("next phase exceeds total deadline")
	}
	if e := g.deadline(time.Time{}, a.SetReadDeadline); e != nil {
		t.Fatal(e)
	}
	g.mu.Lock()
	g.phase = time.Now().Add(-time.Second)
	g.mu.Unlock()
	if e := g.complete(); e != context.DeadlineExceeded {
		t.Fatal("late registration completed", e)
	}
	g.fail()
	if releases.Load() != 1 {
		t.Fatal("slot released multiple times")
	}
}
func TestGuardCompletesOnce(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	var releases atomic.Int32
	g := newGuard(a, func(*guard) { releases.Add(1) })
	if e := g.complete(); e != nil {
		t.Fatal(e)
	}
	g.fail()
	if releases.Load() != 1 {
		t.Fatal("guard released twice")
	}
}
func TestExpiredHandshakeCannotAdvance(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	var releases atomic.Int32
	g := newGuard(a, func(*guard) { releases.Add(1) })
	g.mu.Lock()
	g.phase = time.Now().Add(-time.Second)
	g.mu.Unlock()
	if g.next() {
		t.Fatal("expired phase advanced")
	}
	if e := g.complete(); e != context.DeadlineExceeded {
		t.Fatal("late READY accepted", e)
	}
	if releases.Load() != 1 {
		t.Fatal("guard not released exactly once")
	}
}
