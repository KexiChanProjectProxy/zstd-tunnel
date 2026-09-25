package pool

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func pair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	accepted := make(chan *net.TCPConn, 1)
	go func() { c, _ := ln.Accept(); accepted <- c.(*net.TCPConn) }()
	c, e := net.Dial("tcp", ln.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	return c.(*net.TCPConn), <-accepted
}
func TestSerialQueueAndExpiry(t *testing.T) {
	p := New(1)
	w, e := p.Register(1, Options{}, func() {})
	if e != nil {
		t.Fatal(e)
	}
	if w.Idle() != Ready {
		t.Fatal("idle failed")
	}
	a, b := pair(t)
	defer a.Close()
	defer b.Close()
	if e = p.Dispatch(context.Background(), b, time.Now().Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	if got, _ := w.Next(context.Background()); got != b {
		t.Fatal("first handoff")
	}
	c, d := pair(t)
	defer c.Close()
	defer d.Close()
	if e = p.Dispatch(context.Background(), d, time.Now().Add(10*time.Millisecond)); e != nil {
		t.Fatal(e)
	}
	x, y := pair(t)
	defer x.Close()
	defer y.Close()
	if e = p.Dispatch(context.Background(), y, time.Now().Add(time.Second)); e != ErrFull {
		t.Fatal("pending cap")
	}
	time.Sleep(20 * time.Millisecond)
	w.Releasing()
	if w.Idle() != Ready {
		t.Fatal("return failed")
	}
	p.mu.Lock()
	pending := p.pending
	p.mu.Unlock()
	if pending != 0 {
		t.Fatal("expired waiter remained")
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	var buf [1]byte
	if _, e = c.Read(buf[:]); e == nil {
		t.Fatal("waiter not closed")
	}
	w.Closed()
	if p.Count() != 0 {
		t.Fatal("quota not freed")
	}
}
func TestCancelAfterHandoffDoesNotCloseTCP(t *testing.T) {
	p := New(1)
	w, _ := p.Register(1, Options{}, func() {})
	ctx, cancel := context.WithCancel(context.Background())
	a, b := pair(t)
	defer a.Close()
	defer b.Close()
	if e := p.Dispatch(ctx, b, time.Now().Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	w.Idle()
	got, _ := w.Next(context.Background())
	cancel()
	if _, e := a.Write([]byte("x")); e != nil {
		t.Fatal(e)
	}
	var one [1]byte
	_ = got.SetReadDeadline(time.Now().Add(time.Second))
	if _, e := got.Read(one[:]); e != nil {
		t.Fatal("handoff canceled TCP", e)
	}
	w.Closed()
}

func TestDeadlineCheckedBeforeTimerCallback(t *testing.T) {
	p := New(2)
	w, _ := p.Register(1, Options{}, func() {})
	a, b := pair(t)
	defer a.Close()
	defer b.Close()
	if e := p.Dispatch(context.Background(), b, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	p.mu.Lock()
	v := p.waiting.Front().Value.(*waiter)
	v.deadline = time.Now().Add(-time.Second)
	p.mu.Unlock()
	if w.Idle() != Ready {
		t.Fatal("idle failed")
	}
	p.mu.Lock()
	pending, mail := p.pending, w.mailbox
	p.mu.Unlock()
	if pending != 0 || mail != nil {
		t.Fatal("expired waiter handed off")
	}
	_ = a.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if _, e := a.Read(one[:]); e != io.EOF {
		t.Fatal("expired waiter not closed", e)
	}
	w.Closed()
}

func TestCheckingCannotLeaseUntilPong(t *testing.T) {
	p := New(2)
	w, _ := p.Register(1, Options{}, func() {})
	w.Idle()
	p.mu.Lock()
	p.unlinkLocked(w)
	w.state = checking
	p.mu.Unlock()
	a, b := pair(t)
	defer a.Close()
	defer b.Close()
	if e := p.Dispatch(context.Background(), b, time.Now().Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	p.mu.Lock()
	before := w.mailbox
	p.mu.Unlock()
	if before != nil {
		t.Fatal("checking connection leased")
	}
	w.Idle()
	got, _ := w.Next(context.Background())
	if got != b {
		t.Fatal("queued request not delivered after PONG")
	}
	w.Closed()
}

func TestWaitingCancellationPreservesWorker(t *testing.T) {
	p := New(1)
	w, _ := p.Register(1, Options{}, func() {})
	visitor, waiting := pair(t)
	defer visitor.Close()
	defer waiting.Close()
	ctx, cancel := context.WithCancel(context.Background())
	if e := p.Dispatch(ctx, waiting, time.Now().Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	cancel()
	_ = visitor.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if _, e := visitor.Read(one[:]); e != io.EOF {
		t.Fatalf("waiting TCP not closed: %v", e)
	}
	if w.Idle() != Ready {
		t.Fatal("cancel poisoned healthy worker")
	}
	active, handed := pair(t)
	defer active.Close()
	defer handed.Close()
	if e := p.Dispatch(context.Background(), handed, time.Now().Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	got, _ := w.Next(context.Background())
	if got != handed {
		t.Fatal("healthy worker lost handoff")
	}
	w.Closed()
}

func TestStopNeverReturnsCheckingOrReleasingToIdle(t *testing.T) {
	pChecking := New(1)
	w, _ := pChecking.Register(1, Options{}, func() {})
	w.Idle()
	pChecking.mu.Lock()
	pChecking.unlinkLocked(w)
	w.state = checking
	pChecking.mu.Unlock()
	pChecking.Stop()
	if w.Idle() != Stopped || pChecking.Count() != 0 {
		t.Fatal("late PONG restored stopped worker")
	}
	releasing := New(1)
	v, _ := releasing.Register(1, Options{}, func() {})
	v.Idle()
	visitor, accepted := pair(t)
	defer visitor.Close()
	defer accepted.Close()
	if e := releasing.Dispatch(context.Background(), accepted, time.Now().Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	v.Next(context.Background())
	v.Releasing()
	releasing.Stop()
	if releasing.Count() != 1 {
		t.Fatal("active release closed before barrier")
	}
	if v.Idle() != Stopped || releasing.Count() != 0 {
		t.Fatal("late READY restored stopped worker")
	}
}

func TestStats(t *testing.T) {
	p := New(4)
	if s := p.Stats(); s != (Stats{}) {
		t.Fatalf("empty pool %+v", s)
	}
	w, _ := p.Register(1, Options{}, func() {})
	if s := p.Stats(); s.Registering != 1 {
		t.Fatalf("registering %+v", s)
	}
	w.Idle()
	if s := p.Stats(); s.Idle != 1 || s.Registering != 0 {
		t.Fatalf("idle %+v", s)
	}
	a, b := pair(t)
	defer a.Close()
	defer b.Close()
	_ = p.Dispatch(context.Background(), b, time.Now().Add(time.Second))
	if s := p.Stats(); s.Leased != 1 || s.Idle != 0 {
		t.Fatalf("leased %+v", s)
	}
	// With the only worker leased, visitors queue.
	c, d := pair(t)
	defer c.Close()
	defer d.Close()
	_ = p.Dispatch(context.Background(), d, time.Now().Add(20*time.Millisecond))
	e, f := pair(t)
	defer e.Close()
	defer f.Close()
	ctx, cancel := context.WithCancel(context.Background())
	_ = p.Dispatch(ctx, f, time.Now().Add(time.Minute))
	if s := p.Stats(); s.Pending != 2 {
		t.Fatalf("pending %+v", s)
	}
	cancel()
	time.Sleep(60 * time.Millisecond)
	if s := p.Stats(); s.Pending != 0 || s.WaitTimeouts != 1 || s.WaitCanceled != 1 {
		t.Fatalf("dropped visitors %+v", s)
	}
	w.Releasing()
	if s := p.Stats(); s.Releasing != 1 {
		t.Fatalf("releasing %+v", s)
	}
	g, h := pair(t)
	defer g.Close()
	defer h.Close()
	_ = p.Dispatch(context.Background(), h, time.Now().Add(time.Minute))
	p.Stop()
	if s := p.Stats(); s.Pending != 0 || s.WaitCanceled != 2 || s.WaitTimeouts != 1 {
		t.Fatalf("after stop %+v", s)
	}
	w.Closed()
	if s := p.Stats(); s.Releasing != 0 {
		t.Fatalf("closed worker still counted %+v", s)
	}
}
