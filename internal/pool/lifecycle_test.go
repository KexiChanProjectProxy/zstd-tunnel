package pool

import (
	"context"
	"testing"
	"time"
)

func TestDispatchPrefersYoungest(t *testing.T) {
	p := New(4)
	var ws []*Worker
	// Register out of order so the idle list must sort by ID, not arrival.
	for _, id := range []uint64{2, 3, 1} {
		w, _ := p.Register(id, Options{}, func() {})
		if w.Idle() != Ready {
			t.Fatal("idle failed")
		}
		ws = append(ws, w)
	}
	defer func() {
		for _, w := range ws {
			w.Closed()
		}
	}()
	for _, want := range []uint64{3, 2, 1} {
		a, b := pair(t)
		defer a.Close()
		defer b.Close()
		if e := p.Dispatch(context.Background(), b, time.Now().Add(time.Second)); e != nil {
			t.Fatal(e)
		}
		var got *Worker
		for _, w := range ws {
			p.mu.Lock()
			if w.mailbox == b {
				got = w
			}
			p.mu.Unlock()
		}
		if got == nil || got.ID != want {
			t.Fatalf("dispatch picked %v, want connection %d", got, want)
		}
	}
	// A returning older worker must not jump ahead of a newer idle one.
	old, young := ws[2], ws[1] // IDs 1 and 3
	for _, w := range []*Worker{young, old} {
		if tcp, o := w.Next(context.Background()); o != Leased || tcp == nil {
			t.Fatal("lease not delivered")
		}
		w.Releasing()
		if w.Idle() != Ready {
			t.Fatal("return failed")
		}
	}
	p.mu.Lock()
	back := p.idle.Back().Value.(*Worker).ID
	p.mu.Unlock()
	if back != 3 {
		t.Fatalf("newest idle is %d, want 3", back)
	}
}

func TestIdleExpiry(t *testing.T) {
	p := New(1)
	w, _ := p.Register(1, Options{IdleTimeout: 50 * time.Millisecond}, func() {})
	defer w.Closed()
	start := time.Now()
	if w.Idle() != Ready {
		t.Fatal("idle failed")
	}
	if _, o := w.Next(context.Background()); o != Expired {
		t.Fatalf("outcome %d, want Expired", o)
	}
	if d := time.Since(start); d < 50*time.Millisecond || d > time.Second {
		t.Fatalf("expired after %v", d)
	}
	a, b := pair(t)
	defer a.Close()
	defer b.Close()
	if e := p.Dispatch(context.Background(), b, time.Now().Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	p.mu.Lock()
	mail, pending := w.mailbox, p.pending
	p.mu.Unlock()
	if mail != nil || pending != 1 {
		t.Fatal("expiring worker received a lease")
	}
}

func TestCheckDoesNotExtendIdleExpiry(t *testing.T) {
	p := New(1)
	w, _ := p.Register(1, Options{Heartbeat: 20 * time.Millisecond, IdleTimeout: 150 * time.Millisecond}, func() {})
	defer w.Closed()
	start := time.Now()
	w.Idle()
	checks := 0
	for {
		_, o := w.Next(context.Background())
		if o == Expired {
			break
		}
		if o != Check {
			t.Fatalf("outcome %d", o)
		}
		checks++
		if w.Idle() != Ready {
			t.Fatal("check return failed")
		}
		if time.Since(start) > time.Second {
			t.Fatal("heartbeats kept idle connection alive")
		}
	}
	if checks < 2 {
		t.Fatalf("only %d heartbeats before expiry", checks)
	}
	if d := time.Since(start); d > 400*time.Millisecond {
		t.Fatalf("expired after %v", d)
	}
}

func TestLeaseRestartsIdleExpiry(t *testing.T) {
	p := New(1)
	w, _ := p.Register(1, Options{IdleTimeout: 100 * time.Millisecond}, func() {})
	defer w.Closed()
	w.Idle()
	time.Sleep(70 * time.Millisecond)
	a, b := pair(t)
	defer a.Close()
	defer b.Close()
	if e := p.Dispatch(context.Background(), b, time.Now().Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	w.Next(context.Background())
	w.Releasing()
	returned := time.Now()
	w.Idle()
	if _, o := w.Next(context.Background()); o != Expired {
		t.Fatal("not expired")
	}
	if d := time.Since(returned); d < 100*time.Millisecond {
		t.Fatalf("lease did not restart idle timer: expired %v after return", d)
	}
}

func TestMaxLifetimeExpiresAtIdle(t *testing.T) {
	p := New(1)
	w, _ := p.Register(1, Options{MaxLifetime: 30 * time.Millisecond}, func() {})
	defer w.Closed()
	if w.Idle() != Ready {
		t.Fatal("young connection refused")
	}
	a, b := pair(t)
	defer a.Close()
	defer b.Close()
	if e := p.Dispatch(context.Background(), b, time.Now().Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	w.Next(context.Background())
	w.Releasing()
	time.Sleep(40 * time.Millisecond)
	if w.Idle() != Expired {
		t.Fatal("aged connection returned to idle")
	}
	p.mu.Lock()
	n := p.idle.Len()
	p.mu.Unlock()
	if n != 0 {
		t.Fatal("aged connection in idle list")
	}
}

func TestMaxLifetimeExpiresWhileIdle(t *testing.T) {
	p := New(1)
	w, _ := p.Register(1, Options{IdleTimeout: time.Hour, MaxLifetime: 40 * time.Millisecond}, func() {})
	defer w.Closed()
	w.Idle()
	start := time.Now()
	if _, o := w.Next(context.Background()); o != Expired {
		t.Fatal("lifetime ignored while idle")
	}
	if time.Since(start) > time.Second {
		t.Fatal("lifetime expiry late")
	}
}

func TestJitterWithinBounds(t *testing.T) {
	p := New(1)
	idle, spread := time.Minute, 10*time.Second
	life, lspread := time.Hour, time.Minute
	distinct := map[time.Duration]bool{}
	for i := range 50 {
		before := time.Now()
		w, _ := p.Register(uint64(i+1), Options{IdleTimeout: idle, IdleJitter: spread, MaxLifetime: life, LifetimeJitter: lspread}, func() {})
		w.Idle()
		after := time.Now()
		p.mu.Lock()
		exp, dies := w.expires, w.dies
		p.mu.Unlock()
		if exp.Before(before.Add(idle)) || exp.After(after.Add(idle+spread)) {
			t.Fatalf("idle deadline %v outside window", exp.Sub(before))
		}
		if dies.Before(before.Add(life)) || dies.After(after.Add(life+lspread)) {
			t.Fatalf("lifetime deadline %v outside window", dies.Sub(before))
		}
		distinct[exp.Sub(before).Round(time.Second)] = true
		w.Closed()
	}
	if len(distinct) < 5 {
		t.Fatal("idle deadlines are not jittered")
	}
}

func TestStopClosesExpiring(t *testing.T) {
	p := New(1)
	closed := make(chan struct{})
	w, _ := p.Register(1, Options{IdleTimeout: time.Millisecond}, func() { close(closed) })
	w.Idle()
	if _, o := w.Next(context.Background()); o != Expired {
		t.Fatal("not expired")
	}
	p.Stop()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("expiring worker survived Stop")
	}
	if p.Count() != 0 {
		t.Fatal("expiring worker still counted")
	}
}
