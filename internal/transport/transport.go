package transport

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/kexichanprojectproxy/zstd-tunnel/internal/config"
)

type Incoming struct {
	net.Conn
	guard *guard
}

func (in *Incoming) CompleteAuth() error { return in.guard.complete() }

type guard struct {
	mu           sync.Mutex
	conn         net.Conn
	until, phase time.Time
	timer        *time.Timer
	done         bool
	onDone       func(*guard)
}

func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func newGuard(c net.Conn, onDone func(*guard)) *guard {
	g := &guard{conn: c, until: time.Now().Add(20 * time.Second), onDone: onDone}
	g.phase = earlier(time.Now().Add(10*time.Second), g.until)
	g.timer = time.AfterFunc(time.Until(g.phase), func() { g.fail() })
	_ = c.SetDeadline(g.phase)
	return g
}
func (g *guard) next() bool {
	g.mu.Lock()
	if g.done || !time.Now().Before(g.phase) || !time.Now().Before(g.until) {
		g.mu.Unlock()
		g.fail()
		return false
	}
	g.phase = earlier(time.Now().Add(10*time.Second), g.until)
	_ = g.conn.SetDeadline(g.phase)
	g.timer.Reset(time.Until(g.phase))
	g.mu.Unlock()
	return true
}
func (g *guard) complete() error {
	g.mu.Lock()
	if g.done || !time.Now().Before(g.until) || !time.Now().Before(g.phase) {
		g.mu.Unlock()
		g.fail()
		return context.DeadlineExceeded
	}
	g.done = true
	g.timer.Stop()
	_ = g.conn.SetDeadline(time.Time{})
	g.mu.Unlock()
	g.onDone(g)
	return nil
}
func (g *guard) fail() {
	g.mu.Lock()
	if g.done {
		g.mu.Unlock()
		return
	}
	g.done = true
	g.timer.Stop()
	g.mu.Unlock()
	_ = g.conn.Close()
	g.onDone(g)
}
func (g *guard) deadline(t time.Time, method func(time.Time) error) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.done && (t.IsZero() || t.After(g.phase)) {
		t = g.phase
	}
	return method(t)
}

type guardedConn struct {
	net.Conn
	g *guard
}

func (c *guardedConn) Close() error                  { c.g.fail(); return c.Conn.Close() }
func (c *guardedConn) SetDeadline(t time.Time) error { return c.g.deadline(t, c.Conn.SetDeadline) }
func (c *guardedConn) SetReadDeadline(t time.Time) error {
	return c.g.deadline(t, c.Conn.SetReadDeadline)
}
func (c *guardedConn) SetWriteDeadline(t time.Time) error {
	return c.g.deadline(t, c.Conn.SetWriteDeadline)
}

type guardedListener struct {
	net.Listener
	ctx      context.Context
	slots    chan struct{}
	mu       sync.Mutex
	active   map[*guard]struct{}
	stopping bool
	wg       sync.WaitGroup
}

func newListener(ctx context.Context, ln net.Listener) *guardedListener {
	return &guardedListener{Listener: ln, ctx: ctx, slots: make(chan struct{}, 64), active: make(map[*guard]struct{})}
}
func (l *guardedListener) Accept() (net.Conn, error) {
	for {
		c, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		select {
		case l.slots <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		l.mu.Lock()
		g := newGuard(c, func(g *guard) { l.mu.Lock(); delete(l.active, g); l.mu.Unlock(); <-l.slots })
		l.active[g] = struct{}{}
		l.mu.Unlock()
		return &guardedConn{Conn: c, g: g}, nil
	}
}
func (l *guardedListener) beginHandler() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stopping {
		return false
	}
	l.wg.Add(1)
	return true
}
func (l *guardedListener) stop() {
	_ = l.Listener.Close()
	l.mu.Lock()
	l.stopping = true
	a := make([]*guard, 0, len(l.active))
	for g := range l.active {
		a = append(a, g)
	}
	l.mu.Unlock()
	for _, g := range a {
		g.fail()
	}
	l.wg.Wait()
}
func Dial(ctx context.Context, cfg config.ClientTransport) (net.Conn, error) {
	switch cfg.Type {
	case "noise":
		return dialNoise(ctx, cfg)
	case "wss":
		return dialWS(ctx, cfg)
	default:
		return nil, errors.New("unsupported transport")
	}
}
func Serve(ctx context.Context, ln net.Listener, cfg config.ServerTransport, accept func(*Incoming)) error {
	l := newListener(ctx, ln)
	defer l.stop()
	if cfg.Type == "wss" {
		return serveWS(ctx, l, cfg, accept)
	}
	if cfg.Type != "noise" {
		return errors.New("unsupported transport")
	}
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		c, e := l.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			gc := c.(*guardedConn)
			raw, e := handshakeNoise(c, cfg.PrivateKey, cfg.PeerKey, false)
			if e != nil {
				_ = c.Close()
				return
			}
			if !gc.g.next() {
				_ = raw.Close()
				return
			}
			in := &Incoming{Conn: raw, guard: gc.g}
			accept(in)
			gc.g.mu.Lock()
			done := gc.g.done
			gc.g.mu.Unlock()
			if !done {
				_ = in.Close()
			}
		}()
	}
}
