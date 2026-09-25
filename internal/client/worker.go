package client

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/kexichanprojectproxy/zstd-tunnel/internal/config"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/protocol"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/relay"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/transport"
)

const (
	baseBackoff = 250 * time.Millisecond
	maxBackoff  = 30 * time.Second
	stableAfter = 30 * time.Second
)

// errSurplus reports that a connection was closed at the release barrier
// because the service already had max_idle idle connections.
var errSurplus = errors.New("surplus idle connection")

type slotState uint8

const (
	connecting slotState = iota
	idleSlot
	busySlot
)

// service tracks one configured service's tunnel connections. The counters
// are guarded by runtime.mu. idle+connecting never exceeds MaxIdle: new
// dials only happen while it is below MinIdle, and a connection only
// returns to idle at a release barrier while it is below MaxIdle.
type service struct {
	name             string
	cfg              config.Service
	wake             chan struct{}
	idle, connecting int
	backoff          time.Duration
	notBefore        time.Time
}
type slot struct {
	conn  *protocol.Conn
	tcp   *net.TCPConn
	state slotState
	svc   *service
}
type runtime struct {
	cfg      *config.Client
	log      *slog.Logger
	mu       sync.Mutex
	slots    map[*slot]struct{}
	stopping bool
	wg       sync.WaitGroup
}

func (svc *service) notify() {
	select {
	case svc.wake <- struct{}{}:
	default:
	}
}

// control keeps at least MinIdle idle-or-connecting tunnel connections open
// for one service, honouring the reconnect backoff after failures.
func (r *runtime) control(ctx context.Context, svc *service) {
	defer r.wg.Done()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for {
		r.mu.Lock()
		if r.stopping || ctx.Err() != nil {
			r.mu.Unlock()
			return
		}
		if need := r.cfg.Pool.MinIdle - svc.idle - svc.connecting; need > 0 {
			if wait := time.Until(svc.notBefore); wait > 0 {
				timer.Reset(wait)
			} else {
				svc.connecting += need
				r.wg.Add(need)
				for range need {
					go r.runConn(ctx, svc)
				}
			}
		}
		r.mu.Unlock()
		select {
		case <-svc.wake:
		case <-timer.C:
		case <-ctx.Done():
			return
		}
		timer.Stop()
	}
}

// runConn owns one tunnel connection from dial to close. Connections are
// never redialled in place; the controller decides whether to replace them.
func (r *runtime) runConn(ctx context.Context, svc *service) {
	defer r.wg.Done()
	s := &slot{state: connecting, svc: svc}
	r.mu.Lock()
	r.slots[s] = struct{}{}
	r.mu.Unlock()
	started := time.Now()
	e := r.dialAndServe(ctx, s)
	r.drop(s)
	r.mu.Lock()
	delete(r.slots, s)
	switch s.state {
	case connecting:
		svc.connecting--
	case idleSlot:
		svc.idle--
	}
	failed := e != nil && ctx.Err() == nil && !r.stopping
	if failed {
		if time.Since(started) >= stableAfter {
			svc.backoff = baseBackoff
		}
		svc.notBefore = time.Now().Add(time.Duration(rand.Int64N(int64(svc.backoff) + 1)))
		svc.backoff = min(svc.backoff*2, maxBackoff)
	} else if e == nil {
		svc.backoff = baseBackoff
	}
	r.mu.Unlock()
	if failed {
		r.log.Warn("client connection failed", "event", "connection_closed", "service", svc.name, "error", e.Error())
	}
	svc.notify()
}
func (r *runtime) dialAndServe(ctx context.Context, s *slot) error {
	raw, e := transport.Dial(ctx, r.cfg.Transport)
	if e != nil {
		return e
	}
	c := protocol.NewConn(raw)
	r.mu.Lock()
	if r.stopping {
		r.mu.Unlock()
		_ = c.Close()
		return nil
	}
	s.conn = c
	r.mu.Unlock()
	return r.serveSlot(ctx, s, c)
}
func (r *runtime) drop(s *slot) {
	r.mu.Lock()
	conn, tcp := s.conn, s.tcp
	s.conn = nil
	s.tcp = nil
	r.mu.Unlock()
	if tcp != nil {
		_ = tcp.Close()
	}
	if conn != nil {
		_ = conn.Close()
	}
}
func (r *runtime) setTCP(s *slot, tcp *net.TCPConn) {
	r.mu.Lock()
	s.tcp = tcp
	r.mu.Unlock()
}
func poolParams(p config.ClientPool) protocol.PoolParams {
	return protocol.PoolParams{HeartbeatMS: p.Heartbeat.Milliseconds(), IdleTimeoutMS: p.IdleTimeout.Milliseconds(), IdleJitterMS: p.IdleJitter.Milliseconds(), MaxLifetimeMS: p.MaxLifetime.Milliseconds(), LifetimeJitterMS: p.LifetimeJitter.Milliseconds()}
}
func (r *runtime) serveSlot(ctx context.Context, s *slot, c *protocol.Conn) error {
	svc := s.svc
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if e := c.WriteFrame(protocol.Frame{Type: protocol.HELLO, Payload: protocol.JSON(protocol.Hello{Version: 2, Service: svc.name, Token: svc.cfg.Token, Compression: "zstd", Pool: poolParams(r.cfg.Pool)})}); e != nil {
		return e
	}
	f, e := c.ReadFrame()
	if e != nil {
		return e
	}
	if f.LeaseID != 0 {
		return errors.New("invalid HELLO reply")
	}
	if f.Type == protocol.HELLO_ERR {
		var code protocol.Code
		if protocol.DecodeJSON(f.Payload, &code) == nil {
			return errors.New("registration: " + code.Code)
		}
		return errors.New("invalid HELLO_ERR")
	}
	if f.Type != protocol.HELLO_OK {
		return errors.New("invalid HELLO reply")
	}
	r.mu.Lock()
	s.state = idleSlot
	svc.connecting--
	svc.idle++
	r.mu.Unlock()
	if e = c.WriteFrame(protocol.Frame{Type: protocol.READY}); e != nil {
		return e
	}
	_ = c.SetDeadline(time.Time{})
	var codec relay.Relay
	defer codec.Close()
	var last uint64
	idleRead := 3 * r.cfg.Pool.Heartbeat
	for {
		if ctx.Err() != nil {
			return nil
		}
		_ = c.SetReadDeadline(time.Now().Add(idleRead))
		f, e = c.ReadFrame()
		if e != nil {
			return e
		}
		_ = c.SetReadDeadline(time.Time{})
		switch f.Type {
		case protocol.PING:
			if f.LeaseID != 0 {
				return errors.New("wrong PING id")
			}
			_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			e = c.WriteFrame(protocol.Frame{Type: protocol.PONG, Payload: f.Payload})
			_ = c.SetWriteDeadline(time.Time{})
			if e != nil {
				return e
			}
		case protocol.CLOSE:
			if f.LeaseID != 0 {
				return errors.New("wrong CLOSE id")
			}
			r.log.Info("connection retired", "event", "connection_retired", "service", svc.name, "reason", "server_close")
			return nil
		case protocol.OPEN:
			if last == math.MaxUint64 || f.LeaseID != last+1 {
				return errors.New("nonmonotonic OPEN")
			}
			last = f.LeaseID
			r.mu.Lock()
			s.state = busySlot
			svc.idle--
			r.mu.Unlock()
			svc.notify()
			e = r.lease(c, s, svc.cfg, &codec, last)
			if errors.Is(e, errSurplus) {
				r.log.Info("connection retired", "event", "connection_retired", "service", svc.name, "reason", "surplus")
				return nil
			}
			if e != nil {
				return e
			}
		default:
			return errors.New("unexpected idle frame")
		}
	}
}
func (r *runtime) lease(c *protocol.Conn, s *slot, cfg config.Service, codec *relay.Relay, id uint64) error {
	dctx, cancel := context.WithTimeout(context.Background(), r.cfg.DialTimeout)
	defer cancel()
	dialer := net.Dialer{Timeout: r.cfg.DialTimeout, KeepAlive: 30 * time.Second}
	raw, e := dialer.DialContext(dctx, "tcp", cfg.Addr)
	if e != nil {
		_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if e = c.WriteFrame(protocol.Frame{Type: protocol.OPEN_ERR, LeaseID: id, Payload: protocol.JSON(protocol.Code{Code: "dial_failed"})}); e != nil {
			return e
		}
	} else {
		tcp := raw.(*net.TCPConn)
		r.setTCP(s, tcp)
		defer func() { r.setTCP(s, nil); _ = tcp.Close() }()
		_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if e = c.WriteFrame(protocol.Frame{Type: protocol.OPEN_OK, LeaseID: id}); e != nil {
			return e
		}
		_ = c.SetWriteDeadline(time.Time{})
		if e = codec.Run(context.Background(), c, tcp, id); e != nil {
			return e
		}
	}
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	f, e := c.ReadFrame()
	if e != nil {
		return e
	}
	if f.Type != protocol.RELEASE || f.LeaseID != id {
		return errors.New("invalid RELEASE")
	}
	// The server keeps this connection out of its idle list until it sees
	// READY, so deciding here cannot race with a new OPEN.
	r.mu.Lock()
	svc := s.svc
	surplus := r.stopping || svc.idle+svc.connecting >= r.cfg.Pool.MaxIdle
	if !surplus {
		s.state = idleSlot
		svc.idle++
	}
	r.mu.Unlock()
	if surplus {
		if e = c.WriteFrame(protocol.Frame{Type: protocol.CLOSE}); e != nil {
			return e
		}
		return errSurplus
	}
	if e = c.WriteFrame(protocol.Frame{Type: protocol.READY, LeaseID: id}); e != nil {
		return e
	}
	_ = c.SetDeadline(time.Time{})
	return nil
}
func (r *runtime) stop() {
	r.mu.Lock()
	r.stopping = true
	var idle []*protocol.Conn
	for s := range r.slots {
		if s.state != busySlot && s.conn != nil {
			idle = append(idle, s.conn)
		}
	}
	r.mu.Unlock()
	for _, c := range idle {
		_ = c.Close()
	}
}
func (r *runtime) force() {
	r.mu.Lock()
	var conns []*protocol.Conn
	var tcp []*net.TCPConn
	for s := range r.slots {
		if s.conn != nil {
			conns = append(conns, s.conn)
		}
		if s.tcp != nil {
			tcp = append(tcp, s.tcp)
		}
	}
	r.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	for _, c := range tcp {
		_ = c.Close()
	}
}
