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

type slot struct {
	conn *protocol.Conn
	tcp  *net.TCPConn
	busy bool
}
type runtime struct {
	cfg      *config.Client
	log      *slog.Logger
	mu       sync.Mutex
	slots    map[*slot]struct{}
	stopping bool
	wg       sync.WaitGroup
}

func (r *runtime) runSlot(ctx context.Context, service string, cfg config.Service) {
	defer r.wg.Done()
	s := &slot{}
	r.mu.Lock()
	r.slots[s] = struct{}{}
	r.mu.Unlock()
	defer func() { r.drop(s); r.mu.Lock(); delete(r.slots, s); r.mu.Unlock() }()
	backoff := 250 * time.Millisecond
	for ctx.Err() == nil {
		raw, e := transport.Dial(ctx, r.cfg.Transport)
		if e == nil {
			c := protocol.NewConn(raw)
			r.mu.Lock()
			if r.stopping {
				r.mu.Unlock()
				_ = c.Close()
				return
			}
			s.conn = c
			r.mu.Unlock()
			started := time.Now()
			e = r.serveSlot(ctx, s, c, service, cfg)
			r.drop(s)
			if ctx.Err() != nil {
				return
			}
			if time.Since(started) >= 30*time.Second {
				backoff = 250 * time.Millisecond
			}
		}
		if e != nil {
			r.log.Warn("client connection failed", "event", "connection_closed", "service", service, "error", e.Error())
		}
		jitter := time.Duration(rand.Int64N(int64(backoff) + 1))
		timer := time.NewTimer(jitter)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}
func (r *runtime) drop(s *slot) {
	r.mu.Lock()
	conn, tcp := s.conn, s.tcp
	s.conn = nil
	s.tcp = nil
	s.busy = false
	r.mu.Unlock()
	if tcp != nil {
		_ = tcp.Close()
	}
	if conn != nil {
		_ = conn.Close()
	}
}
func (r *runtime) setBusy(s *slot, tcp *net.TCPConn, busy bool) {
	r.mu.Lock()
	s.tcp = tcp
	s.busy = busy
	r.mu.Unlock()
}
func (r *runtime) serveSlot(ctx context.Context, s *slot, c *protocol.Conn, service string, cfg config.Service) error {
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if e := c.WriteFrame(protocol.Frame{Type: protocol.HELLO, Payload: protocol.JSON(protocol.Hello{Version: 1, Service: service, Token: cfg.Token, Compression: "zstd"})}); e != nil {
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
	if e = c.WriteFrame(protocol.Frame{Type: protocol.READY}); e != nil {
		return e
	}
	_ = c.SetDeadline(time.Time{})
	var codec relay.Relay
	defer codec.Close()
	var last uint64
	for {
		if ctx.Err() != nil {
			return nil
		}
		_ = c.SetReadDeadline(time.Now().Add(45 * time.Second))
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
		case protocol.OPEN:
			if last == math.MaxUint64 || f.LeaseID != last+1 {
				return errors.New("nonmonotonic OPEN")
			}
			last = f.LeaseID
			r.setBusy(s, nil, true)
			e = r.lease(c, s, cfg, &codec, last)
			r.setBusy(s, nil, false)
			if e != nil {
				return e
			}
			if ctx.Err() != nil {
				return nil
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
		r.setBusy(s, tcp, true)
		defer tcp.Close()
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
		if !s.busy && s.conn != nil {
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
