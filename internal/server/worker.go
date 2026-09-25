package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kexichanprojectproxy/zstd-tunnel/internal/config"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/pool"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/protocol"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/relay"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/transport"
)

var dummyHash = sha256.Sum256([]byte("not a registered service token"))

type runtime struct {
	cfg     *config.Server
	pools   map[string]*pool.Pool
	log     *slog.Logger
	ids     atomic.Uint64
	workers sync.WaitGroup
}

func (r *runtime) register(in *transport.Incoming) {
	id := r.ids.Add(1)
	conn := protocol.NewConn(in)
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	f, e := conn.ReadFrame()
	if e != nil || f.Type != protocol.HELLO || f.LeaseID != 0 {
		r.reject(conn, id, "incompatible_protocol")
		return
	}
	var hello protocol.Hello
	if e = protocol.DecodeJSON(f.Payload, &hello); e != nil {
		r.reject(conn, id, "incompatible_protocol")
		return
	}
	service, known := r.cfg.Services[hello.Service]
	expected := dummyHash
	if known {
		expected = service.TokenHash
	}
	given := sha256.Sum256([]byte(hello.Token))
	valid := subtle.ConstantTimeCompare(expected[:], given[:]) == 1
	if hello.Version != 2 || hello.Compression != "zstd" {
		r.reject(conn, id, "incompatible_protocol")
		return
	}
	if !known || !valid {
		r.reject(conn, id, "authentication_failed")
		return
	}
	opts, e := poolOptions(hello.Pool)
	if e != nil {
		r.reject(conn, id, "invalid_pool")
		return
	}
	p := r.pools[hello.Service]
	w, e := p.Register(id, opts, func() { _ = conn.Close() })
	if e != nil {
		r.reject(conn, id, "shutting_down")
		return
	}
	if e = conn.WriteFrame(protocol.Frame{Type: protocol.HELLO_OK}); e != nil {
		w.Closed()
		return
	}
	f, e = conn.ReadFrame()
	if e != nil || f.Type != protocol.READY || f.LeaseID != 0 {
		w.Closed()
		return
	}
	if e = in.CompleteAuth(); e != nil {
		w.Closed()
		return
	}
	_ = conn.SetDeadline(time.Time{})
	r.workers.Add(1)
	go func() { defer r.workers.Done(); r.work(conn, w, hello.Service) }()
}
func (r *runtime) reject(c *protocol.Conn, id uint64, code string) {
	r.log.Warn("registration rejected", "event", "registration_rejected", "connection_id", id, "code", code)
	_ = c.WriteFrame(protocol.Frame{Type: protocol.HELLO_ERR, Payload: protocol.JSON(protocol.Code{Code: code})})
	_ = c.Close()
}

// errClientClose reports that the client closed a surplus idle connection at
// the release barrier instead of returning it to the pool.
var errClientClose = errors.New("client closed connection at release")

// poolOptions validates the timings a client announced in HELLO.
func poolOptions(p protocol.PoolParams) (pool.Options, error) {
	ms := func(v int64) time.Duration {
		if v < 0 || v > 1<<40 {
			return -1
		}
		return time.Duration(v) * time.Millisecond
	}
	c := config.ClientPool{MinIdle: 1, MaxIdle: 1, Heartbeat: ms(p.HeartbeatMS), IdleTimeout: ms(p.IdleTimeoutMS), IdleJitter: ms(p.IdleJitterMS), MaxLifetime: ms(p.MaxLifetimeMS), LifetimeJitter: ms(p.LifetimeJitterMS)}
	if e := config.ValidatePool(c); e != nil {
		return pool.Options{}, e
	}
	return pool.Options{Heartbeat: c.Heartbeat, IdleTimeout: c.IdleTimeout, IdleJitter: c.IdleJitter, MaxLifetime: c.MaxLifetime, LifetimeJitter: c.LifetimeJitter}, nil
}

// goodbye tells the client that an idle connection is being retired so it
// can replace it without treating the close as a failure.
func goodbye(conn *protocol.Conn) {
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_ = conn.WriteFrame(protocol.Frame{Type: protocol.CLOSE})
}

func heartbeat(conn *protocol.Conn) error {
	var nonce [8]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return e
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if e := conn.WriteFrame(protocol.Frame{Type: protocol.PING, Payload: nonce[:]}); e != nil {
		return e
	}
	f, e := conn.ReadFrame()
	if e != nil {
		return e
	}
	if f.Type != protocol.PONG || f.LeaseID != 0 || subtle.ConstantTimeCompare(f.Payload, nonce[:]) != 1 {
		return errors.New("invalid PONG")
	}
	_ = conn.SetDeadline(time.Time{})
	return nil
}

func (r *runtime) work(conn *protocol.Conn, w *pool.Worker, service string) {
	reason := "error"
	defer func() {
		w.Closed()
		r.log.Info("connection closed", "event", "connection_closed", "service", service, "connection_id", w.ID, "reason", reason)
	}()
	var codec relay.Relay
	defer codec.Close()
	var last uint64
	outcome := w.Idle()
	for {
		switch outcome {
		case pool.Ready:
			r.log.Info("connection ready", "event", "pool_ready", "service", service, "connection_id", w.ID)
		case pool.Expired:
			reason = "expired"
			goodbye(conn)
			return
		default:
			reason = "shutdown"
			return
		}
		tcp, next := w.Next(context.Background())
		switch next {
		case pool.Check:
			if heartbeat(conn) != nil {
				return
			}
			outcome = w.Idle()
			continue
		case pool.Expired:
			reason = "expired"
			goodbye(conn)
			return
		case pool.Leased:
		default:
			reason = "shutdown"
			return
		}
		if last == math.MaxUint64 {
			_ = tcp.Close()
			return
		}
		last++
		id := last
		r.log.Info("lease started", "event", "lease_started", "service", service, "connection_id", w.ID, "lease_id", id)
		e := r.lease(conn, tcp, w, &codec, id)
		_ = tcp.Close()
		if e != nil && !errors.Is(e, errClientClose) {
			return
		}
		r.log.Info("lease finished", "event", "lease_finished", "service", service, "connection_id", w.ID, "lease_id", id)
		if e != nil {
			reason = "client_close"
			return
		}
		outcome = w.Idle()
	}
}
func (r *runtime) lease(conn *protocol.Conn, tcp *net.TCPConn, w *pool.Worker, codec *relay.Relay, id uint64) error {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if e := conn.WriteFrame(protocol.Frame{Type: protocol.OPEN, LeaseID: id}); e != nil {
		return e
	}
	f, e := conn.ReadFrame()
	if e != nil {
		return e
	}
	if f.LeaseID != id {
		return errors.New("wrong OPEN id")
	}
	switch f.Type {
	case protocol.OPEN_OK:
		_ = conn.SetDeadline(time.Time{})
		if e = codec.Run(context.Background(), conn, tcp, id); e != nil {
			return e
		}
	case protocol.OPEN_ERR:
		var code protocol.Code
		if e = protocol.DecodeJSON(f.Payload, &code); e != nil || code.Code != "dial_failed" {
			return errors.New("invalid OPEN_ERR")
		}
		_ = tcp.Close()
		_ = conn.SetDeadline(time.Time{})
	default:
		return errors.New("unexpected OPEN reply")
	}
	w.Releasing()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if e = conn.WriteFrame(protocol.Frame{Type: protocol.RELEASE, LeaseID: id}); e != nil {
		return e
	}
	f, e = conn.ReadFrame()
	if e != nil {
		return e
	}
	if f.Type == protocol.CLOSE && f.LeaseID == 0 {
		return errClientClose
	}
	if f.Type != protocol.READY || f.LeaseID != id {
		return errors.New("invalid release barrier")
	}
	_ = conn.SetDeadline(time.Time{})
	return nil
}
