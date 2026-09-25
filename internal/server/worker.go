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
	if hello.Version != 1 || hello.Compression != "zstd" {
		r.reject(conn, id, "incompatible_protocol")
		return
	}
	if !known || !valid {
		r.reject(conn, id, "authentication_failed")
		return
	}
	p := r.pools[hello.Service]
	w, e := p.Register(id, func() { _ = conn.Close() })
	if e != nil {
		r.reject(conn, id, "pool_full")
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
func (r *runtime) ready(w *pool.Worker, service string) bool {
	if !w.Idle() {
		return false
	}
	r.log.Info("connection ready", "event", "pool_ready", "service", service, "connection_id", w.ID)
	return true
}
func (r *runtime) work(conn *protocol.Conn, w *pool.Worker, service string) {
	defer func() {
		w.Closed()
		r.log.Info("connection closed", "event", "connection_closed", "service", service, "connection_id", w.ID)
	}()
	var codec relay.Relay
	defer codec.Close()
	if !r.ready(w, service) {
		return
	}
	var last uint64
	for {
		tcp, check := w.Next(context.Background())
		if check {
			var nonce [8]byte
			if _, e := rand.Read(nonce[:]); e != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			e := conn.WriteFrame(protocol.Frame{Type: protocol.PING, Payload: nonce[:]})
			if e == nil {
				var f protocol.Frame
				f, e = conn.ReadFrame()
				if e == nil && (f.Type != protocol.PONG || f.LeaseID != 0 || subtle.ConstantTimeCompare(f.Payload, nonce[:]) != 1) {
					e = errors.New("invalid PONG")
				}
			}
			if e != nil {
				return
			}
			_ = conn.SetDeadline(time.Time{})
			if !r.ready(w, service) {
				return
			}
			continue
		}
		if tcp == nil {
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
		if e != nil {
			return
		}
		r.log.Info("lease finished", "event", "lease_finished", "service", service, "connection_id", w.ID, "lease_id", id)
		if !r.ready(w, service) {
			return
		}
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
	if f.Type != protocol.READY || f.LeaseID != id {
		return errors.New("invalid release barrier")
	}
	_ = conn.SetDeadline(time.Time{})
	return nil
}
