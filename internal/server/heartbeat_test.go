package server_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"net"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/config"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/protocol"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/server"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/transport"
)

const heartbeatToken = "heartbeat-test-token-with-enough-length"

// startRawServer runs a server and returns a function that registers a
// hand-driven tunnel connection announcing the given pool timings.
func startRawServer(t *testing.T) func(protocol.PoolParams) (*protocol.Conn, error) {
	t.Helper()
	serverKey, _ := noise.DH25519.GenerateKeypair(rand.Reader)
	clientKey, _ := noise.DH25519.GenerateKeypair(rand.Reader)
	tunnel := freePort(t)
	cfg := &config.Server{BindAddr: tunnel, Services: map[string]config.Service{"heartbeat": {Addr: freePort(t), TokenHash: sha256.Sum256([]byte(heartbeatToken))}}, Transport: config.ServerTransport{Type: "noise", PrivateKey: serverKey.Private, PeerKey: clientKey.Public}, Pool: config.ServerPool{MaxPending: 1, AcquireTimeout: time.Second}}
	clientCfg := config.ClientTransport{Type: "noise", PrivateKey: clientKey.Private, PeerKey: serverKey.Public, RemoteAddr: tunnel, DialTimeout: time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx, cfg) }()
	t.Cleanup(func() {
		cancel()
		select {
		case e := <-done:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(3 * time.Second):
			t.Error("server shutdown stuck")
		}
	})
	return func(params protocol.PoolParams) (*protocol.Conn, error) {
		var e error
		for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
			raw, err := transport.Dial(ctx, clientCfg)
			if err != nil {
				e = err
				time.Sleep(10 * time.Millisecond)
				continue
			}
			conn := protocol.NewConn(raw)
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			err = conn.WriteFrame(protocol.Frame{Type: protocol.HELLO, Payload: protocol.JSON(protocol.Hello{Version: 2, Service: "heartbeat", Token: heartbeatToken, Compression: "zstd", Pool: params})})
			if err == nil {
				var frame protocol.Frame
				frame, err = conn.ReadFrame()
				if err == nil && frame.Type != protocol.HELLO_OK {
					err = net.ErrClosed
				}
			}
			if err == nil {
				err = conn.WriteFrame(protocol.Frame{Type: protocol.READY})
			}
			if err == nil {
				_ = conn.SetDeadline(time.Time{})
				return conn, nil
			}
			_ = conn.Close()
			e = err
			time.Sleep(10 * time.Millisecond)
		}
		return nil, e
	}
}

var fastHeartbeat = protocol.PoolParams{HeartbeatMS: 1000, IdleTimeoutMS: 60000, MaxLifetimeMS: 3600000}

func TestHeartbeatFailuresCloseConnection(t *testing.T) {
	connect := startRawServer(t)
	first, e := connect(fastHeartbeat)
	if e != nil {
		t.Fatal(e)
	}
	defer first.Close()
	_ = first.SetReadDeadline(time.Now().Add(3 * time.Second))
	ping, e := first.ReadFrame()
	if e != nil || ping.Type != protocol.PING || ping.LeaseID != 0 || len(ping.Payload) != 8 {
		t.Fatalf("idle heartbeat: %+v %v", ping, e)
	}
	ping.Payload[0] ^= 1
	if e = first.WriteFrame(protocol.Frame{Type: protocol.PONG, Payload: ping.Payload}); e != nil {
		t.Fatal(e)
	}
	_ = first.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, e = first.ReadFrame(); e == nil {
		t.Fatal("invalid PONG kept connection alive")
	}
	second, e := connect(fastHeartbeat)
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(3 * time.Second))
	ping, e = second.ReadFrame()
	if e != nil || ping.Type != protocol.PING {
		t.Fatalf("second heartbeat: %+v %v", ping, e)
	}
	_ = second.SetReadDeadline(time.Now().Add(7 * time.Second))
	if _, e = second.ReadFrame(); e == nil {
		t.Fatal("missing PONG kept connection alive")
	}
}

func TestInvalidPoolRejected(t *testing.T) {
	connect := startRawServer(t)
	if c, e := connect(protocol.PoolParams{HeartbeatMS: 10, IdleTimeoutMS: 60000, MaxLifetimeMS: 3600000}); e == nil {
		_ = c.Close()
		t.Fatal("sub-second heartbeat accepted")
	}
}

// Heartbeats must not refresh the idle deadline, and an expiring connection
// announces CLOSE before the server hangs up.
func TestIdleExpirySendsClose(t *testing.T) {
	connect := startRawServer(t)
	c, e := connect(protocol.PoolParams{HeartbeatMS: 1000, IdleTimeoutMS: 2500, MaxLifetimeMS: 3600000})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	start := time.Now()
	pings := 0
	for {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		f, e := c.ReadFrame()
		if e != nil {
			t.Fatalf("after %d pings: %v", pings, e)
		}
		if f.Type == protocol.CLOSE {
			break
		}
		if f.Type != protocol.PING {
			t.Fatalf("unexpected frame %d", f.Type)
		}
		pings++
		if e = c.WriteFrame(protocol.Frame{Type: protocol.PONG, Payload: f.Payload}); e != nil {
			t.Fatal(e)
		}
	}
	if d := time.Since(start); d < 2400*time.Millisecond || d > 4*time.Second || pings < 2 {
		t.Fatalf("CLOSE after %v and %d pings", d, pings)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, e = c.ReadFrame(); e == nil {
		t.Fatal("connection open after CLOSE")
	}
}
