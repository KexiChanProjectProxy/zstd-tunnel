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

func TestBadPongReleasesConnectionQuota(t *testing.T) {
	serverKey, _ := noise.DH25519.GenerateKeypair(rand.Reader)
	clientKey, _ := noise.DH25519.GenerateKeypair(rand.Reader)
	token := "heartbeat-test-token-with-enough-length"
	tunnel := freePort(t)
	cfg := &config.Server{BindAddr: tunnel, Services: map[string]config.Service{"heartbeat": {Addr: freePort(t), TokenHash: sha256.Sum256([]byte(token))}}, Transport: config.ServerTransport{Type: "noise", PrivateKey: serverKey.Private, PeerKey: clientKey.Public}, Pool: config.ServerPool{MaxConnections: 1, MaxPending: 1, AcquireTimeout: time.Second}}
	clientCfg := config.ClientTransport{Type: "noise", PrivateKey: clientKey.Private, PeerKey: serverKey.Public, RemoteAddr: tunnel, DialTimeout: time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx, cfg) }()
	defer func() {
		cancel()
		select {
		case e := <-done:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(3 * time.Second):
			t.Error("server shutdown stuck")
		}
	}()
	connect := func() (*protocol.Conn, error) {
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
			err = conn.WriteFrame(protocol.Frame{Type: protocol.HELLO, Payload: protocol.JSON(protocol.Hello{Version: 1, Service: "heartbeat", Token: token, Compression: "zstd"})})
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
	first, e := connect()
	if e != nil {
		t.Fatal(e)
	}
	defer first.Close()
	_ = first.SetReadDeadline(time.Now().Add(20 * time.Second))
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
	second, e := connect()
	if e != nil {
		t.Fatal("quota was not released", e)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(20 * time.Second))
	ping, e = second.ReadFrame()
	if e != nil || ping.Type != protocol.PING {
		t.Fatalf("second heartbeat: %+v %v", ping, e)
	}
	_ = second.SetReadDeadline(time.Now().Add(7 * time.Second))
	if _, e = second.ReadFrame(); e == nil {
		t.Fatal("missing PONG kept connection alive")
	}
	third, e := connect()
	if e != nil {
		t.Fatal("timeout did not free quota", e)
	}
	_ = third.Close()
}
