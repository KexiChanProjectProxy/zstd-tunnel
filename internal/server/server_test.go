package server_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/client"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/config"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/server"
)

func freePort(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}
func configHash(s string) [32]byte { return sha256.Sum256([]byte(s)) }
func TestNoiseEndToEnd(t *testing.T) {
	backend, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer backend.Close()
	go func() {
		for {
			c, e := backend.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	sk, _ := noise.DH25519.GenerateKeypair(rand.Reader)
	ck, _ := noise.DH25519.GenerateKeypair(rand.Reader)
	tunnel, public := freePort(t), freePort(t)
	token := "a long random-looking token for testing!"
	srvcfg := &config.Server{BindAddr: tunnel, Services: map[string]config.Service{"echo": {Addr: public, TokenHash: configHash(token)}}, Transport: config.ServerTransport{Type: "noise", PrivateKey: sk.Private, PeerKey: ck.Public}, Pool: config.ServerPool{MaxConnections: 1, MaxPending: 4, AcquireTimeout: time.Second}}
	clicfg := &config.Client{RemoteAddr: tunnel, DialTimeout: time.Second, Services: map[string]config.Service{"echo": {Addr: backend.Addr().String(), Token: token}}, Transport: config.ClientTransport{Type: "noise", PrivateKey: ck.Private, PeerKey: sk.Public, RemoteAddr: tunnel, DialTimeout: time.Second}, Pool: config.ClientPool{Size: 1}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := make(chan error, 2)
	go func() { results <- server.Run(ctx, srvcfg) }()
	go func() { results <- client.Run(ctx, clicfg) }()
	defer func() {
		cancel()
		for range 2 {
			select {
			case e := <-results:
				if e != nil {
					t.Error(e)
				}
			case <-time.After(3 * time.Second):
				t.Error("shutdown timeout")
			}
		}
	}()
	for i := range 3 {
		deadline := time.Now().Add(5 * time.Second)
		for {
			c, e := net.DialTimeout("tcp", public, 200*time.Millisecond)
			if e == nil {
				tcp := c.(*net.TCPConn)
				_ = tcp.SetDeadline(time.Now().Add(2 * time.Second))
				_, e = tcp.Write([]byte("hello"))
				var buf [5]byte
				if e == nil {
					_, e = io.ReadFull(tcp, buf[:])
				}
				if e == nil && string(buf[:]) == "hello" {
					_ = tcp.CloseWrite()
					_, e = io.ReadAll(tcp)
				}
				_ = tcp.Close()
				if e == nil {
					break
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("lease %d failed: %v", i, e)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}
