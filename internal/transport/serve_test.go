package transport

import (
	"context"
	"crypto/rand"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/config"
)

func TestServeDoesNotSerializeRegistration(t *testing.T) {
	a, _ := noise.DH25519.GenerateKeypair(rand.Reader)
	b, _ := noise.DH25519.GenerateKeypair(rand.Reader)
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var seen atomic.Int32
	ready := make(chan struct{}, 1)
	served := make(chan error, 1)
	go func() {
		served <- Serve(ctx, ln, config.ServerTransport{Type: "noise", PrivateKey: a.Private, PeerKey: b.Public}, func(in *Incoming) {
			var x [1]byte
			if _, e := io.ReadFull(in, x[:]); e != nil {
				return
			}
			if err := in.CompleteAuth(); err == nil {
				seen.Add(1)
				ready <- struct{}{}
			}
		})
	}()
	cfg := config.ClientTransport{Type: "noise", RemoteAddr: ln.Addr().String(), PrivateKey: b.Private, PeerKey: a.Public, DialTimeout: time.Second}
	first, e := Dial(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer first.Close()
	second, e := Dial(ctx, cfg)
	if e != nil {
		t.Fatal("first blocked Accept", e)
	}
	defer second.Close()
	if _, e = second.Write([]byte{1}); e != nil {
		t.Fatal(e)
	}
	select {
	case <-ready:
		if seen.Load() != 1 {
			t.Fatal("unexpected registrations")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second registration blocked")
	}
	cancel()
	if e = <-served; e != nil {
		t.Fatal(e)
	}
}
